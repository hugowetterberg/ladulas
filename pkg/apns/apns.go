// Package apns sends wake-up pushes through Apple's provider API (§11).
//
// It is deliberately the smallest thing that can do that. Everything a general
// APNs library has — templates, per-notification payloads, delivery receipts,
// certificate authentication — is either unwanted or forbidden here: the payload
// carries no request data at all, so there is nothing to template, and what is
// sent is one of two fixed messages.
//
// Token authentication rather than a push certificate, which is the arrangement
// that survives an expiring certificate nobody remembered to renew: a `.p8` key
// signs a short JWT per connection, and the same key serves every topic in the
// team. The key is configuration and is never in the tree.
package apns

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// The two provider hosts.
//
// Production is the one to expect during development, which is not a mistake and
// is worth saying plainly: a TestFlight build is signed for distribution, so its
// device tokens are production tokens and the sandbox host answers BadDeviceToken
// for every one of them. CI and TestFlight are the only path to a device on this
// project, so production is what a development relay talks to — and the host
// stays configuration so that a locally built debug app can use the other one.
const (
	Production = "https://api.push.apple.com"
	Sandbox    = "https://api.sandbox.push.apple.com"
)

// ErrUnregistered says the device token is dead: the app was deleted, or the
// token was reissued and this one was not. It is the signal a route is dropped
// on, which is half of how a rotating token stops being pushed to.
var ErrUnregistered = errors.New("apns: the device token is no longer registered")

// Style is what a push should do when it arrives.
type Style int

const (
	// Alert is a visible notification. The only one that reaches a human, and
	// the only one §11 permits for prompting one.
	Alert Style = iota
	// Silent is a background wake, for a request the approver has already
	// promised to answer (§20, M9).
	Silent
)

// Subject is which of the two fixed sentences an alert carries.
//
// It is the only thing about an event that reaches this process, it is one bit,
// and it is an enumeration rather than a string for that reason: what can be
// sent is a list written here, never something a caller composes.
type Subject int

const (
	// Approval is somebody waiting for a signature, and is what every wake-up
	// was before there was anything else to be woken for.
	Approval Subject = iota
	// KeyOffer is a paired instance handing over a portable key (§10,
	// decision S).
	KeyOffer
)

// The bodies are the whole of what leaves this process about an event, and each
// is the same sentence whoever asked, whatever they asked for, and whichever
// machine they asked from. Nothing is templated here because there is nothing to
// template: the relay is not told what the request was (§11).
const (
	alertTitle   = "Ladulås"
	approvalBody = "Signing request pending — tap to review"
	keyOfferBody = "A key is waiting for you — tap to review"
)

// There is deliberately no apns-collapse-id, and the reasoning that put one
// here was sound and wrong.
//
// The argument for it: a requester that parks three requests in a minute is one
// thing that happened as far as the person holding the phone is concerned, and
// three banners is three times the noise for none of the information. All true.
//
// What it missed is what replacement means. A collapse id does not merge
// notifications into a quieter one — it makes each push *replace* the last, and
// iOS updates a notification that is still sitting unread **without alerting
// again**: no banner, no sound. So the first wake-up arrived and every one after
// it silently overwrote that one, for as long as it went untouched. Measured in
// the end rather than reasoned about: three pushes six seconds apart, one
// banner.
//
// Collapsing would only be worth having if the replacement said something the
// original did not, and it cannot — the payload is a constant, because §11
// forbids it carrying anything about the request. A newer copy of the same
// sentence is not worth losing an alert over.
//
// One alert per request is what this leaves, which is what was wanted all
// along: runWake sends at most one alert for a request, a silent push draws
// nothing, and the relay's throttle bounds a burst.

// category is what the shell registers its notification actions under. It is a
// string both sides have to agree on and neither can check, so it is here rather
// than assembled from the topic.
const category = "LADULAS_PENDING"

// expiry is how long APNs should keep trying.
//
// Short, because a wake-up is only worth delivering while somebody is still
// blocked on the answer. One stored for an hour and delivered to a phone coming
// out of a tunnel is a notification about a commit that was abandoned, which is
// worse than no notification: it teaches the person holding the phone that the
// banner does not mean anything.
const expiry = 5 * time.Minute

// Options configures a sender.
type Options struct {
	// Host is Production or Sandbox, or anything else in a test.
	Host string
	// Topic is the app's bundle identifier.
	Topic string
	// KeyID and TeamID identify the signing key to Apple.
	KeyID  string
	TeamID string
	// Key is the ES256 key from the `.p8`.
	Key *ecdsa.PrivateKey
	// Client defaults to one that will negotiate HTTP/2, which APNs requires.
	Client *http.Client
	// Now is the clock, for tests.
	Now func() time.Time
}

// Sender talks to one APNs host for one topic.
type Sender struct {
	opts   Options
	client *http.Client
	now    func() time.Time

	mu       sync.Mutex
	token    string
	tokenAge time.Time
}

// tokenLifetime is how long a provider JWT is reused.
//
// Apple bounds it from both ends: a token over an hour old is rejected, and
// refreshing more often than every twenty minutes is rejected as well
// (TooManyProviderTokenUpdates). Anything comfortably between the two satisfies
// both, and there is no reason to be near either edge.
const tokenLifetime = 45 * time.Minute

// New builds a sender.
func New(opts Options) (*Sender, error) {
	switch {
	case opts.Host == "":
		return nil, errors.New("apns: no host")
	case opts.Topic == "":
		return nil, errors.New("apns: no topic")
	case opts.KeyID == "":
		return nil, errors.New("apns: no key id")
	case opts.TeamID == "":
		return nil, errors.New("apns: no team id")
	case opts.Key == nil:
		return nil, errors.New("apns: no signing key")
	}

	sender := &Sender{
		opts:   opts,
		client: opts.Client,
		now:    opts.Now,
	}

	if sender.client == nil {
		sender.client = &http.Client{Timeout: 20 * time.Second}
	}

	if sender.now == nil {
		sender.now = time.Now
	}

	return sender, nil
}

// Push sends one wake-up to one device token.
func (s *Sender) Push(
	ctx context.Context, deviceToken string, style Style, subject Subject,
) error {
	if deviceToken == "" {
		return errors.New("apns: no device token")
	}

	jwt, err := s.providerToken()
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.opts.Host+"/3/device/"+deviceToken,
		bytes.NewReader(payload(style, subject)))
	if err != nil {
		return fmt.Errorf("apns: build the request: %w", err)
	}

	req.Header.Set("authorization", "bearer "+jwt)
	req.Header.Set("apns-topic", s.opts.Topic)
	req.Header.Set("apns-expiration",
		strconv.FormatInt(s.now().Add(expiry).Unix(), 10))
	req.Header.Set("content-type", "application/json")

	if style == Silent {
		// A background push is priority 5 and push type background, and iOS
		// refuses one sent as anything else. It is also the one the system feels
		// free to delay or drop, which is why it is never the only wake sent.
		req.Header.Set("apns-push-type", "background")
		req.Header.Set("apns-priority", "5")
	} else {
		req.Header.Set("apns-push-type", "alert")
		req.Header.Set("apns-priority", "10")
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("apns: reach the push service: %w", err)
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode == http.StatusOK {
		return nil
	}

	return outcome(resp)
}

// outcome turns a refusal into something the caller can act on. Apple's reason
// strings are the only part of the response worth reading, and exactly two of
// them mean "stop sending to this token".
func outcome(resp *http.Response) error {
	var body struct {
		Reason string `json:"reason"`
	}

	// A body that does not decode leaves the reason empty, which falls through
	// to the status code below rather than replacing one useless sentence with
	// another.
	_ = json.NewDecoder(resp.Body).Decode(&body)

	switch body.Reason {
	case "Unregistered", "BadDeviceToken":
		return fmt.Errorf("%w (%s)", ErrUnregistered, body.Reason)
	case "":
		return fmt.Errorf("apns: the push service answered %d", resp.StatusCode)
	default:
		return fmt.Errorf("apns: the push service refused it: %s", body.Reason)
	}
}

func payload(style Style, subject Subject) []byte {
	if style == Silent {
		return []byte(`{"aps":{"content-available":1}}`)
	}

	body := approvalBody
	if subject == KeyOffer {
		body = keyOfferBody
	}

	// Assembled by hand rather than marshalled, because it is a constant and
	// building a struct to produce a constant invites somebody to put a field on
	// it that says what the request was.
	encoded, err := json.Marshal(map[string]any{
		"aps": map[string]any{
			"alert": map[string]any{
				"title": alertTitle,
				"body":  body,
			},
			"sound":    "default",
			"category": category,
		},
	})
	if err != nil {
		// Two string constants in a map do not fail to encode.
		panic("apns: the alert payload does not encode: " + err.Error())
	}

	return encoded
}

// providerToken returns the current JWT, minting one when the old one is due to
// be replaced.
func (s *Sender) providerToken() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()

	if s.token != "" && now.Sub(s.tokenAge) < tokenLifetime {
		return s.token, nil
	}

	token, err := s.mint(now)
	if err != nil {
		return "", err
	}

	s.token = token
	s.tokenAge = now

	return token, nil
}

// mint builds the ES256 JWT Apple wants: a `kid` header, an `iss` of the team
// id, an `iat` of now, and nothing else. There is no `exp` — Apple decides how
// long it will accept one for, and a claim about it here would only be a second
// opinion.
func (s *Sender) mint(now time.Time) (string, error) {
	header := encodeSegment(fmt.Sprintf(
		`{"alg":"ES256","kid":%q}`, s.opts.KeyID))
	claims := encodeSegment(fmt.Sprintf(
		`{"iss":%q,"iat":%d}`, s.opts.TeamID, now.Unix()))

	signing := header + "." + claims
	digest := sha256.Sum256([]byte(signing))

	der, err := ecdsa.SignASN1(rand.Reader, s.opts.Key, digest[:])
	if err != nil {
		return "", fmt.Errorf("apns: sign the provider token: %w", err)
	}

	// JWS wants the two integers left-padded to the curve size and concatenated;
	// crypto/ecdsa produces the ASN.1 sequence. The same re-encoding the mobile
	// boundary does for a Secure Enclave signature (§10), in the other direction.
	signature, err := jwsSignature(der, (s.opts.Key.Curve.Params().BitSize+7)/8)
	if err != nil {
		return "", err
	}

	return signing + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func jwsSignature(der []byte, size int) ([]byte, error) {
	var parsed struct {
		R, S *big.Int
	}

	if _, err := asn1.Unmarshal(der, &parsed); err != nil {
		return nil, fmt.Errorf("apns: parse the signature: %w", err)
	}

	out := make([]byte, 2*size)
	parsed.R.FillBytes(out[:size])
	parsed.S.FillBytes(out[size:])

	return out, nil
}

func encodeSegment(json string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(json))
}

// ParseKey reads an ES256 signing key out of the PEM Apple hands over as a
// `.p8`, which is a PKCS#8 wrapper around a P-256 private key.
func ParseKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("apns: the signing key is not PEM")
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("apns: parse the signing key: %w", err)
	}

	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf(
			"apns: the signing key is %T, and APNs token authentication is ES256",
			parsed)
	}

	return key, nil
}
