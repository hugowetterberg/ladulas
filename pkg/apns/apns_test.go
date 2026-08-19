package apns_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hugowetterberg/ladulas/pkg/apns"
)

// Every test here generates its own throwaway key. The real one is a `.p8` on
// somebody's disk and nothing in this repository has any business reading it.
func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate a key: %v", err)
	}

	return key
}

type capture struct {
	mu       sync.Mutex
	requests []*http.Request
	bodies   []string

	status int
	reason string
}

func (c *capture) handler(t *testing.T) http.Handler {
	t.Helper()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		if _, err := r.Body.Read(body); err != nil && len(body) == 0 {
			t.Errorf("read the payload: %v", err)
		}

		c.mu.Lock()
		c.requests = append(c.requests, r.Clone(r.Context()))
		c.bodies = append(c.bodies, string(body))
		status, reason := c.status, c.reason
		c.mu.Unlock()

		if status == 0 || status == http.StatusOK {
			w.WriteHeader(http.StatusOK)

			return
		}

		w.WriteHeader(status)

		if err := json.NewEncoder(w).Encode(
			map[string]string{"reason": reason}); err != nil {
			t.Errorf("write the refusal: %v", err)
		}
	})
}

func (c *capture) last() (*http.Request, string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.requests[len(c.requests)-1], c.bodies[len(c.bodies)-1]
}

func newSender(t *testing.T, host string, now func() time.Time) *apns.Sender {
	t.Helper()

	sender, err := apns.New(apns.Options{
		Host:   host,
		Topic:  "nu.example.app",
		KeyID:  "TESTKEYID1",
		TeamID: "TESTTEAM01",
		Key:    testKey(t),
		Now:    now,
	})
	if err != nil {
		t.Fatalf("sender: %v", err)
	}

	return sender
}

func TestAnAlertPushCarriesTheFixedSentenceAndNothingElse(t *testing.T) {
	shot := &capture{}
	server := httptest.NewServer(shot.handler(t))

	t.Cleanup(server.Close)

	sender := newSender(t, server.URL, nil)

	if err := sender.Push(
		context.Background(), "abc123", apns.Alert, apns.Approval); err != nil {
		t.Fatalf("push: %v", err)
	}

	req, body := shot.last()

	if req.URL.Path != "/3/device/abc123" {
		t.Fatalf("the push went to %s", req.URL.Path)
	}

	if got := req.Header.Get("apns-push-type"); got != "alert" {
		t.Fatalf("push type %q", got)
	}

	if got := req.Header.Get("apns-priority"); got != "10" {
		t.Fatalf("priority %q", got)
	}

	if got := req.Header.Get("apns-topic"); got != "nu.example.app" {
		t.Fatalf("topic %q", got)
	}

	// The apns-* headers as a set, and not three of them by name, because the
	// one bug this file has actually had was a header: a collapse id, which
	// makes each push replace the last and makes iOS update an unread
	// notification without alerting again. Three assertions by name had nothing
	// to say about a fourth header being there. Adding or removing one should
	// mean coming here and saying so.
	want := []string{
		"apns-expiration", "apns-priority", "apns-push-type", "apns-topic",
	}

	var sent []string

	for name := range req.Header {
		if strings.HasPrefix(strings.ToLower(name), "apns-") {
			sent = append(sent, strings.ToLower(name))
		}
	}

	slices.Sort(sent)

	if !slices.Equal(sent, want) {
		t.Fatalf("the apns headers were %v, expected %v", sent, want)
	}

	// Asserted whole rather than sampled, which is the point: the property the
	// relay exists to have is that nothing about the request leaves this
	// process, and a test that looked for particular leaks would pass the day
	// somebody added a field nobody thought to look for (§11).
	const expected = `{"aps":{"alert":{"body":"Signing request pending — tap to review",` +
		`"title":"Ladulås"},"category":"LADULAS_PENDING","sound":"default"}}`

	if body != expected {
		t.Fatalf("the payload was %s", body)
	}
}

func TestASilentPushIsABackgroundPush(t *testing.T) {
	shot := &capture{}
	server := httptest.NewServer(shot.handler(t))

	t.Cleanup(server.Close)

	sender := newSender(t, server.URL, nil)

	if err := sender.Push(
		context.Background(), "abc123", apns.Silent, apns.Approval); err != nil {
		t.Fatalf("push: %v", err)
	}

	req, body := shot.last()

	if got := req.Header.Get("apns-push-type"); got != "background" {
		t.Fatalf("push type %q", got)
	}

	if got := req.Header.Get("apns-priority"); got != "5" {
		t.Fatalf("priority %q", got)
	}

	if body != `{"aps":{"content-available":1}}` {
		t.Fatalf("the payload was %s", body)
	}
}

func TestADeadTokenIsSaidToBeDead(t *testing.T) {
	for _, reason := range []string{"Unregistered", "BadDeviceToken"} {
		t.Run(reason, func(t *testing.T) {
			shot := &capture{status: http.StatusGone, reason: reason}
			server := httptest.NewServer(shot.handler(t))

			t.Cleanup(server.Close)

			sender := newSender(t, server.URL, nil)

			err := sender.Push(
				context.Background(), "abc123", apns.Alert, apns.Approval)
			if !errors.Is(err, apns.ErrUnregistered) {
				t.Fatalf("the sender reported %v", err)
			}
		})
	}
}

func TestAnythingElseIsNotADeadToken(t *testing.T) {
	shot := &capture{
		status: http.StatusServiceUnavailable,
		reason: "ServiceUnavailable",
	}
	server := httptest.NewServer(shot.handler(t))

	t.Cleanup(server.Close)

	sender := newSender(t, server.URL, nil)

	err := sender.Push(context.Background(), "abc123", apns.Alert, apns.Approval)
	if err == nil {
		t.Fatal("a refused push succeeded")
	}

	// Apple having a bad afternoon must not look like a device that has gone,
	// because the relay forgets a device that has gone.
	if errors.Is(err, apns.ErrUnregistered) {
		t.Fatalf("a transient failure read as a dead token: %v", err)
	}
}

// The provider token is reused between pushes and replaced on a schedule that
// sits inside both of Apple's bounds: rejected over an hour old, and rejected
// when refreshed more often than every twenty minutes.
func TestTheProviderTokenIsReusedAndThenReplaced(t *testing.T) {
	shot := &capture{}
	server := httptest.NewServer(shot.handler(t))

	t.Cleanup(server.Close)

	var mu sync.Mutex

	now := time.Now()

	sender := newSender(t, server.URL, func() time.Time {
		mu.Lock()
		defer mu.Unlock()

		return now
	})

	push := func() string {
		t.Helper()

		if err := sender.Push(
			context.Background(), "abc123", apns.Alert, apns.Approval); err != nil {
			t.Fatalf("push: %v", err)
		}

		req, _ := shot.last()

		return req.Header.Get("authorization")
	}

	first := push()

	if !strings.HasPrefix(first, "bearer ") {
		t.Fatalf("the authorization header was %q", first)
	}

	mu.Lock()
	now = now.Add(19 * time.Minute)
	mu.Unlock()

	if second := push(); second != first {
		t.Fatal("the provider token was refreshed inside Apple's twenty minutes")
	}

	mu.Lock()
	now = now.Add(50 * time.Minute)
	mu.Unlock()

	third := push()
	if third == first {
		t.Fatal("the provider token was still in use after an hour")
	}

	assertJWT(t, third, "TESTKEYID1", "TESTTEAM01")
}

func assertJWT(t *testing.T, header, keyID, teamID string) {
	t.Helper()

	parts := strings.Split(strings.TrimPrefix(header, "bearer "), ".")
	if len(parts) != 3 {
		t.Fatalf("the token has %d parts", len(parts))
	}

	var head struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}

	decode(t, parts[0], &head)

	if head.Alg != "ES256" || head.Kid != keyID {
		t.Fatalf("the header is %+v", head)
	}

	var claims struct {
		Iss string `json:"iss"`
		Iat int64  `json:"iat"`
	}

	decode(t, parts[1], &claims)

	if claims.Iss != teamID || claims.Iat == 0 {
		t.Fatalf("the claims are %+v", claims)
	}
}

func decode(t *testing.T, segment string, into any) {
	t.Helper()

	body, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		t.Fatalf("decode a segment: %v", err)
	}

	if err := json.Unmarshal(body, into); err != nil {
		t.Fatalf("parse a segment: %v", err)
	}
}

func TestASigningKeyIsReadOutOfItsPEM(t *testing.T) {
	key := testKey(t)

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	parsed, err := apns.ParseKey(encoded)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if !parsed.Equal(key) {
		t.Fatal("the key came back as a different key")
	}

	if _, err := apns.ParseKey([]byte("not a pem")); err == nil {
		t.Fatal("a non-PEM parsed as a signing key")
	}
}
