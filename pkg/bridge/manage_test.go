package bridge_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/hugowetterberg/ladulas/pkg/bridge"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"golang.org/x/crypto/ssh"
)

// Managing keys and the daemon's stored settings from a window (§12, §14).
//
// These are the routes that let a screen do what `ladulas keys` and
// `ladulas listen` do rather than only watch it, and the shape they share is
// the signing budget's: a write answers with what a read would now say, a host
// that has not wired a route gets a 501 rather than a button that fails, and a
// body that could mean two things is refused rather than guessed at.

type manageHost struct {
	mu sync.Mutex

	keys     map[string]*ladulasv1.KeyRef
	removed  []string
	agentUse []string
	sent     []string
	// The passphrase as the host saw it, copied before the bridge wipes it.
	passphrase string

	listen   *ladulasv1.PeerListenState
	listened []string
	detail   string

	autoPublish bool
	enrolled    bool
	refuse      error
}

func (h *manageHost) removeKey(_ context.Context, key string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.removed = append(h.removed, key)

	if h.refuse != nil {
		return h.refuse
	}

	delete(h.keys, key)

	return nil
}

func (h *manageHost) setKeyAgentUse(
	_ context.Context, key string, use bool,
) (*ladulasv1.KeyRef, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.agentUse = append(h.agentUse, fmt.Sprintf("%s=%t", key, use))

	ref, ok := h.keys[key]
	if !ok {
		return nil, errors.New("no such key")
	}

	ref.AgentUse = &use

	return ref, nil
}

func (h *manageHost) sendKey(
	_ context.Context, key, peer string, passphrase []byte,
) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.sent = append(h.sent, key+"->"+peer)
	h.passphrase = string(bytes.Clone(passphrase))

	if h.refuse != nil {
		return "", h.refuse
	}

	return "laptop", nil
}

func (h *manageHost) listenState() (*ladulasv1.PeerListenState, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	return h.listen, nil
}

func (h *manageHost) setListen(
	_ context.Context, spec string, allowPublic, clear bool,
) (*ladulasv1.SetPeerListenResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.listened = append(h.listened,
		fmt.Sprintf("spec=%q public=%t clear=%t", spec, allowPublic, clear))

	if h.refuse != nil {
		return nil, h.refuse
	}

	return &ladulasv1.SetPeerListenResponse{
		State:  h.listen,
		Detail: h.detail,
	}, nil
}

func (h *manageHost) readAutoPublish() (bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	return h.autoPublish, nil
}

func (h *manageHost) setAutoPublish(_ context.Context, enabled bool) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.autoPublish = enabled

	return nil
}

func (h *manageHost) unlockAtLogin() (bridge.UnlockAtLoginView, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	return bridge.UnlockAtLoginView{
		Enrolled:           h.enrolled,
		PassphraseWrapping: true,
	}, nil
}

func (h *manageHost) setUnlockAtLogin(_ context.Context, enrol bool) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.refuse != nil {
		return h.refuse
	}

	h.enrolled = enrol

	return nil
}

// testKeyRef is a real ed25519 key as the store would hand it over, so the
// authorized_keys line the bridge derives can be checked against the marshaller
// rather than a literal.
func testKeyRef(t *testing.T, label, comment string) (*ladulasv1.KeyRef, string) {
	t.Helper()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate a key: %v", err)
	}

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("wrap the key: %v", err)
	}

	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))

	return &ladulasv1.KeyRef{
		Fingerprint: ssh.FingerprintSHA256(sshPub),
		Algorithm:   sshPub.Type(),
		PublicKey:   sshPub.Marshal(),
		Label:       label,
		Comment:     comment,
	}, line
}

func newManageFixture(
	t *testing.T, host *manageHost, wired bool,
) http.Handler {
	t.Helper()

	opts := bridge.Options{
		Name:      "workstation",
		Presenter: &presenter{},
		Keys: func() []*ladulasv1.KeyRef {
			host.mu.Lock()
			defer host.mu.Unlock()

			out := make([]*ladulasv1.KeyRef, 0, len(host.keys))
			for _, key := range host.keys {
				out = append(out, key)
			}

			return out
		},
	}

	if wired {
		opts.RemoveKey = host.removeKey
		opts.SetKeyAgentUse = host.setKeyAgentUse
		opts.SendKey = host.sendKey
		opts.Listen = host.listenState
		opts.SetListen = host.setListen
		opts.AutoPublish = host.readAutoPublish
		opts.SetAutoPublish = host.setAutoPublish
		opts.UnlockAtLogin = host.unlockAtLogin
		opts.SetUnlockAtLogin = host.setUnlockAtLogin
	}

	return bridge.NewSession(opts).Handler()
}

func newManageHost(t *testing.T) (*manageHost, *ladulasv1.KeyRef, string) {
	t.Helper()

	key, line := testKeyRef(t, "work", "hugo@laptop")

	host := &manageHost{
		keys: map[string]*ladulasv1.KeyRef{key.GetFingerprint(): key},
		listen: &ladulasv1.PeerListenState{
			Spec:       "auto",
			Source:     ladulasv1.ListenSource_LISTEN_SOURCE_AUTOMATIC,
			Bound:      []string{"100.64.0.7:7373", "192.168.1.20:7373"},
			Advertised: []string{"100.64.0.7:7373", "192.168.1.20:7373"},
			Tier:       "local",
			Skipped: []*ladulasv1.SkippedListenAddress{{
				Address:   "172.17.0.1",
				Interface: "docker0",
				Reason:    "a container bridge",
			}},
		},
		detail: "listening on 2 addresses",
	}

	return host, key, line
}

// TestAStoredKeyCarriesItsPublicLineAndWhetherTheAgentOffersIt: the key card
// is where a public key is copied from, so the authorized_keys line arrives
// with the key rather than in a second call — with the comment the line would
// carry in a file, and the label when nobody gave it one.
func TestAStoredKeyCarriesItsPublicLineAndWhetherTheAgentOffersIt(t *testing.T) {
	host, key, line := newManageHost(t)
	handler := newManageFixture(t, host, true)

	var view bridge.InstanceView

	getJSON(t, handler, "/api/v1/instance", &view)

	if len(view.Keys) != 1 {
		t.Fatalf("the instance lists %d keys", len(view.Keys))
	}

	if got, want := view.Keys[0].Public, line+" hugo@laptop"; got != want {
		t.Errorf("the public line is %q, wanted %q", got, want)
	}

	// Unset means offered (decision T).
	if !view.Keys[0].AgentUse {
		t.Error("a key with agent use unset is shown as not offered")
	}

	// With no comment the label stands in, as `ladulas keys public` does.
	key.Comment = ""

	getJSON(t, handler, "/api/v1/instance", &view)

	if got, want := view.Keys[0].Public, line+" work"; got != want {
		t.Errorf("the uncommented line is %q, wanted %q", got, want)
	}
}

// TestTakingAKeyOutOfTheAgentAnswersWithTheKey: the toggle redraws from the
// reply, and a body that does not say which way is refused rather than read
// as "hide it".
func TestTakingAKeyOutOfTheAgentAnswersWithTheKey(t *testing.T) {
	host, key, _ := newManageHost(t)
	handler := newManageFixture(t, host, true)

	body := fmt.Sprintf(`{"key":%q,"agentUse":false}`, key.GetFingerprint())

	resp := postTo(t, handler, "/api/v1/keys/agent", body)
	if resp.Code != http.StatusOK {
		t.Fatalf("hide the key: %d %s", resp.Code, resp.Body.String())
	}

	var answered bridge.KeyView

	if err := json.Unmarshal(resp.Body.Bytes(), &answered); err != nil {
		t.Fatalf("read the answer: %v", err)
	}

	if answered.AgentUse {
		t.Error("the answer still says the agent offers the key")
	}

	if answered.Public == "" {
		t.Error("the answer lost the public line")
	}

	resp = postTo(t, handler, "/api/v1/keys/agent",
		fmt.Sprintf(`{"key":%q}`, key.GetFingerprint()))
	if resp.Code != http.StatusBadRequest {
		t.Errorf("a body that does not say which way answered %d", resp.Code)
	}

	if len(host.agentUse) != 1 {
		t.Errorf("the host was asked %v", host.agentUse)
	}
}

// TestRemovingAKeyIsSilentOnSuccessAndNamedOnRefusal: there is nothing to
// answer with once the key is gone, and a refusal is the daemon's sentence.
func TestRemovingAKeyIsSilentOnSuccessAndNamedOnRefusal(t *testing.T) {
	host, key, _ := newManageHost(t)
	handler := newManageFixture(t, host, true)

	resp := postTo(t, handler, "/api/v1/keys/remove", `{}`)
	if resp.Code != http.StatusBadRequest {
		t.Errorf("removing no key answered %d", resp.Code)
	}

	resp = postTo(t, handler, "/api/v1/keys/remove",
		fmt.Sprintf(`{"key":%q}`, key.GetFingerprint()))
	if resp.Code != http.StatusNoContent {
		t.Fatalf("remove the key: %d %s", resp.Code, resp.Body.String())
	}

	if len(host.keys) != 0 {
		t.Error("the key is still held")
	}

	host.refuse = errors.New("the key is lent to laptop")

	resp = postTo(t, handler, "/api/v1/keys/remove",
		fmt.Sprintf(`{"key":%q}`, key.GetFingerprint()))
	if resp.Code != http.StatusBadRequest ||
		!strings.Contains(resp.Body.String(), "lent to laptop") {
		t.Errorf("a refused removal answered %d %s", resp.Code, resp.Body.String())
	}
}

// TestHandingAKeyOverNeedsThePassphraseAndWipesIt: the daemon checks the
// passphrase, but a body without one is refused here so that the host is
// never asked to try an empty one — and what the host was handed is wiped once
// it has answered (§14).
func TestHandingAKeyOverNeedsThePassphraseAndWipesIt(t *testing.T) {
	host, key, _ := newManageHost(t)
	handler := newManageFixture(t, host, true)

	resp := postTo(t, handler, "/api/v1/keys/send",
		fmt.Sprintf(`{"key":%q,"peer":"SHA256:peer"}`, key.GetFingerprint()))
	if resp.Code != http.StatusBadRequest ||
		!strings.Contains(resp.Body.String(), "passphrase") {
		t.Errorf("sending without a passphrase answered %d %s",
			resp.Code, resp.Body.String())
	}

	if len(host.sent) != 0 {
		t.Fatalf("the host was asked to send %v with no passphrase", host.sent)
	}

	passphrase := base64.StdEncoding.EncodeToString([]byte("correct horse"))

	resp = postTo(t, handler, "/api/v1/keys/send",
		fmt.Sprintf(`{"key":%q,"peer":"SHA256:peer","passphrase":%q}`,
			key.GetFingerprint(), passphrase))
	if resp.Code != http.StatusOK {
		t.Fatalf("send the key: %d %s", resp.Code, resp.Body.String())
	}

	var answered bridge.SentKeyView

	if err := json.Unmarshal(resp.Body.Bytes(), &answered); err != nil {
		t.Fatalf("read the answer: %v", err)
	}

	if answered.Peer != "laptop" || answered.Fingerprint != key.GetFingerprint() {
		t.Errorf("the answer says %+v", answered)
	}

	if host.passphrase != "correct horse" {
		t.Errorf("the host saw the passphrase as %q", host.passphrase)
	}

	if host.sent[0] != key.GetFingerprint()+"->SHA256:peer" {
		t.Errorf("the host was asked to send %v", host.sent)
	}
}

// TestTheListenStateIsOnTheInstanceViewInWords: the settings screen is drawn
// from one call, and the words are the bridge's so that every host says the
// same thing `ladulas listen` does — including what was passed over and why,
// which is the half that answers "why can't my phone reach this machine".
func TestTheListenStateIsOnTheInstanceViewInWords(t *testing.T) {
	host, _, _ := newManageHost(t)
	handler := newManageFixture(t, host, true)

	var view bridge.InstanceView

	getJSON(t, handler, "/api/v1/instance", &view)

	if view.Listen == nil {
		t.Fatal("the instance view carries no listen state")
	}

	if view.Listen.Source != "automatic" || view.Listen.SourceNote == "" {
		t.Errorf("the source reads %q / %q", view.Listen.Source, view.Listen.SourceNote)
	}

	if view.Listen.Chose != "the tailnet and the local network addresses" {
		t.Errorf("the policy's choice reads %q", view.Listen.Chose)
	}

	if len(view.Listen.Skipped) != 1 || view.Listen.Skipped[0].Interface != "docker0" {
		t.Errorf("the passed-over list is %+v", view.Listen.Skipped)
	}

	if view.Publishing == nil || view.Publishing.AutoPublish {
		t.Errorf("publishing reads %+v", view.Publishing)
	}

	if view.UnlockAtLogin == nil || view.UnlockAtLogin.Enrolled {
		t.Errorf("unlock at login reads %+v", view.UnlockAtLogin)
	}
}

// TestChangingWhereToListenAnswersWithTheStateAndTheDaemonsSentence: a bind
// that failed and fell back is a success as far as the state can tell, so the
// sentence saying so travels with it. Clearing is its own request, and a body
// that both clears and gives a setting — or does neither — is refused.
func TestChangingWhereToListenAnswersWithTheStateAndTheDaemonsSentence(t *testing.T) {
	host, _, _ := newManageHost(t)
	handler := newManageFixture(t, host, true)

	host.detail = "could not bind 10.0.0.1:7373; the previous addresses are back"

	resp := postTo(t, handler, "/api/v1/settings/listen",
		`{"spec":"10.0.0.1:7373","allowPublic":true}`)
	if resp.Code != http.StatusOK {
		t.Fatalf("set the addresses: %d %s", resp.Code, resp.Body.String())
	}

	var answered bridge.ListenChangeView

	if err := json.Unmarshal(resp.Body.Bytes(), &answered); err != nil {
		t.Fatalf("read the answer: %v", err)
	}

	if !strings.Contains(answered.Detail, "previous addresses are back") {
		t.Errorf("the sentence was lost: %q", answered.Detail)
	}

	if len(answered.Listen.Bound) != 2 {
		t.Errorf("the state did not travel with the answer: %+v", answered.Listen)
	}

	resp = postTo(t, handler, "/api/v1/settings/listen", `{"clear":true}`)
	if resp.Code != http.StatusOK {
		t.Errorf("clearing answered %d %s", resp.Code, resp.Body.String())
	}

	for _, body := range []string{`{}`, `{"spec":"auto","clear":true}`} {
		resp = postTo(t, handler, "/api/v1/settings/listen", body)
		if resp.Code != http.StatusBadRequest {
			t.Errorf("%s answered %d", body, resp.Code)
		}
	}

	want := []string{
		`spec="10.0.0.1:7373" public=true clear=false`,
		`spec="" public=false clear=true`,
	}

	if fmt.Sprint(host.listened) != fmt.Sprint(want) {
		t.Errorf("the host was asked %v", host.listened)
	}
}

// TestTheTogglesRefuseABodyThatDoesNotSayWhichWay: auto-publish and unlock at
// login are booleans, and a missing one reads as false in JSON — which for one
// of them is a store that stops opening at login because a field was
// misspelled. Both answer with what a read would now say.
func TestTheTogglesRefuseABodyThatDoesNotSayWhichWay(t *testing.T) {
	host, _, _ := newManageHost(t)
	handler := newManageFixture(t, host, true)

	resp := postTo(t, handler, "/api/v1/settings/auto-publish", `{}`)
	if resp.Code != http.StatusBadRequest {
		t.Errorf("auto-publish with no value answered %d", resp.Code)
	}

	resp = postTo(t, handler, "/api/v1/settings/auto-publish", `{"enabled":true}`)
	if resp.Code != http.StatusOK ||
		!strings.Contains(resp.Body.String(), `"autoPublish":true`) {
		t.Errorf("turning auto-publish on answered %d %s", resp.Code, resp.Body.String())
	}

	if !host.autoPublish {
		t.Error("the host was not told to publish automatically")
	}

	resp = postTo(t, handler, "/api/v1/settings/unlock-at-login", `{}`)
	if resp.Code != http.StatusBadRequest {
		t.Errorf("unlock-at-login with no value answered %d", resp.Code)
	}

	resp = postTo(t, handler, "/api/v1/settings/unlock-at-login", `{"enrol":true}`)
	if resp.Code != http.StatusOK {
		t.Fatalf("enrolling answered %d %s", resp.Code, resp.Body.String())
	}

	var keyring bridge.UnlockAtLoginView

	if err := json.Unmarshal(resp.Body.Bytes(), &keyring); err != nil {
		t.Fatalf("read the answer: %v", err)
	}

	if !keyring.Enrolled {
		t.Error("the answer does not say the keychain is enrolled")
	}
}

// TestAHostThatManagesNothingOffersNothing: a phone shell that lists keys
// through its own bound methods is a real host, and its webview gets an
// instance view with no listen state and routes that say so rather than
// buttons that fail.
func TestAHostThatManagesNothingOffersNothing(t *testing.T) {
	host, key, _ := newManageHost(t)
	handler := newManageFixture(t, host, false)

	var view bridge.InstanceView

	getJSON(t, handler, "/api/v1/instance", &view)

	if view.Listen != nil || view.Publishing != nil || view.UnlockAtLogin != nil {
		t.Errorf("a host with no settings offered %+v %+v %+v",
			view.Listen, view.Publishing, view.UnlockAtLogin)
	}

	// The public line needs nothing from the host but the key.
	if len(view.Keys) != 1 || view.Keys[0].Public == "" {
		t.Errorf("the key lost its public line: %+v", view.Keys)
	}

	routes := map[string]string{
		"/api/v1/keys/remove":              fmt.Sprintf(`{"key":%q}`, key.GetFingerprint()),
		"/api/v1/keys/agent":               fmt.Sprintf(`{"key":%q,"agentUse":false}`, key.GetFingerprint()),
		"/api/v1/keys/send":                fmt.Sprintf(`{"key":%q,"peer":"x","passphrase":"eA=="}`, key.GetFingerprint()),
		"/api/v1/settings/listen":          `{"spec":"auto"}`,
		"/api/v1/settings/auto-publish":    `{"enabled":true}`,
		"/api/v1/settings/unlock-at-login": `{"enrol":true}`,
	}

	for path, body := range routes {
		resp := postTo(t, handler, path, body)
		if resp.Code != http.StatusNotImplemented {
			t.Errorf("%s on a host that cannot answered %d", path, resp.Code)
		}
	}

	resp := getFrom(t, handler, "/api/v1/settings/listen")
	if resp.Code != http.StatusNotImplemented {
		t.Errorf("reading the listen state on a host that cannot answered %d", resp.Code)
	}
}
