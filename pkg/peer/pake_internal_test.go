package peer

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/hugowetterberg/ladulas/internal/cpace"
	"github.com/hugowetterberg/ladulas/pkg/identity"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1/ladulasv1connect"
	"github.com/hugowetterberg/ladulas/pkg/transport"
	"github.com/hugowetterberg/ladulas/pkg/trust"
)

// The PIN exchange and its attempt accounting (decision AV). Each test is one
// of the rules the decision states, so that a rule that stops holding fails a
// test named after it.

func pairingContext(t *testing.T) context.Context {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	return ctx
}

// typedPIN is the code a joiner has when somebody typed the PIN: nothing else.
func typedPIN(pin trust.PIN) *ladulasv1.PairingCode {
	return &ladulasv1.PairingCode{Version: 1, Pin: string(pin)}
}

// wrongPIN is a PIN that is certainly not the window's.
func wrongPIN(right trust.PIN) trust.PIN {
	if right == "000000" {
		return "000001"
	}

	return "000000"
}

// rawPairing is a pairing client from one instance's identity to another's
// listener, for driving the rounds by hand.
func rawPairing(
	t *testing.T, id *identity.Identity, address string,
) ladulasv1connect.PairingServiceClient {
	t.Helper()

	client, err := transport.NewClient(transport.ClientOptions{Identity: id})
	if err != nil {
		t.Fatalf("client: %v", err)
	}

	t.Cleanup(client.CloseIdle)

	return ladulasv1connect.NewPairingServiceClient(client.HTTP(), client.URL(address))
}

func TestATypedPINPairs(t *testing.T) {
	desktop := newInstance(t, "desktop")
	laptop := newInstance(t, "laptop")

	window, _, err := desktop.node.beginPairing(trust.IntentMutual)
	if err != nil {
		t.Fatalf("begin pairing: %v", err)
	}

	defer desktop.node.closeWindow(window)

	pending, err := laptop.node.PairWith(pairingContext(t), desktop.address(),
		typedPIN(window.pin))
	if err != nil {
		t.Fatalf("pair by PIN: %v", err)
	}

	if pending.GetFingerprint() != desktop.identity.Fingerprint() ||
		pending.GetKeyFromCode() {
		t.Errorf("recorded %s, key from code %v",
			pending.GetFingerprint(), pending.GetKeyFromCode())
	}

	waitPaired(t, desktop, laptop.identity.Fingerprint())
	waitPaired(t, laptop, desktop.identity.Fingerprint())
}

// Five wrong PINs and the window is closed, so even the right one fails — and
// the displaying side has been told each time, with where the guess came from,
// and then that something is guessing.
func TestWrongPINsAreCountedAndCloseTheWindow(t *testing.T) {
	desktop := newInstance(t, "desktop")
	laptop := newInstance(t, "laptop")

	window, _, err := desktop.node.beginPairing(trust.IntentPeerRequests)
	if err != nil {
		t.Fatalf("begin pairing: %v", err)
	}

	defer desktop.node.closeWindow(window)

	ctx := pairingContext(t)

	for range trust.MaxAttempts {
		_, err := laptop.node.PairWith(ctx, desktop.address(),
			typedPIN(wrongPIN(window.pin)))
		if !errors.Is(err, ErrPINRefused) {
			t.Fatalf("a wrong PIN: got %v, want ErrPINRefused", err)
		}

		select {
		case attempt := <-window.attempted:
			if attempt.GetSource() == "" || attempt.GetOutcome() != "refused PIN" {
				t.Errorf("the attempt was reported as %v", attempt)
			}
		case <-time.After(time.Second):
			t.Fatal("a failed attempt was not reported to the displaying side")
		}
	}

	select {
	case <-window.exhausted:
	case <-time.After(time.Second):
		t.Fatal("spent attempts did not say so")
	}

	// The screen ends on exhaustion, and the window outlives it so that a
	// joiner arriving afterwards hears why (§7).
	desktop.node.closeWindow(window)

	if _, err := laptop.node.PairWith(ctx, desktop.address(),
		typedPIN(window.pin)); !errors.Is(err, ErrAttemptsSpent) {
		t.Fatalf("the right PIN after the attempts: got %v, want ErrAttemptsSpent",
			err)
	}

	if desktop.human.count() != 0 || len(desktop.store.PendingPairings()) != 0 {
		t.Error("wrong PINs raised a prompt or left a pairing behind")
	}
}

// One counter per window: the older proof and the PIN exchange draw on the
// same five, so an attacker cannot have five of each (invariant 4).
func TestTheOlderProofSharesTheCounter(t *testing.T) {
	desktop := newInstance(t, "desktop")
	laptop := newInstance(t, "laptop")

	window, secret, err := desktop.node.beginPairing(trust.IntentPeerRequests)
	if err != nil {
		t.Fatalf("begin pairing: %v", err)
	}

	defer desktop.node.closeWindow(window)

	wrongSecret, err := trust.NewSecret()
	if err != nil {
		t.Fatal(err)
	}

	ctx := pairingContext(t)

	for i := range trust.MaxAttempts {
		code := typedPIN(wrongPIN(window.pin))
		if i%2 == 1 {
			code = &ladulasv1.PairingCode{Version: 1, Secret: string(wrongSecret)}
		}

		if _, err := laptop.node.PairWith(ctx, desktop.address(), code); err == nil {
			t.Fatal("a wrong code paired")
		}
	}

	if _, err := laptop.node.PairWith(ctx, desktop.address(),
		&ladulasv1.PairingCode{Version: 1, Secret: string(secret)}); err == nil {
		t.Fatal("the older proof had attempts of its own")
	}
}

// A first round that is never finished is still an attempt. Without that a
// PAKE gives free guesses to anybody who can tell whether a guess was right
// and walk away before confirming.
func TestAnUnfinishedRoundStillCounts(t *testing.T) {
	desktop := newInstance(t, "desktop")
	laptop := newInstance(t, "laptop")

	window, _, err := desktop.node.beginPairing(trust.IntentPeerRequests)
	if err != nil {
		t.Fatalf("begin pairing: %v", err)
	}

	defer desktop.node.closeWindow(window)

	ctx := pairingContext(t)

	// Five first rounds from five identities, none finished. That is the whole
	// budget in flight, which is also the cap on how much may be in flight.
	for i := range trust.MaxAttempts {
		guesser, _, err := identity.Generate("guesser")
		if err != nil {
			t.Fatal(err)
		}

		if _, err := rawPairing(t, guesser, desktop.address()).PairStart(ctx,
			connect.NewRequest(&ladulasv1.PairStartRequest{})); err != nil {
			t.Fatalf("first round %d: %v", i, err)
		}
	}

	_, err = laptop.node.PairWith(ctx, desktop.address(), typedPIN(window.pin))
	if !errors.Is(err, ErrAttemptsSpent) {
		t.Fatalf("the right PIN after five unfinished rounds: got %v", err)
	}
}

// A second first round from the same identity abandons the first, which stays
// charged and is written down as such.
func TestStartingAgainAbandonsTheFirstRound(t *testing.T) {
	desktop := newInstance(t, "desktop")
	laptop := newInstance(t, "laptop")

	window, _, err := desktop.node.beginPairing(trust.IntentPeerRequests)
	if err != nil {
		t.Fatalf("begin pairing: %v", err)
	}

	defer desktop.node.closeWindow(window)

	ctx := pairingContext(t)
	client := rawPairing(t, laptop.identity, desktop.address())

	first, err := client.PairStart(ctx, connect.NewRequest(&ladulasv1.PairStartRequest{}))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := client.PairStart(ctx,
		connect.NewRequest(&ladulasv1.PairStartRequest{})); err != nil {
		t.Fatal(err)
	}

	select {
	case attempt := <-window.attempted:
		if attempt.GetOutcome() != "started again before finishing" {
			t.Errorf("reported as %q", attempt.GetOutcome())
		}
	case <-time.After(time.Second):
		t.Fatal("the abandoned round was not reported")
	}

	// And the first exchange is gone: its second round has nothing to finish.
	share, session, err := cpace.Respond(
		pinInputs(window.pin, laptop.identity.PublicKey(),
			desktop.identity.PublicKey(), first.Msg.GetSessionId()),
		[]byte(adJoiner), first.Msg.GetShare(), []byte(adListener))
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.PairFinish(ctx, connect.NewRequest(&ladulasv1.PairFinishRequest{
		SessionId:    first.Msg.GetSessionId(),
		Share:        share,
		Confirmation: session.Confirmation(),
	}))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("finishing an abandoned round: got %v", err)
	}
}

// Both rounds belong to one identity. A second round from anybody else is
// refused, and leaves the exchange for the identity that started it — which
// then pairs.
func TestASecondRoundFromAnotherIdentityIsRefused(t *testing.T) {
	desktop := newInstance(t, "desktop")
	laptop := newInstance(t, "laptop")
	interloper := newInstance(t, "interloper")

	window, _, err := desktop.node.beginPairing(trust.IntentPeerRequests)
	if err != nil {
		t.Fatalf("begin pairing: %v", err)
	}

	defer desktop.node.closeWindow(window)

	ctx := pairingContext(t)
	honest := rawPairing(t, laptop.identity, desktop.address())

	start, err := honest.PairStart(ctx, connect.NewRequest(&ladulasv1.PairStartRequest{}))
	if err != nil {
		t.Fatal(err)
	}

	finishAs := func(
		client ladulasv1connect.PairingServiceClient, joiner *identity.Identity,
	) error {
		share, session, err := cpace.Respond(
			pinInputs(window.pin, joiner.PublicKey(),
				desktop.identity.PublicKey(), start.Msg.GetSessionId()),
			[]byte(adJoiner), start.Msg.GetShare(), []byte(adListener))
		if err != nil {
			return err
		}

		_, err = client.PairFinish(ctx, connect.NewRequest(&ladulasv1.PairFinishRequest{
			SessionId:    start.Msg.GetSessionId(),
			Share:        share,
			Confirmation: session.Confirmation(),
			InstanceName: joiner.Name(),
		}))

		return err //nolint:wrapcheck // the test reads the code
	}

	err = finishAs(rawPairing(t, interloper.identity, desktop.address()),
		interloper.identity)
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("a second round from another identity: got %v", err)
	}

	if err := finishAs(honest, laptop.identity); err != nil {
		t.Fatalf("the identity that started it could not finish: %v", err)
	}
}

// The party identities are bound: a joiner whose idea of the listener's key
// is not the key the listener holds — a relay in the middle — gets a refusal,
// not a pairing.
func TestTheExchangeIsBoundToBothKeys(t *testing.T) {
	desktop := newInstance(t, "desktop")
	laptop := newInstance(t, "laptop")
	relay := newInstance(t, "relay")

	window, _, err := desktop.node.beginPairing(trust.IntentPeerRequests)
	if err != nil {
		t.Fatalf("begin pairing: %v", err)
	}

	defer desktop.node.closeWindow(window)

	ctx := pairingContext(t)
	client := rawPairing(t, laptop.identity, desktop.address())

	start, err := client.PairStart(ctx, connect.NewRequest(&ladulasv1.PairStartRequest{}))
	if err != nil {
		t.Fatal(err)
	}

	share, session, err := cpace.Respond(
		pinInputs(window.pin, laptop.identity.PublicKey(),
			relay.identity.PublicKey(), start.Msg.GetSessionId()),
		[]byte(adJoiner), start.Msg.GetShare(), []byte(adListener))
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.PairFinish(ctx, connect.NewRequest(&ladulasv1.PairFinishRequest{
		SessionId:    start.Msg.GetSessionId(),
		Share:        share,
		Confirmation: session.Confirmation(),
	}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("a tag over the wrong listener key: got %v", err)
	}
}

// A joiner that finds the code already used says so, in the words §7 asks for.
func TestASpentCodeIsReportedLoudly(t *testing.T) {
	desktop := newInstance(t, "desktop")
	first := newInstance(t, "first")
	second := newInstance(t, "second")

	window, _, err := desktop.node.beginPairing(trust.IntentPeerRequests)
	if err != nil {
		t.Fatalf("begin pairing: %v", err)
	}

	defer desktop.node.closeWindow(window)

	ctx := pairingContext(t)

	if _, err := first.node.PairWith(ctx, desktop.address(),
		typedPIN(window.pin)); err != nil {
		t.Fatalf("the first joiner: %v", err)
	}

	// The screen goes away, which is what BeginPairing's deferred close does
	// when its user rejects the card. The spent window must still be there to
	// tell the second joiner why (§7).
	desktop.node.closeWindow(window)

	_, err = second.node.PairWith(ctx, desktop.address(), typedPIN(window.pin))
	if !errors.Is(err, ErrCodeSpent) {
		t.Fatalf("the second joiner: got %v, want ErrCodeSpent", err)
	}
}

// A window nobody used stops admitting the moment its screen goes away:
// nobody is looking at the code any more.
func TestAnUnusedWindowClosesWithItsScreen(t *testing.T) {
	desktop := newInstance(t, "desktop")
	laptop := newInstance(t, "laptop")

	window, _, err := desktop.node.beginPairing(trust.IntentPeerRequests)
	if err != nil {
		t.Fatalf("begin pairing: %v", err)
	}

	desktop.node.closeWindow(window)

	if desktop.node.openWindow() != nil {
		t.Fatal("an unused window outlived its screen")
	}

	_, err = laptop.node.PairWith(pairingContext(t), desktop.address(),
		typedPIN(window.pin))
	if err == nil || errors.Is(err, ErrCodeSpent) {
		t.Fatalf("joining a closed window: got %v", err)
	}
}

// The abandon timer can fire just as a second round takes its exchange. The
// exchange is then the second round's to resolve, and must not be written
// down as abandoned or tire the window under an answer about to verify.
func TestAbandonLeavesATakenExchangeAlone(t *testing.T) {
	window := newPairingWindow("123456", "", trust.IntentPeerRequests)
	defer window.close()

	window.mu.Lock()
	window.charged = trust.MaxAttempts - 1
	window.mu.Unlock()

	if err := window.startExchange("x", &pinExchange{
		fingerprint: "fp", remote: "somewhere",
	}); err != nil {
		t.Fatalf("start: %v", err)
	}

	if _, err := window.takeExchange("x", "fp"); err != nil {
		t.Fatalf("take: %v", err)
	}

	window.abandon("x")

	if got := window.failedAttempts(); len(got) != 0 {
		t.Fatalf("a taken exchange was written down as %v", got)
	}

	select {
	case <-window.exhausted:
		t.Fatal("abandoning a taken exchange tired the window")
	default:
	}

	if !window.passExchange("x") {
		t.Fatal("the verified answer did not claim the window")
	}
}

// The displaying side's card says what failed before the attempt that worked.
func TestTheCardShowsTheFailedAttempts(t *testing.T) {
	desktop := newInstance(t, "desktop")
	laptop := newInstance(t, "laptop")

	window, _, err := desktop.node.beginPairing(trust.IntentPeerRequests)
	if err != nil {
		t.Fatalf("begin pairing: %v", err)
	}

	defer desktop.node.closeWindow(window)

	ctx := pairingContext(t)

	if _, err := laptop.node.PairWith(ctx, desktop.address(),
		typedPIN(wrongPIN(window.pin))); err == nil {
		t.Fatal("a wrong PIN paired")
	}

	pending, err := laptop.node.PairWith(ctx, desktop.address(), typedPIN(window.pin))
	if err != nil {
		t.Fatalf("pair: %v", err)
	}

	listened, ok := desktop.store.PendingPairing(pending.GetSessionId())
	if !ok {
		// It may already have completed, in which case the card was raised from
		// the pending entry before it went; the prompt is the place to look.
		last := desktop.human.last()
		if last == nil {
			t.Fatal("no pending pairing and no prompt on the displaying side")
		}

		if got := last.Msg.GetPairing().GetFailedAttempts(); len(got) != 1 {
			t.Fatalf("the card shows %d failed attempts", len(got))
		}

		return
	}

	attempts := listened.GetFailedAttempts()
	if len(attempts) != 1 || attempts[0].GetSource() == "" {
		t.Fatalf("the pending pairing carries %v", attempts)
	}

	card := desktop.node.pendingConfirmation(listened).GetPairing()
	if len(card.GetFailedAttempts()) != 1 {
		t.Errorf("the card shows %v", card.GetFailedAttempts())
	}
}

// oldListener is a listener from before the PIN: the older Pair and nothing
// else, counting how often it is offered a proof.
type oldListener struct {
	ladulasv1connect.UnimplementedPairingServiceHandler

	pairs atomic.Int32
}

func (o *oldListener) Pair(
	context.Context, *connect.Request[ladulasv1.PairRequest],
) (*connect.Response[ladulasv1.PairResponse], error) {
	o.pairs.Add(1)

	return nil, connect.NewError(connect.CodePermissionDenied,
		errors.New("the pairing code does not match"))
}

// A joiner that holds only a PIN never falls back to the older proof
// (invariant 2). Doing so would hand whoever answered an HMAC over twenty
// bits, and that is the one thing the PIN must never be fed to.
func TestAPINJoinerNeverFallsBackToTheOlderProof(t *testing.T) {
	laptop := newInstance(t, "laptop")

	impostorID, _, err := identity.Generate("desktop")
	if err != nil {
		t.Fatal(err)
	}

	old := &oldListener{}
	mux := http.NewServeMux()
	mux.Handle(ladulasv1connect.NewPairingServiceHandler(old))

	server, err := transport.NewServer(transport.ServerOptions{
		Identity: impostorID,
		Listen:   "127.0.0.1:0",
		Handler:  mux,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := server.Listen(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = server.Serve(ctx) }()

	_, err = laptop.node.PairWith(pairingContext(t), server.Addresses()[0],
		typedPIN("123456"))
	if !errors.Is(err, ErrPossibleImpostor) {
		t.Fatalf("got %v, want ErrPossibleImpostor", err)
	}

	if old.pairs.Load() != 0 {
		t.Error("the PIN joiner offered the older proof")
	}

	if len(laptop.store.PendingPairings()) != 0 {
		t.Error("a refused join left a pending pairing behind")
	}
}

// A window that holds no ten-character code refuses the older proof
// altogether, which is how the overlap ends (invariant 3).
func TestAWindowWithoutTheOlderCodeRefusesTheOlderProof(t *testing.T) {
	desktop := newInstance(t, "desktop")
	laptop := newInstance(t, "laptop")

	window, secret, err := desktop.node.beginPairing(trust.IntentPeerRequests)
	if err != nil {
		t.Fatalf("begin pairing: %v", err)
	}

	defer desktop.node.closeWindow(window)

	window.secret = ""

	_, err = laptop.node.PairWith(pairingContext(t), desktop.address(),
		&ladulasv1.PairingCode{Version: 1, Secret: string(secret)})
	if err == nil {
		t.Fatal("the older proof paired against a window without the older code")
	}
}
