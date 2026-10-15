package peer

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1/ladulasv1connect"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
	"github.com/hugowetterberg/ladulas/pkg/transport"
	"github.com/hugowetterberg/ladulas/pkg/trust"
)

// acrossNetworks is two machines that cannot reach each other directly at
// all — no bound listener on either, and no direct probe that answers — with
// the tunnel upgrade on at both, on one fabric. It is the café laptop and the
// desktop at home that the pairing server exists for (decision AZ).
type acrossNetworks struct {
	desk, laptop *instance
	fabric       *fabric
	deskTunnel   *fakeTunnel
	laptopTunnel *fakeTunnel
}

func newAcrossNetworks(t *testing.T, laptopTunnel bool) *acrossNetworks {
	t.Helper()

	h := &acrossNetworks{
		desk:   newInstanceOn(t, "desk", transport.ListenNone),
		laptop: newInstanceOn(t, "laptop", transport.ListenNone),
		fabric: newFabric(),
	}

	nothing := func(context.Context, []string) string { return "" }

	for _, side := range []*instance{h.desk, h.laptop} {
		side.node.probe = nothing
		side.node.pairingGrace = 50 * time.Millisecond
	}

	h.deskTunnel = h.fabric.tunnel("tcdesk", 1)
	h.desk.node.SetTunnel(h.deskTunnel)
	waitOffer(t, h.desk.node)

	if laptopTunnel {
		h.laptopTunnel = h.fabric.tunnel("tclaptop", 2)
		h.laptop.node.SetTunnel(h.laptopTunnel)
		waitOffer(t, h.laptop.node)
	}

	return h
}

// display opens a window on the desk and builds the full code BeginPairing
// would show: the PIN, the key, a direct address nothing answers at, and the
// pairing server's address when there is one.
func (h *acrossNetworks) display(t *testing.T) (*pairingWindow, *ladulasv1.PairingCode, offNetwork) {
	t.Helper()

	window, secret, err := h.desk.node.beginPairing(trust.IntentPeerRequests)
	if err != nil {
		t.Fatalf("begin pairing: %v", err)
	}

	t.Cleanup(func() { h.desk.node.closeWindow(window) })

	reach := h.desk.node.openPairingServer(window)

	code := trust.NewCode(window.pin, secret, "desk", h.desk.identity.PublicKey(),
		[]string{"127.0.0.1:1"}, window.expires)
	code.TunnelAddress = reach.address
	code.TunnelVersion = uint32(max(reach.version, 0))

	return window, code, reach
}

func joinContext(t *testing.T) context.Context {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)

	return ctx
}

// A full code whose direct addresses do not answer pairs through the pairing
// server, settles over the two long-lived tunnels, and records neither the
// pairing server's address nor anything else that is not a direct address
// (decision AZ).
func TestAFullCodePairsThroughThePairingServer(t *testing.T) {
	h := newAcrossNetworks(t, true)

	_, code, reach := h.display(t)
	if reach.address == "" {
		t.Fatalf("no pairing server: %s", reach.sentence)
	}

	if strings.Contains(reach.sentence, "unavailable") {
		t.Errorf("the screen says %q with a pairing server up", reach.sentence)
	}

	pending, err := h.laptop.node.PairWith(joinContext(t), "", code)
	if err != nil {
		t.Fatalf("pair through the pairing server: %v", err)
	}

	// The joiner wrote down the listener's long-lived offer and where it was
	// reached, and no address: the pairing server's dies with the window.
	if len(pending.GetAddresses()) != 0 {
		t.Errorf("the joiner recorded addresses %v", pending.GetAddresses())
	}

	if got := pending.GetRemoteAddress(); got != PairingServerPath {
		t.Errorf("the joiner says it reached the listener at %q", got)
	}

	if got := pending.GetTunnel().GetServerAddress(); got != "tcdesk" {
		t.Errorf("the joiner holds the tunnel offer %q, want the long-lived one", got)
	}

	// PairWith has returned, so the displaying side has written its half
	// down; a missing one is a failure, not a check to skip.
	listened, ok := h.desk.store.PendingPairing(h.laptop.identity.Fingerprint())
	if !ok {
		t.Fatal("the displaying side recorded no pending pairing")
	}

	if got := listened.GetRemoteAddress(); got != PairingServerPath {
		t.Errorf("the displaying side's card says %q", got)
	}

	// Both admitted the other's long-lived client key on spend.
	if !h.deskTunnel.admits(h.laptopTunnel.client) ||
		!h.laptopTunnel.admits(h.deskTunnel.client) {
		t.Error("the long-lived client keys were not admitted on both sides")
	}

	// And the pairing completes with no direct path between them: both
	// humans approve, and SettlePairing goes through the tunnels.
	theirs := waitPaired(t, h.desk, h.laptop.identity.Fingerprint())
	ours := waitPaired(t, h.laptop, h.desk.identity.Fingerprint())

	for _, record := range []struct {
		name    string
		address []string
	}{{"desk", theirs.GetAddresses()}, {"laptop", ours.GetAddresses()}} {
		for _, address := range record.address {
			if !trust.IsDirectAddress(address) || strings.HasPrefix(address, "tc") {
				t.Errorf("the %s recorded %q", record.name, address)
			}
		}
	}

	// The pairing server closes once the exchange that spent the code has
	// answered, and its grace is over.
	waitUntil(t, "the pairing server closes after the grace", func() bool {
		return h.deskTunnel.pairing().isClosed()
	})
}

// A joiner with the upgrade off is refused before anything is sent: a pair
// born through the pairing server with no tunnel on one side could never
// settle (decision AZ).
func TestJoiningAcrossNetworksNeedsTheTunnel(t *testing.T) {
	h := newAcrossNetworks(t, false)

	window, code, reach := h.display(t)
	if reach.address == "" {
		t.Fatalf("no pairing server: %s", reach.sentence)
	}

	_, err := h.laptop.node.PairWith(joinContext(t), "", code)
	if !errors.Is(err, ErrTunnelNeeded) {
		t.Fatalf("joined with the tunnel off: %v", err)
	}

	// Nothing reached the window, so nothing was charged.
	window.mu.Lock()
	charged := window.charged
	window.mu.Unlock()

	if charged != 0 {
		t.Errorf("a refused join charged %d attempts", charged)
	}
}

// The pairing server is started only while the long-lived server is up, and
// the screen says why when it is not (decision AZ).
func TestNoPairingServerWithoutTheLongLivedServer(t *testing.T) {
	off := newInstanceOn(t, "off", transport.ListenNone)

	window, _, err := off.node.beginPairing(trust.IntentPeerRequests)
	if err != nil {
		t.Fatalf("begin pairing: %v", err)
	}

	defer off.node.closeWindow(window)

	reach := off.node.openPairingServer(window)
	if reach.address != "" ||
		!strings.HasPrefix(reach.sentence, "Off-network pairing unavailable: the tunnel is off") {
		t.Errorf("with the tunnel off: %+v", reach)
	}

	// Built and not up: a server whose start fails.
	starting := newInstanceOn(t, "starting", transport.ListenNone)
	tunnel := newFabric().tunnel("tcstarting", 3)
	tunnel.failures = 1_000_000

	starting.node.SetTunnel(tunnel)

	window, _, err = starting.node.beginPairing(trust.IntentPeerRequests)
	if err != nil {
		t.Fatalf("begin pairing: %v", err)
	}

	defer starting.node.closeWindow(window)

	waitUntil(t, "the server reports why it is not up", func() bool {
		return starting.node.TunnelStatus().Detail != ""
	})

	reach = starting.node.openPairingServer(window)
	if reach.address != "" || !strings.Contains(reach.sentence, "not up") {
		t.Errorf("with the server not up: %+v", reach)
	}

	if tunnel.pairing() != nil {
		t.Error("a pairing server was started without the long-lived one")
	}
}

// A window that closes unused takes its pairing server with it, and so does
// the node closing — which is what sealing does (§3, decision AZ).
func TestThePairingServerClosesWithItsWindowAndTheNode(t *testing.T) {
	h := newAcrossNetworks(t, true)

	window, _, reach := h.display(t)
	if reach.address == "" {
		t.Fatalf("no pairing server: %s", reach.sentence)
	}

	first := h.deskTunnel.pairing()

	h.desk.node.closeWindow(window)

	waitUntil(t, "the unused window's pairing server closes", first.isClosed)

	_, _, reach = h.display(t)
	if reach.address == "" {
		t.Fatalf("no second pairing server: %s", reach.sentence)
	}

	second := h.deskTunnel.pairing()
	if second == first {
		t.Fatal("the second window reused the first pairing server")
	}

	if err := h.desk.node.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if !second.isClosed() {
		t.Error("closing the node left the pairing server up")
	}
}

// The pairing server's door: anybody while its window is open, the PIN
// exchange and nothing else, and nobody once another window has replaced it.
func TestThePairingGate(t *testing.T) {
	h := newAcrossNetworks(t, true)

	window, _, _ := h.display(t)
	gate := pairingGate{node: h.desk.node, window: window}

	if err := gate.Admit("SHA256:stranger", nil); err != nil {
		t.Errorf("a stranger was refused while the window is open: %v", err)
	}

	for procedure, allowed := range map[string]bool{
		pairStartProcedure:                            true,
		pairFinishProcedure:                           true,
		settleProcedure:                               false,
		"/ladulas.v1.PairingService/Pair":             false,
		"/ladulas.v1.ApprovalService/RequestApproval": false,
	} {
		err := gate.Permit("SHA256:stranger", procedure)
		if allowed != (err == nil) {
			t.Errorf("%s: permitted=%v", procedure, err == nil)
		}
	}

	if _, _, err := h.desk.node.beginPairing(trust.IntentPeerRequests); err != nil {
		t.Fatalf("begin pairing: %v", err)
	}

	if err := gate.Admit("SHA256:stranger", nil); err == nil {
		t.Error("a replaced window's pairing server still admits")
	}
}

// Spent is not closed: the pairing server stays up while the exchange that
// spent the code is still writing its answer, and closes a grace after it
// has. Closing on spend would tear down the connection carrying the response,
// and leave the displaying side with a pending pairing the joiner never heard
// about (decision AZ).
func TestASpentPairingServerWaitsForItsAnswer(t *testing.T) {
	n := tunnelNode(&memoryStore{}, nil)
	n.pairingGrace = 20 * time.Millisecond

	window := newPairingWindow("123456", "", trust.IntentPeerRequests)
	listener := &fabricListener{closed: make(chan struct{})}

	serve := &pairingServe{
		window:   window,
		server:   &fakePairingServer{tunnel: newFakeTunnel("tcpair", 0), listener: listener},
		finished: make(chan struct{}, 1),
		closed:   make(chan struct{}),
	}

	// The second round is being served, and spends the code.
	serve.begin()

	go n.runPairingServer(serve)

	window.mu.Lock()
	window.claimLocked()
	window.mu.Unlock()

	time.Sleep(100 * time.Millisecond)

	if serve.server.(*fakePairingServer).isClosed() {
		t.Fatal("the pairing server closed while the exchange that spent it was answering")
	}

	serve.end()

	waitUntil(t, "the pairing server closes after its answer and the grace",
		serve.server.(*fakePairingServer).isClosed)
}

// A pairing born through the pairing server, refused at the desk while the
// laptop cannot be reached, is still heard about once it can: the desk holds
// the refusal with the laptop's client key admitted, both gates let the laptop
// in to ask, and whichever end gets through first ends it at both (§7,
// refusal.go). Before the hold, the laptop's convergence loop was refused at
// the door on every attempt, forever.
func TestARefusalAcrossNetworksIsHeardWhenTheFarSideComesBack(t *testing.T) {
	for _, ending := range []string{"declined", "withdrawn"} {
		t.Run(ending, func(t *testing.T) {
			h := newAcrossNetworks(t, true)
			h.desk.node.refusalGrace = 20 * time.Millisecond
			h.laptop.node.refusalGrace = 20 * time.Millisecond

			// Nobody at the desk answers on their own; the test does.
			h.desk.drop()

			_, code, reach := h.display(t)
			if reach.address == "" {
				t.Fatalf("no pairing server: %s", reach.sentence)
			}

			if _, err := h.laptop.node.PairWith(joinContext(t), "", code); err != nil {
				t.Fatalf("pair through the pairing server: %v", err)
			}

			laptopFP := h.laptop.identity.Fingerprint()

			// The laptop goes to sleep: nothing crosses the fabric.
			h.fabric.setBroken(true)

			var err error

			if ending == "declined" {
				_, _, _, err = h.desk.node.AnswerPending(laptopFP, false, "not today")
			} else {
				_, _, err = h.desk.node.Withdraw(context.Background(), laptopFP, "not today")
			}

			if err != nil {
				t.Fatalf("%s at the desk: %v", ending, err)
			}

			if _, ok := h.desk.store.PendingPairing(laptopFP); ok {
				t.Fatal("the desk still lists a pairing it refused")
			}

			// Held: the laptop's key stays admitted, and both doors let it in
			// to ask, through the tunnel for SettlePairing only.
			if !h.deskTunnel.admits(h.laptopTunnel.client) {
				t.Error("refusing took the laptop's key off before it heard")
			}

			gate := tunnelGate{node: h.desk.node}

			if err := gate.Admit(laptopFP, h.laptopTunnel.client); err != nil {
				t.Errorf("the tunnel gate refused a peer that has not heard: %v", err)
			}

			if err := gate.Admit(laptopFP, []byte("some other key")); err == nil {
				t.Error("the tunnel gate admitted the held identity on another key")
			}

			if err := gate.Permit(laptopFP, settleProcedure); err != nil {
				t.Errorf("the held identity cannot reach SettlePairing: %v", err)
			}

			if err := gate.Permit(laptopFP,
				ladulasv1connect.ApprovalServiceRequestApprovalProcedure); err == nil {
				t.Error("the held identity reaches more than SettlePairing")
			}

			if err := h.desk.node.gate(&transport.PeerIdentity{Fingerprint: laptopFP}); err != nil {
				t.Errorf("the bound gate refused a peer that has not heard: %v", err)
			}

			// The laptop wakes. Its half ends, in the desk's words.
			h.fabric.setBroken(false)

			waitUntil(t, "the laptop hears the refusal", func() bool {
				_, ok := h.laptop.store.PendingPairing(h.desk.identity.Fingerprint())

				return !ok
			})

			if _, ok := h.laptop.store.Peer(h.desk.identity.Fingerprint()); ok {
				t.Error("the laptop paired with a desk that refused")
			}

			// And the hold ends at the desk, with both allowlists let go.
			waitUntil(t, "the desk lets the refusal go", func() bool {
				_, held := h.desk.node.heldRefusalOf(laptopFP)

				return !held && !h.deskTunnel.admits(h.laptopTunnel.client)
			})

			waitUntil(t, "the laptop lets the desk's key go", func() bool {
				return !h.laptopTunnel.admits(h.deskTunnel.client)
			})

			if err := gate.Admit(laptopFP, h.laptopTunnel.client); err == nil {
				t.Error("the tunnel gate still admits the laptop after it heard")
			}
		})
	}
}

// A peer that asks about a refusal it has not heard is told it in the words it
// was made in, not "no record" (refusal.go).
func TestAHeldRefusalAnswersInItsOwnWords(t *testing.T) {
	t.Parallel()

	n := tunnelNode(&memoryStore{}, newFakeTunnel("tcours", 9))
	n.refusalGrace = time.Hour

	n.holdRefusal(&storepb.PendingPairing{
		SessionId:   "s1",
		Fingerprint: "SHA256:laptop",
		OurAnswer:   ladulasv1.PairingAnswer_PAIRING_ANSWER_DECLINED,
	}, "not today")

	if _, held := n.answerHeldRefusal("SHA256:somebody-else", "s1"); held {
		t.Error("another identity was answered from the laptop's refusal")
	}

	resp, held := n.answerHeldRefusal("SHA256:laptop", "s1")
	if !held {
		t.Fatal("the held refusal did not answer")
	}

	if resp.GetState() != ladulasv1.PairingRecordState_PAIRING_RECORD_STATE_GONE ||
		resp.GetAnswer() != ladulasv1.PairingAnswer_PAIRING_ANSWER_DECLINED ||
		resp.GetReason() != "not today" {
		t.Errorf("answered %v", resp)
	}

	// Heard is not released at once: an answer lost on the way is asked for
	// again.
	if _, held := n.answerHeldRefusal("SHA256:laptop", "s1"); !held {
		t.Error("a heard refusal was gone before its grace")
	}

	if got := refusalMessage(ladulasv1.PairingAnswer_PAIRING_ANSWER_ACCEPTED,
		resp.GetAnswer(), resp.GetReason()); got != "declined at the other end: not today" {
		t.Errorf("the asker would say %q", got)
	}
}
