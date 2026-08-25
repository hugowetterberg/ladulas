package peer

import (
	"context"
	"errors"
	"net"
	"slices"
	"testing"

	"github.com/hugowetterberg/ladulas/pkg/identity"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
	"github.com/hugowetterberg/ladulas/pkg/transport"
)

// TestThePreferredAddressIsGivenSeveralGoesBeforeTheSweep is the compromise in
// presenceMisses, from both ends.
//
// A healthy link must cost one dial per beat and not fourteen, because a trust
// record written before decision AH holds every address the peer could see
// including its container runtime's, and a peer that is merely asleep charges a
// dial timeout for each. A link whose address has genuinely gone must still find
// the peer somewhere else, which is what the code this replaces never did: it
// took the first address, mistook a queued request for a connection, and never
// reached the second.
func TestThePreferredAddressIsGivenSeveralGoesBeforeTheSweep(t *testing.T) {
	t.Parallel()

	all := []string{
		"100.74.235.31:7373", "10.26.30.34:7373", "172.17.0.1:7373",
	}

	l := &link{
		record: &storepb.TrustRecord{Addresses: all},
	}

	// Nothing has worked yet, so there is nothing to prefer and everything to
	// try. This is the first connection and a peer whose record was written by
	// somebody else's pairing.
	if got := l.presenceOrder(); !slices.Equal(got, all) {
		t.Errorf("with no preferred address tried %v, want all of %v", got, all)
	}

	l.preferred = "10.26.30.34:7373"

	// The address that last worked is worth the benefit of the doubt: a peer
	// that has closed its lid is not a peer that has moved.
	want := []string{"10.26.30.34:7373"}

	for attempt := range presenceMisses {
		if got := l.presenceOrder(); !slices.Equal(got, want) {
			t.Fatalf("attempt %d tried %v, want only %v", attempt, got, want)
		}

		l.failed(errors.New("i/o timeout"))
	}

	// It has now failed often enough to be doubted, and the rest of the record
	// gets a turn — the preferred one still first, since it is still the best
	// guess, just no longer the only one.
	got := l.presenceOrder()

	if !slices.Equal(got, l.addresses()) {
		t.Errorf("after %d failures tried %v, want the whole record %v",
			presenceMisses, got, l.addresses())
	}

	if len(got) != len(all) {
		t.Errorf("the sweep offered %d addresses, want %d", len(got), len(all))
	}

	// A beat puts it back to trusting the address that produced the beat.
	// online is set first so that succeeded takes this for a link that was
	// already up, which is the path that does not go on to push grant activity.
	l.online = true
	l.succeeded("172.17.0.1:7373")

	after := l.presenceOrder()
	if !slices.Equal(after, []string{"172.17.0.1:7373"}) {
		t.Errorf("after a beat tried %v, want only the address that beat", after)
	}
}

// TestAPeerThatNeverBeatsIsNotALink is the bug itself.
//
// connect hands back a stream as soon as the request is queued and keeps the
// transport error for the first Receive, so `Watch` returning nil is not a
// connection. This used to be read as one: the link marked itself online, logged
// "linked to a peer", and returned — which is how a laptop asleep with its lid
// shut was reported as connected every twenty seconds, and why the loop over the
// peer's addresses never reached its second entry.
//
// A closed port is enough to show it. The dial is refused immediately and
// `Watch` still returns no error.
func TestAPeerThatNeverBeatsIsNotALink(t *testing.T) {
	t.Parallel()

	self, _, err := identity.Generate("guppy")
	if err != nil {
		t.Fatalf("generate an identity: %v", err)
	}

	peer, _, err := identity.Generate("horatio")
	if err != nil {
		t.Fatalf("generate a peer identity: %v", err)
	}

	client, err := transport.NewClient(transport.ClientOptions{
		Identity: self,
		Expect:   peer.PublicKey(),
	})
	if err != nil {
		t.Fatalf("build a client: %v", err)
	}

	l := &link{
		client: client,
		record: &storepb.TrustRecord{Addresses: []string{closedPort(t)}},
	}

	// node is nil on purpose: nothing before the first beat may need it, and a
	// panic here would mean something claims the peer is there before it is.
	if err := l.presence(context.Background()); err == nil {
		t.Error("a peer that never answered produced no error")
	}

	if l.online {
		t.Error("a peer that never answered was marked online")
	}

	if l.preferred != "" {
		t.Errorf("a peer that never answered became the preferred address: %q",
			l.preferred)
	}
}

// closedPort is an address that nothing is listening on, obtained by listening
// and then stopping, so that the port is real and known to be free rather than
// guessed.
func closedPort(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("take a port: %v", err)
	}

	address := listener.Addr().String()

	if err := listener.Close(); err != nil {
		t.Fatalf("give the port back: %v", err)
	}

	return address
}
