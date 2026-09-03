package peer

import (
	"context"
	"net"
	"testing"
	"time"
)

// The failure this exists for: a tailnet whose IPv6 is blackholed and whose
// IPv4 works. Serially that is a ten-second wait before the address that could
// have worked is tried, on every call, and a phone pays it once per address.

// blackholed is an address nothing answers on and nothing refuses either, which
// is what a blackholed route looks like from the dialler: no RST, no ICMP, just
// silence until the timeout. 203.0.113.0/24 is TEST-NET-3 and is not routed.
const blackholed = "203.0.113.1:7373"

func listening(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	t.Cleanup(func() {
		_ = listener.Close()
	})

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			_ = conn.Close()
		}
	}()

	return listener.Addr().String()
}

func TestAnAddressThatAnswersIsTriedFirst(t *testing.T) {
	t.Parallel()

	live := listening(t)

	// The blackholed one first, which is the order the trust record has it in
	// and the reason every call was starting with a ten-second timeout.
	got := reachableFirst(context.Background(), []string{blackholed, live})

	if got[0] != live {
		t.Errorf("tried %s first, want the address that answers (%s)",
			got[0], live)
	}

	if len(got) != 2 {
		t.Errorf("got %d addresses back, want both", len(got))
	}
}

// Reordering, not selecting: an address that lost the race is still tried, and
// everything callOver does about ranking failures still happens.
func TestEveryAddressSurvivesTheRace(t *testing.T) {
	t.Parallel()

	live := listening(t)

	got := reachableFirst(context.Background(),
		[]string{blackholed, live, "198.51.100.7:7373"})

	if len(got) != 3 {
		t.Fatalf("got %d addresses, want all three", len(got))
	}

	seen := map[string]bool{}
	for _, address := range got {
		seen[address] = true
	}

	for _, want := range []string{blackholed, live, "198.51.100.7:7373"} {
		if !seen[want] {
			t.Errorf("%s was dropped by the race", want)
		}
	}
}

// A peer that is wholly unreachable must not turn the race into a second wait
// on top of the dialling: it gives up at probeTimeout and leaves the order
// alone.
func TestARaceNobodyWinsChangesNothingAndIsQuick(t *testing.T) {
	t.Parallel()

	addresses := []string{blackholed, "198.51.100.7:7373"}

	started := time.Now()
	got := reachableFirst(context.Background(), addresses)
	took := time.Since(started)

	if took > probeTimeout*2 {
		t.Errorf("the race took %s, want it bounded by %s", took, probeTimeout)
	}

	for i, want := range addresses {
		if got[i] != want {
			t.Errorf("order changed: got %v, want %v", got, addresses)

			break
		}
	}
}

// One address is the ordinary case and must not pay for a race at all.
func TestASingleAddressIsNotRaced(t *testing.T) {
	t.Parallel()

	started := time.Now()
	got := reachableFirst(context.Background(), []string{blackholed})
	took := time.Since(started)

	if took > 100*time.Millisecond {
		t.Errorf("racing one address took %s, want none of the probe budget",
			took)
	}

	if len(got) != 1 || got[0] != blackholed {
		t.Errorf("got %v, want the address unchanged", got)
	}
}

// A cancelled call does not wait out the probe.
func TestACancelledRaceReturnsAtOnce(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	started := time.Now()
	got := reachableFirst(ctx, []string{blackholed, "198.51.100.7:7373"})

	if took := time.Since(started); took > time.Second {
		t.Errorf("a cancelled race took %s", took)
	}

	if len(got) != 2 {
		t.Errorf("got %d addresses, want both back unchanged", len(got))
	}
}

// The point of remembering: the ordinary call does not race at all.
//
// A race per call was the first shape of this and it was the wrong one — it
// made a per-call cost cheaper instead of noticing the per-call cost should not
// exist. What a repeated caller wants is the connection it already has, to the
// address that already worked.

func TestARememberedAddressIsUsedWithoutRacing(t *testing.T) {
	t.Parallel()

	held := &dialer{}
	held.remember("100.64.0.5:7373")

	raced := false

	order := held.order(func(all []string) []string {
		raced = true

		return all
	}, []string{blackholed, "100.64.0.5:7373", "198.51.100.7:7373"})

	if raced {
		t.Error("a call with a remembered address raced anyway")
	}

	if order[0] != "100.64.0.5:7373" {
		t.Errorf("tried %s first, want the remembered address", order[0])
	}

	if len(order) != 3 {
		t.Errorf("got %d addresses, want all of them still there", len(order))
	}
}

func TestWithNothingRememberedTheAddressesAreRaced(t *testing.T) {
	t.Parallel()

	held := &dialer{}

	raced := false

	held.order(func(all []string) []string {
		raced = true

		return all
	}, []string{blackholed, "100.64.0.5:7373"})

	if !raced {
		t.Error("a cold call did not race, so it will pay a dial timeout")
	}
}

// A peer that stopped advertising the remembered address — which is what
// pruning an address list does (decision AH) — has nothing to prefer, and
// preferring it anyway would put an address the peer disowned at the front.
func TestAnAddressThePeerNoLongerAdvertisesIsNotPreferred(t *testing.T) {
	t.Parallel()

	held := &dialer{}
	held.remember("192.0.2.9:7373")

	raced := false

	order := held.order(func(all []string) []string {
		raced = true

		return all
	}, []string{"100.64.0.5:7373", blackholed})

	if !raced {
		t.Error("a stale remembered address should fall back to the race")
	}

	if order[0] == "192.0.2.9:7373" {
		t.Error("an address the peer no longer advertises was tried first")
	}
}

// A call that failed everywhere forgets, because the address that worked here
// is the least likely to be the right guess on whatever network this is now.
func TestForgettingSendsTheNextCallBackToTheRace(t *testing.T) {
	t.Parallel()

	held := &dialer{}
	held.remember("100.64.0.5:7373")
	held.forget()

	raced := false

	held.order(func(all []string) []string {
		raced = true

		return all
	}, []string{"100.64.0.5:7373"})

	if !raced {
		t.Error("forgetting did not send the next call back to the race")
	}
}
