//go:build !notailcat

package tunnel

import (
	"io"
	"log/slog"
	"testing"

	"tailscale.com/types/key"
)

// The pairing server admits any client key up to its cap, goes on admitting
// the ones it has, and refuses every new one after that — for good, since a
// refused client asks again every second (decision AZ).
func TestThePairingServerCountsDistinctKeys(t *testing.T) {
	allow := &cappedKeys{max: 2, log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	first, second, third := key.NewNode().Public(), key.NewNode().Public(),
		key.NewNode().Public()

	for _, k := range []key.NodePublic{first, second, first, second} {
		if !allow.admit(k) {
			t.Fatalf("refused %v within the cap", k.ShortString())
		}
	}

	if allow.admit(third) {
		t.Error("a key past the cap was admitted")
	}

	if allow.admit(third) {
		t.Error("a refused key was admitted when it asked again")
	}

	if !allow.admit(first) {
		t.Error("an admitted key was refused once the cap was reached")
	}
}
