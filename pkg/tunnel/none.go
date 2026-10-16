//go:build notailcat

package tunnel

import (
	"errors"

	"github.com/hugowetterberg/ladulas/pkg/peer"
)

// Available says this build carries tailcat: it does not.
const Available = false

// ErrUnavailable is what New says in a build without tailcat.
var ErrUnavailable = errors.New("tunnel: this build does not carry tailcat")

// Tunnel is never built here.
type Tunnel struct{}

// New refuses: a build with the notailcat tag has no tunnel to offer, and says
// so to every peer with the withdrawal form (decision AX).
func New(Options) (*Tunnel, error) {
	return nil, ErrUnavailable
}

// Open refuses for the same reason.
func Open(Options) (peer.Tunnel, error) {
	return nil, ErrUnavailable
}
