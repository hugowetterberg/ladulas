//go:build !linux

package peercred

import (
	"errors"
	"net"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// Process has no implementation outside Linux yet. macOS has LOCAL_PEERPID
// and Windows has its own named pipe equivalent; both arrive with those
// platforms' milestones. Prompts simply omit the process context until then.
func Process(net.Conn) (*ladulasv1.ClientProcess, error) {
	return nil, errors.New("peer credentials are not implemented on this platform")
}
