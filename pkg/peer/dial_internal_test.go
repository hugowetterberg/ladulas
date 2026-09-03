package peer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"syscall"
	"testing"

	"github.com/hugowetterberg/ladulas/pkg/transport"
)

// TestTheReportedFailureIsTheInformativeOne is the dial half of the loopback
// bug. The list is ordered best first, so the *last* address is the one nobody
// expected to work — and reporting its error meant reporting the loopback
// attempt, which reached this instance and complained about the peer's identity.
//
// See bugs/an-identity-mismatch-that-was-a-loopback-address.md.
func TestTheReportedFailureIsTheInformativeOne(t *testing.T) {
	refused := &net.OpError{
		Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED,
	}

	cases := []struct {
		name      string
		failures  map[string]error
		addresses []string
		want      string
		notWant   string
	}{
		{
			name: "our own loopback does not become the verdict on the peer",
			failures: map[string]error{
				"100.74.235.31:7373": refused,
				"127.0.0.1:7373":     transport.ErrSelfAddress,
			},
			addresses: []string{"100.74.235.31:7373", "127.0.0.1:7373"},
			want:      "100.74.235.31:7373",
			notWant:   "127.0.0.1:7373",
		},
		{
			name: "a refusal beats a name that would not resolve",
			failures: map[string]error{
				"horatio.tail97712.ts.net:7373": &net.DNSError{
					Err: "no such host", Name: "horatio.tail97712.ts.net",
				},
				"100.74.235.31:7373": refused,
			},
			addresses: []string{
				"horatio.tail97712.ts.net:7373", "100.74.235.31:7373",
			},
			want:    "100.74.235.31:7373",
			notWant: "tail97712",
		},
		{
			name: "an answer beats a refusal, wherever it came in the list",
			failures: map[string]error{
				"192.168.1.201:7373": fmt.Errorf("%w: got somebody else",
					transport.ErrUnknownPeer),
				"100.74.235.31:7373": refused,
			},
			addresses: []string{
				"192.168.1.201:7373", "100.74.235.31:7373",
			},
			want: "192.168.1.201:7373",
		},
	}

	node := &Node{}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := node.callOver(context.Background(), &transport.Client{},
				tc.addresses,
				func(_ context.Context, _ *http.Client, baseURL string) error {
					for address, failure := range tc.failures {
						if strings.Contains(baseURL, address) {
							return failure
						}
					}

					return fmt.Errorf("no failure set up for %s", baseURL)
				})
			if err == nil {
				t.Fatal("every address failed and the call succeeded")
			}

			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("reported %v, want the failure at %s",
					err, tc.want)
			}

			if tc.notWant != "" && strings.Contains(err.Error(), tc.notWant) {
				t.Errorf("reported %v, which is the address that says least",
					err)
			}
		})
	}
}

// TestEveryAddressBeingOursSaysSo is the case the skip could have hidden: a
// trust record holding nothing but this machine's own addresses is not a peer
// that is offline, and waiting for it would never end.
func TestEveryAddressBeingOursSaysSo(t *testing.T) {
	node := &Node{}

	_, err := node.callOver(context.Background(), &transport.Client{},
		[]string{"127.0.0.1:7373", "[::1]:7373"},
		func(_ context.Context, _ *http.Client, _ string) error {
			return transport.ErrSelfAddress
		})

	if !errors.Is(err, transport.ErrSelfAddress) {
		t.Fatalf("reported %v, want a self-address error", err)
	}

	if !strings.Contains(err.Error(), "never dialled") {
		t.Errorf("reported %v, which does not say the peer was not tried", err)
	}
}
