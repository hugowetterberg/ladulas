package localapi

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"

	"connectrpc.com/connect"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1/ladulasv1connect"
)

// ErrNoInstance is returned when nothing is listening on the socket. Callers
// treat it as "fall back to plain ssh-keygen" rather than as a failure: a
// machine where the daemon is not running should still be able to commit (§5).
var ErrNoInstance = errors.New("localapi: no Ladulås instance is listening")

// Client talks to a local instance over its unix socket.
type Client struct {
	socketPath string
	signing    ladulasv1connect.SigningServiceClient
	control    ladulasv1connect.ControlServiceClient
}

// NewClient builds a client for a socket path. An empty path means
// DefaultSocketPath().
func NewClient(socketPath string) *Client {
	if socketPath == "" {
		socketPath = DefaultSocketPath()
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var dialer net.Dialer

				conn, err := dialer.DialContext(ctx, "unix", socketPath)
				if err != nil {
					return nil, fmt.Errorf("%w: %w", ErrNoInstance, err)
				}

				return conn, nil
			},
		},
		// No client timeout: the wait here is a human deciding, which §9 gives
		// an hour. The context is what bounds it.
	}

	// The host in the URL is never resolved — the dialer ignores it — but
	// net/http insists on one.
	const baseURL = "http://ladulas.local"

	// The Connect protocol rather than gRPC: it is a plain POST with a
	// protobuf body, so it needs no HTTP/2 and works over a unix socket with
	// nothing but net/http.
	return &Client{
		socketPath: socketPath,
		signing:    ladulasv1connect.NewSigningServiceClient(httpClient, baseURL),
		control:    ladulasv1connect.NewControlServiceClient(httpClient, baseURL),
	}
}

// Control is the peer and pairing surface of a running instance.
func (c *Client) Control() ladulasv1connect.ControlServiceClient {
	return c.control
}

// SocketPath is the socket this client talks to.
func (c *Client) SocketPath() string {
	return c.socketPath
}

// SignPayload asks the instance to sign a message.
func (c *Client) SignPayload(
	ctx context.Context, req *ladulasv1.SignPayloadRequest,
) (*ladulasv1.SignPayloadResponse, error) {
	resp, err := c.signing.SignPayload(ctx, connect.NewRequest(req))
	if err != nil {
		if errors.Is(err, ErrNoInstance) {
			return nil, ErrNoInstance
		}

		return nil, fmt.Errorf("ask the local instance to sign: %w", err)
	}

	return resp.Msg, nil
}
