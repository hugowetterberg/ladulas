package relay

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"connectrpc.com/connect"

	"github.com/hugowetterberg/ladulas/pkg/identity"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1/ladulasv1connect"
)

// The two calls anybody makes to a relay, in one place because the two ends of
// M9 make one each and neither should have its own idea of what a signed call
// looks like: a phone registers its device token, and a requester knocks.
//
// A plain HTTP client, deliberately. The peer channel's pinned TLS is about a
// peer's identity key and a relay has no identity in this system at all; what
// protects these calls is that they say nothing — an opaque identifier and a
// signature over it — so the worst a hostile relay learns is that somebody
// signed something.

// Timeout bounds one call. Nothing is waiting for the answer: a registration
// that failed is retried the next time the app opens, and a wake-up that failed
// is a phone that gets picked up by hand.
const Timeout = 10 * time.Second

// Client is the caller's half of a relay.
type Client struct {
	// Identity signs the calls. Required.
	Identity *identity.Identity
	// HTTP defaults to one with Timeout.
	HTTP *http.Client
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}

	return &http.Client{Timeout: Timeout}
}

// Register binds this instance's device token to its instance id at a relay.
//
// The first registration for an id claims it for this identity key, and every
// later one has to be signed by the same key — so re-registering a rotated token
// works and pointing somebody else's id at this device does not.
func (c *Client) Register(
	ctx context.Context, relayURL, instanceID string,
	platform ladulasv1.PushPlatform, deviceToken string,
) error {
	call := identity.NewRelayCall(instanceID)
	call.Operation = &ladulasv1.RelayCall_Register{
		Register: &ladulasv1.DeviceRegistration{
			Platform:    platform,
			DeviceToken: deviceToken,
		},
	}

	signed, err := c.Identity.SignRelayCall(call)
	if err != nil {
		return err
	}

	service := ladulasv1connect.NewRelayServiceClient(c.http(), relayURL)

	_, err = service.Register(ctx, connect.NewRequest(
		&ladulasv1.RegisterRequest{Signed: signed}))
	if err != nil {
		return fmt.Errorf("register with the relay at %s: %w", relayURL, err)
	}

	return nil
}

// Wake asks a relay to knock on one instance, and reports what became of it.
func (c *Client) Wake(
	ctx context.Context, relayURL, instanceID string,
	style ladulasv1.WakeStyle, subject ladulasv1.WakeSubject,
) (ladulasv1.WakeOutcome, error) {
	call := identity.NewRelayCall(instanceID)
	call.Operation = &ladulasv1.RelayCall_Wake{
		Wake: &ladulasv1.Wake{Style: style, Subject: subject},
	}

	signed, err := c.Identity.SignRelayCall(call)
	if err != nil {
		return ladulasv1.WakeOutcome_WAKE_OUTCOME_UNSPECIFIED, err
	}

	service := ladulasv1connect.NewRelayServiceClient(c.http(), relayURL)

	resp, err := service.Wake(ctx, connect.NewRequest(
		&ladulasv1.WakeRequest{Signed: signed}))
	if err != nil {
		return ladulasv1.WakeOutcome_WAKE_OUTCOME_UNSPECIFIED,
			fmt.Errorf("wake through the relay at %s: %w", relayURL, err)
	}

	return resp.Msg.GetOutcome(), nil
}
