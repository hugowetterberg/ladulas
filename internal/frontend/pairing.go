package frontend

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"connectrpc.com/connect"

	"github.com/hugowetterberg/ladulas/pkg/bridge"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/trust"
)

// Displaying a pairing code from the window (§7, decision AD).
//
// The daemon owns the pairing window and the listener, so starting one is a
// call — and it is a *streamed* call whose lifetime is the window's: the code
// is live for as long as somebody holds the stream open, and closing it closes
// the window. That is the whole reason this is a small object with a goroutine
// in it rather than one more method beside the others. A front end that made
// the call and returned would have displayed a code that had already stopped
// working.
//
// What it deliberately does not do is answer anything. The confirmation a
// pairing raises reaches this process the way every other request does, on the
// approval stream, and is drawn as the card it is — so there is one card, one
// renderer and one audit entry whether somebody paired from this window, from
// the command line or from a phone.

// invitationTimeout bounds waiting for the daemon's first message, which is the
// code itself. The listener is already up by then; this is a local socket
// answering, and a daemon that has not in two seconds is one to report.
const invitationTimeout = 2 * time.Second

// pairingControl is the bridge.Pairing a front end offers.
type pairingControl struct {
	front *Frontend

	mu      sync.Mutex
	live    *bridge.Invitation
	cancel  context.CancelFunc
	expires time.Time
	// window counts the codes this front end has displayed, so that a stream
	// ending after a second one was opened cannot take the second one off the
	// screen on its way out.
	window int
}

var _ bridge.Pairing = (*pairingControl)(nil)

// Invite spends a code and holds the window open until somebody stops it.
func (p *pairingControl) Invite(
	_ context.Context, intent trust.Intent,
) (bridge.Invitation, error) {
	if intent == trust.IntentUnspecified {
		return bridge.Invitation{}, bridge.ErrNoIntent
	}

	// One code at a time, and the caller's context is not the window's: the
	// request that asked for a code finishes as soon as the code is on screen,
	// and the window has to outlive it.
	p.Stop()

	ctx, cancel := context.WithCancel(context.Background())

	stream, err := p.front.client.BeginPairing(ctx,
		connect.NewRequest(&ladulasv1.BeginPairingRequest{
			Intent: trust.IntentToWire(intent),
		}))
	if err != nil {
		cancel()

		return bridge.Invitation{}, fmt.Errorf("ask for a pairing code: %w", err)
	}

	invitation, err := firstCode(ctx, stream)
	if err != nil {
		cancel()

		_ = stream.Close()

		return bridge.Invitation{}, err
	}

	p.mu.Lock()
	p.window++
	window := p.window
	p.live = &invitation
	p.cancel = cancel
	p.expires = invitation.Expires
	p.mu.Unlock()

	// The rest of the stream is read and thrown away — the pairing itself is
	// followed through the store and the approval stream, and all this needs is
	// to know when the window has closed, so that the screen stops showing a
	// code that no longer works.
	go p.follow(stream, cancel, window)

	return invitation, nil
}

// firstCode waits for the code, which is the first thing BeginPairing sends.
func firstCode(
	ctx context.Context,
	stream *connect.ServerStreamForClient[ladulasv1.PairingProgress],
) (bridge.Invitation, error) {
	type result struct {
		invitation bridge.Invitation
		err        error
	}

	// The read is on a goroutine because a stream receive cannot be
	// interrupted; it ends when the daemon answers or when the context this
	// call was made on is cancelled, which closes the stream under it.
	answers := make(chan result, 1)

	go func() {
		for stream.Receive() {
			progress := stream.Msg()

			if progress.GetKind() !=
				ladulasv1.PairingProgressKind_PAIRING_PROGRESS_KIND_CODE {
				continue
			}

			answers <- result{invitation: invitationFrom(progress)}

			return
		}

		err := stream.Err()
		if err == nil {
			err = errors.New("the instance displayed no pairing code")
		}

		answers <- result{err: err}
	}()

	select {
	case answer := <-answers:
		if answer.err != nil {
			return bridge.Invitation{},
				fmt.Errorf("ask for a pairing code: %w", answer.err)
		}

		return answer.invitation, nil
	case <-time.After(invitationTimeout):
		return bridge.Invitation{},
			errors.New("the instance did not answer with a pairing code")
	case <-ctx.Done():
		return bridge.Invitation{}, ctx.Err() //nolint:wrapcheck // the caller reports it
	}
}

func invitationFrom(progress *ladulasv1.PairingProgress) bridge.Invitation {
	invitation := bridge.Invitation{
		Code:      progress.GetCode(),
		FullCode:  progress.GetFullCode(),
		Addresses: progress.GetListenAddresses(),
		Intent:    trust.IntentFromWire(progress.GetIntent()),
	}

	if expires := progress.GetExpiresAt(); expires != nil {
		invitation.Expires = expires.AsTime()
	}

	return invitation
}

// follow drains the stream and forgets the code when it ends.
func (p *pairingControl) follow(
	stream *connect.ServerStreamForClient[ladulasv1.PairingProgress],
	cancel context.CancelFunc,
	window int,
) {
	defer cancel()

	defer func() {
		if err := stream.Close(); err != nil {
			p.front.log.Debug("closing the pairing stream", "error", err.Error())
		}
	}()

	for stream.Receive() {
		if stream.Msg().GetKind() ==
			ladulasv1.PairingProgressKind_PAIRING_PROGRESS_KIND_FAILED {
			p.front.log.Info("the pairing code is no longer on offer",
				"reason", stream.Msg().GetMessage())
		}
	}

	p.forget(window)
}

// Invitation is the code on display, if it is still worth displaying.
func (p *pairingControl) Invitation() (bridge.Invitation, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// A code past its five minutes is not one to show. The daemon closes the
	// window on the same clock, so this is the screen agreeing with it rather
	// than deciding anything.
	if p.live == nil || time.Now().After(p.expires) {
		return bridge.Invitation{}, false
	}

	return *p.live, true
}

// Stop takes the code off display, which closes the window at the daemon.
func (p *pairingControl) Stop() {
	p.mu.Lock()
	cancel := p.cancel
	p.live, p.cancel = nil, nil
	p.mu.Unlock()

	if cancel != nil {
		cancel()
	}
}

// forget clears an invitation that ended by itself, and only if it is still the
// one on screen: a code opened while an older stream was closing must not be
// taken away by the older one's goodbye.
func (p *pairingControl) forget(window int) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.window != window {
		return
	}

	p.live, p.cancel = nil, nil
}

// generateKey makes a key in the daemon's store.
//
// The window holds no key and never has (decision Z); this is the same call
// `ladulas keys generate` makes, from the surface that lists what it produced.
func (f *Frontend) generateKey(
	ctx context.Context, label, comment string,
) (*ladulasv1.KeyRef, error) {
	if label == "" {
		return nil, errors.New("a key needs a name to be asked for by")
	}

	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()

	resp, err := f.client.GenerateKey(ctx,
		connect.NewRequest(&ladulasv1.GenerateKeyRequest{
			Label:   label,
			Comment: comment,
		}))
	if err != nil {
		return nil, fmt.Errorf("generate the key: %w", err)
	}

	key := resp.Msg.GetKey()

	return &ladulasv1.KeyRef{
		Fingerprint: key.GetFingerprint(),
		Algorithm:   key.GetAlgorithm(),
		PublicKey:   key.GetPublicKey(),
		Comment:     key.GetComment(),
		Label:       key.GetLabel(),
		AgentUse:    key.AgentUse,
	}, nil
}
