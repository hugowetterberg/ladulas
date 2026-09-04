package frontend

import (
	"context"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"

	"github.com/hugowetterberg/ladulas/pkg/bridge"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// Joining a pairing from the window: the code another machine is showing,
// pasted here (§7, §14).
//
// Like displaying a code, dialling one is a streamed control call — but the
// stream's lifetime is not the pairing's. The daemon writes the pending pairing
// down as soon as the handshake succeeds, and reconciles it with the other side
// whether or not anybody is still listening (core §7), so this holds the stream
// only long enough to learn whether the dial worked. The confirmation the
// pairing raises reaches this process the way every other request does, on the
// approval stream, and is drawn as the card it is; what the stream says about
// it is read and thrown away.

// joinTimeout bounds waiting for the daemon's first word about the dial. The
// dial is to another machine, over whichever network the address is on, so it
// is a network timeout and not the two seconds a local socket gets.
const joinTimeout = 30 * time.Second

// join dials the machine displaying a code and reports when it has answered.
func (f *Frontend) join(
	ctx context.Context, code, address string,
) (bridge.JoinView, error) {
	// The stream outlives the request that asked for it, for the same reason
	// the pairing window's does: the answer goes back as soon as the dial has
	// worked, and the rest of the exchange is followed on its own.
	streamCtx, cancel := context.WithCancel(context.Background())

	stream, err := f.client.PairWithPeer(streamCtx,
		connect.NewRequest(&ladulasv1.PairWithPeerRequest{
			Address: address,
			Code:    code,
		}))
	if err != nil {
		cancel()

		return bridge.JoinView{}, fmt.Errorf("join a pairing: %w", err)
	}

	type result struct {
		view bridge.JoinView
		err  error
	}

	answers := make(chan result, 1)

	// The read is on a goroutine because a stream receive cannot be
	// interrupted; the first message is the answer, and the goroutine goes on
	// reading after it so that the daemon's end of the stream is drained rather
	// than blocked on a window that stopped listening.
	go func() {
		defer cancel()

		defer func() {
			if err := stream.Close(); err != nil {
				f.log.Debug("closing the join stream", "error", err.Error())
			}
		}()

		answered := false

		for stream.Receive() {
			progress := stream.Msg()

			if answered {
				continue
			}

			view, done, err := joinProgress(progress)
			if !done {
				continue
			}

			answered = true
			answers <- result{view: view, err: err}
		}

		if answered {
			return
		}

		err := stream.Err()
		if err == nil {
			err = errors.New("the instance said nothing about the pairing")
		}

		answers <- result{err: err}
	}()

	select {
	case answer := <-answers:
		return answer.view, answer.err
	case <-time.After(joinTimeout):
		cancel()

		return bridge.JoinView{}, errors.New(
			"the other machine did not answer in time; check the address " +
				"and that its code is still showing")
	case <-ctx.Done():
		cancel()

		return bridge.JoinView{}, ctx.Err()
	}
}

// joinProgress turns the first thing the daemon says about a dial into the
// answer a screen gets, and says whether it was the first thing worth saying.
func joinProgress(progress *ladulasv1.PairingProgress) (bridge.JoinView, bool, error) {
	switch progress.GetKind() {
	case ladulasv1.PairingProgressKind_PAIRING_PROGRESS_KIND_CONFIRM:
		return bridge.JoinView{
			RequestID: progress.GetConfirmation().GetRequestId(),
			Message: "The other machine answered. Compare the two " +
				"fingerprints on the card before agreeing.",
		}, true, nil
	case ladulasv1.PairingProgressKind_PAIRING_PROGRESS_KIND_DONE:
		return bridge.JoinView{
			Message: "Paired with " + progress.GetPeer().GetName() + ".",
		}, true, nil
	case ladulasv1.PairingProgressKind_PAIRING_PROGRESS_KIND_WAITING:
		return bridge.JoinView{Message: progress.GetMessage()}, true, nil
	case ladulasv1.PairingProgressKind_PAIRING_PROGRESS_KIND_FAILED:
		return bridge.JoinView{}, true, errors.New(progress.GetMessage())
	case ladulasv1.PairingProgressKind_PAIRING_PROGRESS_KIND_CODE,
		ladulasv1.PairingProgressKind_PAIRING_PROGRESS_KIND_UNSPECIFIED:
	}

	return bridge.JoinView{}, false, nil
}
