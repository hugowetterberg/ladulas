package relay

import (
	"context"
	"errors"
	"fmt"

	"github.com/hugowetterberg/ladulas/pkg/apns"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// APNs adapts the push client to the relay's Pusher.
//
// The only translation is the one that matters: a token the platform says is
// dead has to arrive at the relay as ErrUnregistered, because that is what makes
// the registration go away and the requester stop knocking. Everything else is a
// transient failure and is reported as one, since a relay that forgot a device
// every time Apple had a bad afternoon would be a relay that quietly turned
// wake-ups off for everybody.
type APNs struct {
	Sender *apns.Sender
}

var _ Pusher = (*APNs)(nil)

// Push implements Pusher.
func (a *APNs) Push(
	ctx context.Context, token string, silent bool,
	subject ladulasv1.WakeSubject,
) error {
	style := apns.Alert
	if silent {
		style = apns.Silent
	}

	// An unknown subject is an approval: a relay that has not been redeployed
	// since a new one was added should send the sentence it has always sent
	// rather than nothing at all.
	pushSubject := apns.Approval
	if subject == ladulasv1.WakeSubject_WAKE_SUBJECT_KEY_OFFER {
		pushSubject = apns.KeyOffer
	}

	err := a.Sender.Push(ctx, token, style, pushSubject)
	if err == nil {
		return nil
	}

	if errors.Is(err, apns.ErrUnregistered) {
		return fmt.Errorf("%w: %w", ErrUnregistered, err)
	}

	return err
}
