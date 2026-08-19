package app_test

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/durationpb"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// Waiting for a person to unlock the store.
//
// The two things worth proving are that it does not return early — a wait that
// answered "sealed" immediately would be a poll with extra steps — and that a
// wait which runs out says so rather than failing, because "still sealed after
// a second" is a fact about the store.

func TestAwaitStateReturnsWhenTheStoreIsUnlocked(t *testing.T) {
	inst := start(t)
	inst.lock(t, true)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	waited := make(chan *ladulasv1.AwaitStateResponse, 1)

	go func() {
		resp, err := inst.client.Control().AwaitState(ctx,
			connect.NewRequest(&ladulasv1.AwaitStateRequest{}))
		if err != nil {
			t.Errorf("await: %v", err)

			close(waited)

			return
		}

		waited <- resp.Msg
	}()

	// It is waiting for somebody, so nothing has happened yet.
	select {
	case answer := <-waited:
		t.Fatalf("the wait ended before anybody unlocked anything: %v", answer)
	case <-time.After(200 * time.Millisecond):
	}

	if err := inst.unlock(t, testPassphrase); err != nil {
		t.Fatalf("unlock: %v", err)
	}

	select {
	case answer := <-waited:
		if answer == nil {
			t.Fatal("the wait failed")
		}

		if !answer.GetReached() {
			t.Errorf("the wait says it did not reach anything")
		}

		if answer.GetState() != ladulasv1.LockState_LOCK_STATE_UNLOCKED {
			t.Errorf("the wait ended at %v", answer.GetState())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the wait did not notice the unlock")
	}
}

func TestAwaitStateThatRunsOutIsAnAnswer(t *testing.T) {
	inst := start(t)
	inst.lock(t, true)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := inst.client.Control().AwaitState(ctx,
		connect.NewRequest(&ladulasv1.AwaitStateRequest{
			Timeout: durationpb.New(50 * time.Millisecond),
		}))
	if err != nil {
		t.Fatalf("await: %v", err)
	}

	if resp.Msg.GetReached() {
		t.Errorf("a sealed store reported reaching unlocked")
	}

	if resp.Msg.GetState() != ladulasv1.LockState_LOCK_STATE_SEALED {
		t.Errorf("the store is %v", resp.Msg.GetState())
	}
}

// A soft lock is unsealed, and something waiting for the key to be in memory
// has had what it was waiting for even though the store is not unlocked (§10).
func TestAwaitStateTellsUnsealedFromUnlocked(t *testing.T) {
	inst := start(t)
	inst.lock(t, false)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := inst.client.Control().AwaitState(ctx,
		connect.NewRequest(&ladulasv1.AwaitStateRequest{
			States: []ladulasv1.LockState{
				ladulasv1.LockState_LOCK_STATE_UNLOCKED,
				ladulasv1.LockState_LOCK_STATE_LOCKED,
			},
			Timeout: durationpb.New(time.Second),
		}))
	if err != nil {
		t.Fatalf("await: %v", err)
	}

	if !resp.Msg.GetReached() ||
		resp.Msg.GetState() != ladulasv1.LockState_LOCK_STATE_LOCKED {
		t.Errorf("a soft-locked store did not count as unsealed: %v", resp.Msg)
	}

	// And something waiting for unlocked specifically is still waiting.
	resp, err = inst.client.Control().AwaitState(ctx,
		connect.NewRequest(&ladulasv1.AwaitStateRequest{
			Timeout: durationpb.New(50 * time.Millisecond),
		}))
	if err != nil {
		t.Fatalf("await: %v", err)
	}

	if resp.Msg.GetReached() {
		t.Errorf("a soft-locked store reported being unlocked")
	}
}
