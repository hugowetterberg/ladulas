package approval

import (
	"context"
	"sync"
)

// Requests that are out with approvers, and how somebody who arrives late joins
// one (decision AL).
//
// The engine used to settle the set of approvers when it fanned a request out
// and never look at it again, so a front end that attached a second later was a
// front end that would not be asked. That is not a rule about authority — the
// question has been asked of this machine, the front end is authorised by the
// socket it is on (§14), and it can answer nothing a front end attached a
// moment earlier could not. It was an accident of where the loop kept its
// count.
//
// The count is the part to be careful with. `prompt` denies with NO_APPROVER
// once every approver it asked has gone, and decision AC is the bug that lived
// in exactly that arithmetic: a peer with nobody to ask reported instantly, won
// every race, and vetoed every signature on the machine. So the denominator
// moves under a lock here rather than being a `len()` in the loop, a request
// that has been settled takes no more joiners, and a join is refused rather
// than raced when the two happen at once.

// inflight is one request out with approvers.
type inflight struct {
	req    *Request
	origin Origin
	// ctx is the request's, deadline included. A late joiner is handed this one
	// and not a fresh one: the budget belongs to the request (§9), and an
	// approver that could restart the clock by attaching would be an approver
	// who could hold a terminal open indefinitely by opening a window.
	ctx      context.Context //nolint:containedctx // it is the request's own
	results  chan promptResult
	failures chan struct{}

	mu sync.Mutex
	// asked is by handler and not by ID, because two front ends attached at
	// once are two approvers and may share a name.
	asked   map[Handler]bool
	count   int
	settled bool
}

// promptResult is one approver's answer on its way back to the loop.
type promptResult struct {
	handler Handler
	answer  *Answer
}

// takeoff records a request as being out with the approvers it was fanned to,
// and returns the entry a late arrival joins.
func (e *Engine) takeoff(
	ctx context.Context, req *Request, handlers []Handler,
) *inflight {
	flight := &inflight{
		req:    req,
		origin: req.Origin,
		ctx:    ctx,
		// Buffered for the approvers asked up front, which is the whole of the
		// ordinary case. A joiner may find it full, and sends give up on the
		// context rather than blocking forever — see send.
		results:  make(chan promptResult, len(handlers)),
		failures: make(chan struct{}, len(handlers)),
		asked:    make(map[Handler]bool, len(handlers)),
		count:    len(handlers),
	}

	for _, h := range handlers {
		flight.asked[h] = true
	}

	e.flightMu.Lock()
	defer e.flightMu.Unlock()

	if e.flights == nil {
		e.flights = map[string]*inflight{}
	}

	e.flights[req.Msg.GetRequestId()] = flight

	return flight
}

// land takes a request out of the set that can be joined. It is called when
// `prompt` returns, whatever it returns: settled, timed out or withdrawn are
// all "no longer a question anybody may be asked".
func (e *Engine) land(flight *inflight) {
	flight.mu.Lock()
	flight.settled = true
	flight.mu.Unlock()

	e.flightMu.Lock()
	defer e.flightMu.Unlock()

	delete(e.flights, flight.req.Msg.GetRequestId())
}

// waiting is the requests that could still be joined, copied out so that
// nothing holds the map's lock while a handler is being called.
func (e *Engine) waiting() []*inflight {
	e.flightMu.Lock()
	defer e.flightMu.Unlock()

	out := make([]*inflight, 0, len(e.flights))
	for _, flight := range e.flights {
		out = append(out, flight)
	}

	return out
}

// offer puts every request that is still waiting in front of an approver that
// has just become eligible — one that registered, or a local prompt that a soft
// lock has just been lifted from.
//
// It is what makes "start the terminal and answer what is stuck" work at all.
// Without it the answer to a signature blocking a terminal was to have already
// been running the thing that could answer it.
func (e *Engine) offer(h Handler) {
	for _, flight := range e.waiting() {
		if !e.mayAnswer(h, flight.origin) {
			continue
		}

		e.join(flight, h)
	}
}

// offerLocal is the same for every local prompt at once, for the moment a soft
// lock is lifted (§10).
func (e *Engine) offerLocal() {
	e.mu.RLock()
	handlers := make([]Handler, len(e.handlers))
	copy(handlers, e.handlers)
	e.mu.RUnlock()

	for _, h := range handlers {
		if _, local := h.(LocalPrompt); !local {
			continue
		}

		e.offer(h)
	}
}

// join adds one approver to a request already out, and is the only place the
// denominator grows.
//
// Three ways it refuses, and each of them is a way a card could otherwise
// appear for a question that is over: the request has been settled, its context
// has finished, or this approver has already been asked.
func (e *Engine) join(flight *inflight, h Handler) {
	flight.mu.Lock()

	if flight.settled || flight.ctx.Err() != nil || flight.asked[h] {
		flight.mu.Unlock()

		return
	}

	flight.asked[h] = true
	flight.count++

	flight.mu.Unlock()

	e.log.Debug("a request that was already waiting was offered to an approver",
		"approver", h.ID(), "request_id", flight.req.Msg.GetRequestId())

	go e.ask(flight, h)
}

// ask is one approver's turn: it runs the handler and puts what came back where
// the loop can see it.
func (e *Engine) ask(flight *inflight, h Handler) {
	// Settled between the join and this goroutine being scheduled. Presenting
	// now would put a card on a screen and take it off again in the same
	// breath, which reads as a fault rather than as a race.
	if flight.ctx.Err() != nil {
		return
	}

	answer, err := h.Decide(flight.ctx, flight.req)
	if err != nil {
		if flight.ctx.Err() == nil {
			e.log.Warn("approver failed",
				"approver", h.ID(),
				"request_id", flight.req.Msg.GetRequestId(),
				"error", err.Error())
		}

		send(flight.ctx, flight.failures, struct{}{})

		return
	}

	send(flight.ctx, flight.results, promptResult{handler: h, answer: answer})
}

// send hands a result to the loop, or gives up when the request is over.
//
// The channels are sized for the approvers asked up front, so a joiner can find
// one full — and once `prompt` has returned nobody is reading either of them.
// A blocking send would leak the goroutine for as long as the process lives;
// the context is finished by then, because `prompt` cancels it on the way out.
func send[T any](ctx context.Context, to chan T, value T) {
	select {
	case to <- value:
	case <-ctx.Done():
	}
}

// allGone reports whether every approver this request was put in front of has
// gone without deciding it — read under the lock, because a joiner may have
// moved the denominator since the last time round the loop.
func (f *inflight) allGone(failed int) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	return failed >= f.count
}

// mayAnswer is `eligible`'s test for one handler, so that a request being fanned
// out and a request being joined apply the same rule rather than two copies of
// it.
func (e *Engine) mayAnswer(h Handler, origin Origin) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return e.mayAnswerLocked(h, origin)
}

func (e *Engine) mayAnswerLocked(h Handler, origin Origin) bool {
	// Any request that came from a peer stops here, whichever door it came
	// through: passing one on would make this instance a relay for somebody
	// else's decision. See RemoteHandler.
	if _, remote := h.(RemoteHandler); remote && origin != OriginLocal {
		return false
	}

	if _, local := h.(LocalPrompt); local && e.softLocked {
		return false
	}

	return true
}

// Waiting is how many requests are out with approvers right now. It is for the
// tests and for a metric; nothing decides anything with it.
func (e *Engine) Waiting() int {
	e.flightMu.Lock()
	defer e.flightMu.Unlock()

	return len(e.flights)
}
