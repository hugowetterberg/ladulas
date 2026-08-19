package approval

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// ConsoleHandler prompts on a terminal. It is what a headless box with no GUI
// gets when it is started interactively, and it is how the engine can be
// exercised end to end without a desktop session.
type ConsoleHandler struct {
	In  io.Reader
	Out io.Writer

	// mu serialises prompts: a terminal can only show one at a time, and two
	// goroutines reading the same stdin would each get half the answer.
	mu sync.Mutex
}

var _ LocalPrompt = (*ConsoleHandler)(nil)

// ID implements Handler.
func (c *ConsoleHandler) ID() string {
	return "console"
}

// LocalPrompt implements LocalPrompt: a terminal is somewhere a person here
// answers, so a soft lock takes it out of the eligible set (§10).
func (c *ConsoleHandler) LocalPrompt() {
}

// Decide implements Handler.
func (c *ConsoleHandler) Decide(ctx context.Context, req *Request) (*Answer, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	fmt.Fprintf(c.Out, "\n%s\n", req.Prompt.Text())
	fmt.Fprintf(c.Out, "\n  [y] approve once  [n] deny%s\n> ",
		grantOptionsText(req.GrantTTLs, req.GrantSubject))

	line, err := readLine(ctx, c.In)
	if err != nil {
		return nil, err
	}

	answer := strings.TrimSpace(strings.ToLower(line))

	switch {
	case answer == "y" || answer == "yes":
		return &Answer{
			Decision: ladulasv1.Decision_DECISION_APPROVE,
			Reason:   "approved at the console",
		}, nil
	case strings.HasPrefix(answer, "g"):
		return c.grantAnswer(answer, req), nil
	default:
		return &Answer{
			Decision: ladulasv1.Decision_DECISION_DENY,
			Reason:   "denied at the console",
		}, nil
	}
}

func (c *ConsoleHandler) grantAnswer(answer string, req *Request) *Answer {
	index, convErr := strconv.Atoi(strings.TrimPrefix(answer, "g"))

	if convErr != nil || index < 1 || index > len(req.GrantTTLs) {
		fmt.Fprintf(c.Out, "no such option, denying\n")

		return &Answer{
			Decision: ladulasv1.Decision_DECISION_DENY,
			Reason:   "unrecognised answer at the console",
		}
	}

	ttl := req.GrantTTLs[index-1]

	return &Answer{
		Decision: ladulasv1.Decision_DECISION_APPROVE,
		Reason:   "approved at the console for " + HumanDuration(ttl),
		GrantTTL: ttl,
	}
}

// grantOptionsText offers the promise the way it will be kept: to the session
// the request came from, when there is one to name (decision U).
//
// A terminal offers the four lengths and nothing else. Choosing a length on a
// clock and widening a promise to the whole machine are decision V, and they
// are for a screen with a picker on it; a console that grew a syntax for both
// would be asking somebody to spell out, in the dark, the thing the wording is
// there to make plain.
func grantOptionsText(ttls []time.Duration, subject string) string {
	if len(ttls) == 0 {
		return ""
	}

	var b strings.Builder

	for i, ttl := range ttls {
		if subject == "" {
			fmt.Fprintf(&b, "  [g%d] approve for %s", i+1, HumanDuration(ttl))

			continue
		}

		fmt.Fprintf(&b, "  [g%d] approve %s for %s",
			i+1, subject, HumanDuration(ttl))
	}

	return b.String()
}

// readLine reads one line, giving up when the context is done. A blocked read
// on a terminal cannot be interrupted, so the goroutine outlives the call — it
// finishes when the user eventually types something, or when the process exits.
func readLine(ctx context.Context, in io.Reader) (string, error) {
	type readResult struct {
		line string
		err  error
	}

	results := make(chan readResult, 1)

	go func() {
		line, err := bufio.NewReader(in).ReadString('\n')
		results <- readResult{line: line, err: err}
	}()

	select {
	case r := <-results:
		if r.err != nil && r.line == "" {
			return "", fmt.Errorf("read answer: %w", r.err)
		}

		return r.line, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}
