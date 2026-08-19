// Package signcli implements ladulas-sign, the signing program git runs when
// gpg.ssh.program points at Ladulås (docs/architecture.md §5).
//
// The contract it has to honour is not a design of ours: it is whatever
// ssh-keygen accepts, because git constructs the command line. Against git
// 2.55 that is exactly two shapes, depending on whether user.signingkey names a
// key file or a literal public key:
//
//	ssh-keygen -Y sign -n git -f <private-key>    <payload-file>
//	ssh-keygen -Y sign -n git -f <public-key> -U  <payload-file>
//
// and the signature is expected in <payload-file>.sig. git runs the same
// program for verification, with -Y find-principals and -Y verify, reading the
// payload from standard input — so anything that is not a signing request is
// handed to the real ssh-keygen unchanged.
package signcli

import (
	"errors"
	"fmt"
	"strings"
)

// ErrUnsupportedInvocation means the command line is one this program does not
// implement itself. It is not a failure: the real ssh-keygen gets it.
var ErrUnsupportedInvocation = errors.New("signcli: not a signing invocation")

// invocation is a parsed `-Y sign` command line.
type invocation struct {
	// Namespace is -n. ssh-keygen has no default and neither do we.
	namespace string
	// KeyFile is -f: a private key path, or a file holding a public key when
	// the signature is to be made through an agent.
	keyFile string
	// UseAgent is -U.
	useAgent bool
	// Files are the payloads to sign. "-" means standard input.
	files []string
	// Options are -O key[=value] pairs, kept so they can be reported rather
	// than silently ignored.
	options []string
}

// signFlagsWithValue are the flags of a signing invocation that consume the
// next argument. Anything outside this set — or outside signFlagsBoolean — is
// unfamiliar enough that the real ssh-keygen should deal with it.
var signFlagsWithValue = map[byte]bool{
	'Y': true,
	'n': true,
	'f': true,
	'O': true,
}

var signFlagsBoolean = map[byte]bool{
	'q': true,
	'v': true,
}

// operationOf finds the -Y value without parsing the rest, so that a
// find-principals or verify command line can be passed on without this program
// having to understand every flag those take.
func operationOf(args []string) (string, bool) {
	for i := range args {
		arg := args[i]

		if arg == "--" {
			return "", false
		}

		if !strings.HasPrefix(arg, "-Y") {
			continue
		}

		if len(arg) > 2 {
			return arg[2:], true
		}

		if i+1 < len(args) {
			return args[i+1], true
		}

		return "", false
	}

	return "", false
}

// parseSign reads a `-Y sign` command line.
func parseSign(args []string) (*invocation, error) {
	inv := &invocation{}

	for i := 0; i < len(args); i++ {
		arg := args[i]

		if arg == "--" {
			inv.files = append(inv.files, args[i+1:]...)

			break
		}

		if arg == "-" || !strings.HasPrefix(arg, "-") {
			inv.files = append(inv.files, arg)

			continue
		}

		if len(arg) < 2 {
			return nil, fmt.Errorf("%w: %q", ErrUnsupportedInvocation, arg)
		}

		name := arg[1]

		switch {
		case signFlagsBoolean[name] && len(arg) == 2:
			// Nothing to record; -q and -v only change ssh-keygen's chatter.
			continue
		case name == 'U' && len(arg) == 2:
			inv.useAgent = true

			continue
		case !signFlagsWithValue[name]:
			return nil, fmt.Errorf("%w: unknown flag %q", ErrUnsupportedInvocation, arg)
		}

		value := arg[2:]

		if value == "" {
			i++

			if i >= len(args) {
				return nil, fmt.Errorf("%w: %q wants a value",
					ErrUnsupportedInvocation, arg)
			}

			value = args[i]
		}

		switch name {
		case 'Y':
			if value != "sign" {
				return nil, fmt.Errorf("%w: -Y %s", ErrUnsupportedInvocation, value)
			}
		case 'n':
			inv.namespace = value
		case 'f':
			inv.keyFile = value
		case 'O':
			inv.options = append(inv.options, value)
		}
	}

	if inv.namespace == "" {
		return nil, fmt.Errorf("%w: no namespace", ErrUnsupportedInvocation)
	}

	if inv.keyFile == "" {
		return nil, fmt.Errorf("%w: no key", ErrUnsupportedInvocation)
	}

	if len(inv.files) == 0 {
		// ssh-keygen reads standard input when there is no file to sign.
		inv.files = []string{"-"}
	}

	// The signing options ssh-keygen understands are about hash algorithm and
	// timestamps, neither of which Ladulås implements yet. Rather than sign
	// something subtly different from what was asked for, hand it over.
	if len(inv.options) > 0 {
		return nil, fmt.Errorf("%w: signing options %s",
			ErrUnsupportedInvocation, strings.Join(inv.options, ", "))
	}

	return inv, nil
}
