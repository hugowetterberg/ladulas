// Package gitctx collects and parses the context that turns a git signing
// prompt from "sign this digest" into something worth reading
// (docs/architecture.md §5, §17).
//
// It has two sides, and keeping them apart is the point. Collect runs on the
// requesting machine — the one we distrust when it is a headless box — and
// gathers the repository, the branch and the diff, all of which are asserted
// and nothing more. Describe and Verify run on the approving side and derive
// everything they show from the signed bytes themselves, so that the commit
// message and author in the prompt are provably the ones being signed.
package gitctx

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// ErrNotAGitObject is returned for a payload that is not a commit or tag
// object. git only ever asks its signing program to sign one of the two, so
// anything else means the request did not come from git — worth saying rather
// than guessing.
var ErrNotAGitObject = errors.New("gitctx: not a git commit or tag object")

// Object types as they appear in a context.
const (
	TypeCommit = "commit"
	TypeTag    = "tag"
)

// ParseObject reads the commit or tag object git hands to its signing program.
//
// What git passes is the object as it will be written, minus the signature
// header it is about to add: header lines, a blank line, then the message. The
// parse is deliberately tolerant of headers it does not know — mergetag and
// encoding both turn up in real repositories — and keeps them rather than
// dropping them, so that "there was a header I did not understand" stays
// visible to whoever is approving.
func ParseObject(payload []byte) (*ladulasv1.GitObject, error) {
	headers, message, err := splitObject(payload)
	if err != nil {
		return nil, err
	}

	object := &ladulasv1.GitObject{
		Message: message,
		Subject: subjectOf(message),
	}

	for _, h := range headers {
		if err := applyHeader(object, h); err != nil {
			return nil, err
		}
	}

	switch {
	case object.GetTree() != "" && object.GetTag() == "":
		object.Type = TypeCommit
	case object.GetTaggedObject() != "" && object.GetTag() != "":
		object.Type = TypeTag
	default:
		return nil, fmt.Errorf(
			"%w: no tree header and no tag header", ErrNotAGitObject)
	}

	return object, nil
}

// header is one parsed header line, with continuations already joined.
type header struct {
	name  string
	value string
}

func splitObject(payload []byte) ([]header, string, error) {
	// The header block ends at the first empty line. A commit with no message
	// still has that empty line, so its absence means this is not an object.
	separator := bytes.Index(payload, []byte("\n\n"))
	if separator < 0 {
		return nil, "", fmt.Errorf(
			"%w: no blank line separating headers from the message",
			ErrNotAGitObject)
	}

	block := string(payload[:separator])
	message := string(payload[separator+2:])

	var headers []header

	for _, line := range strings.Split(block, "\n") {
		// A leading space continues the previous header, which is how mergetag
		// and the signature headers carry multi-line values.
		if strings.HasPrefix(line, " ") {
			if len(headers) == 0 {
				return nil, "", fmt.Errorf(
					"%w: a continuation line before any header", ErrNotAGitObject)
			}

			headers[len(headers)-1].value += "\n" + line[1:]

			continue
		}

		name, value, found := strings.Cut(line, " ")
		if !found {
			return nil, "", fmt.Errorf(
				"%w: header line %q has no value", ErrNotAGitObject, line)
		}

		headers = append(headers, header{name: name, value: value})
	}

	if len(headers) == 0 {
		return nil, "", fmt.Errorf("%w: no headers", ErrNotAGitObject)
	}

	return headers, message, nil
}

func applyHeader(object *ladulasv1.GitObject, h header) error {
	switch h.name {
	case "tree":
		object.Tree = h.value
	case "parent":
		object.Parents = append(object.GetParents(), h.value)
	case "object":
		object.TaggedObject = h.value
	case "type":
		object.TaggedType = h.value
	case "tag":
		object.Tag = h.value
	case "author", "committer", "tagger":
		id, err := ParseIdentity(h.value)
		if err != nil {
			return fmt.Errorf("%s header: %w", h.name, err)
		}

		switch h.name {
		case "author":
			object.Author = id
		case "committer":
			object.Committer = id
		case "tagger":
			object.Tagger = id
		}
	default:
		object.ExtraHeaders = append(object.GetExtraHeaders(), &ladulasv1.GitHeader{
			Name:  h.name,
			Value: h.value,
		})
	}

	return nil
}

// ParseIdentity reads one of git's author, committer or tagger lines:
//
//	Name <email> 1786209283 +0200
//
// The name is whatever precedes the address and may contain anything git let
// through, so the address is found from the last angle bracket pair rather than
// the first — a display name containing a bracket must not shift the parse.
func ParseIdentity(line string) (*ladulasv1.GitIdentity, error) {
	closing := strings.LastIndex(line, ">")
	if closing < 0 {
		return nil, fmt.Errorf("%w: no email address in %q", ErrNotAGitObject, line)
	}

	opening := strings.LastIndex(line[:closing], "<")
	if opening < 0 {
		return nil, fmt.Errorf("%w: no email address in %q", ErrNotAGitObject, line)
	}

	id := &ladulasv1.GitIdentity{
		Name:  strings.TrimSpace(line[:opening]),
		Email: line[opening+1 : closing],
	}

	rest := strings.Fields(line[closing+1:])

	// A timestamp is not strictly guaranteed — git itself tolerates identity
	// lines without one when reading old history — so its absence leaves the
	// time unset rather than failing the parse.
	if len(rest) == 0 {
		return id, nil
	}

	seconds, err := strconv.ParseInt(rest[0], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("%w: timestamp %q: %w", ErrNotAGitObject, rest[0], err)
	}

	id.Time = timestamppb.New(time.Unix(seconds, 0).UTC())

	if len(rest) > 1 {
		id.Timezone = rest[1]
	}

	return id, nil
}

// subjectOf is the first line of the message, which is what every git UI calls
// the subject.
func subjectOf(message string) string {
	line, _, _ := strings.Cut(message, "\n")

	return strings.TrimSpace(line)
}

// Describe parses the object carried in a context and fills in everything
// derived from it, replacing whatever the requester put there.
//
// The replacement is the point: the requester may assert what it likes about
// the repository, but the message and author shown next to a signature come
// from the bytes being signed and are parsed here, on the approving side (§5).
func Describe(git *ladulasv1.GitContext) error {
	if git == nil {
		return errors.New("gitctx: no context")
	}

	git.ObjectType = ""
	git.Parsed = nil

	object, err := ParseObject(git.GetObject())
	if err != nil {
		return err
	}

	git.ObjectType = object.GetType()
	git.Parsed = object

	return nil
}
