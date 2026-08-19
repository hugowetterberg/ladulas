package observe

import "strings"

// Label names and the values that are not read off an enum. They are constants
// because a label spelled two ways is two time series that look like one, and
// the compiler is the only thing that will ever notice.
const (
	labelState     = "state"
	labelOrigin    = "origin"
	labelKind      = "kind"
	labelDecision  = "decision"
	labelSource    = "source"
	labelEvent     = "event"
	labelPlatform  = "platform"
	labelStyle     = "style"
	labelOutcome   = "outcome"
	labelProcedure = "procedure"
	labelCode      = "code"
)

// other is the bucket a value falls into when this build has no name for it. A
// label vocabulary has to be bounded by something, and here it is bounded by
// the schema — a value from a newer peer counts as other rather than becoming a
// time series nobody declared.
//
// It is deliberately not spelled "unknown": WAKE_OUTCOME_UNKNOWN is a real
// answer meaning "no device has registered that instance id", and a bucket that
// shared its name would make an unregistered phone and a schema mismatch the
// same line on a graph.
const other = "other"

// enumLabel turns a protobuf enum into a label value: the generated name, with
// the enum's prefix taken off and lowercased. REQUEST_KIND_SSH_AUTH becomes
// ssh_auth.
func enumLabel[T ~int32](value T, names map[int32]string, prefix string) string {
	name, ok := names[int32(value)]
	if !ok {
		return other
	}

	name = strings.TrimPrefix(name, prefix)
	if name == "" {
		return other
	}

	return strings.ToLower(name)
}
