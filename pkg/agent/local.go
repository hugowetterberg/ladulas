package agent

import (
	"crypto"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hugowetterberg/ladulas/pkg/keystore"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// The keys programs park in the agent (§10, decision AU).
//
// A local key is a credential Ladulås is holding, not a key it manages. It
// arrived through the agent protocol's Add — `ssh-add`, or Teleport's tsh
// pushing the certificate it just minted — and it lives in this process's
// memory for as long as the adder asked, which is exactly the promise every
// tool that calls Add was written against. It is written nowhere: the store
// is the thing that is encrypted, unlocked and backed up, and none of those
// promises make sense for material with a twelve-hour life that a far end
// will reissue on demand. Sealing drops every one of them, because seal means
// the machine holds nothing usable.
//
// What a local key cannot do is leave. It is not in the store, so it is not
// among the keys a peer is offered, not something RemoteSign resolves, and not
// something SendKey can find — by construction rather than by a check. That is
// what bounds the blast radius of accepting Add at all: a hostile process on
// this box can put a key in front of the operator, and cannot get it any
// further than this machine.

// DefaultLocalKeyLimit caps how many keys programs may park at once.
//
// A hostile local process can call Add in a loop, and the session column makes
// a flood legible without making it bounded. Sixty-four is more than any
// working machine's tools park between them and small enough that a loop
// hits it at once rather than after the heap has grown interesting.
const DefaultLocalKeyLimit = 64

// ErrLocalKeysFull is returned by Add at the limit.
var ErrLocalKeysFull = errors.New("ladulas: the agent holds as many parked keys as it will take")

// ErrNoSuchLocalKey is returned when a key named for forgetting or promotion
// is not parked here.
var ErrNoSuchLocalKey = errors.New("ladulas: no such parked key")

// ErrAmbiguousLocalKey is returned when a label names parked keys that are
// not the same key — promotion has to know which private half to keep.
var ErrAmbiguousLocalKey = errors.New("ladulas: the label names more than one parked key")

// LocalKeyEventKind is what happened to a parked key.
type LocalKeyEventKind int

const (
	// LocalKeyAdded is a key arriving through Add, or one already parked being
	// replaced by a fresh copy with new constraints.
	LocalKeyAdded LocalKeyEventKind = iota
	// LocalKeyExpired is a lifetime running out.
	LocalKeyExpired
	// LocalKeyForgotten is a removal: through the agent's Remove or RemoveAll,
	// through the management surface, or with the seal.
	LocalKeyForgotten
	// LocalKeyPromoted is a key leaving the parked set for the store.
	LocalKeyPromoted
)

// String is the word the audit log uses.
func (k LocalKeyEventKind) String() string {
	switch k {
	case LocalKeyAdded:
		return "added"
	case LocalKeyExpired:
		return "expired"
	case LocalKeyForgotten:
		return "forgotten"
	case LocalKeyPromoted:
		return "promoted"
	default:
		return "unknown"
	}
}

// LocalKeyEvent is a change to the parked set, for the audit log.
type LocalKeyEvent struct {
	Kind LocalKeyEventKind
	Key  *ladulasv1.LocalKeyInfo
	// By is the process that caused it, when one did: the adder on an add, the
	// remover on a removal through the agent socket. Nil for an expiry, for a
	// seal, and for a verb on the control socket.
	By *ladulasv1.ClientProcess
	// Reason is the sentence the log line carries.
	Reason string
}

// LocalKeysOptions configures the parked set.
type LocalKeysOptions struct {
	// Limit caps the set. Zero means DefaultLocalKeyLimit.
	Limit int
	// Accept says whether an add may be taken right now, with the reason it may
	// not as the error. Nil accepts everything; the instance answers with the
	// sealed state, because a sealed machine holds nothing usable and a key
	// parked in one would make that false.
	Accept func() error
	// OnEvent is told about every change. Optional.
	OnEvent func(LocalKeyEvent)
	// Now is the clock, for tests.
	Now func() time.Time
}

// LocalKeys is the parked set: what programs have put in the agent, held in
// memory and nowhere else.
type LocalKeys struct {
	opts LocalKeysOptions

	mu   sync.Mutex
	keys []*localKey
}

type localKey struct {
	info    *ladulasv1.LocalKeyInfo
	ref     *ladulasv1.KeyRef
	signer  ssh.Signer
	private crypto.PrivateKey
	timer   *time.Timer
}

// NewLocalKeys creates an empty parked set.
func NewLocalKeys(opts LocalKeysOptions) *LocalKeys {
	if opts.Limit <= 0 {
		opts.Limit = DefaultLocalKeyLimit
	}

	if opts.Now == nil {
		opts.Now = time.Now
	}

	return &LocalKeys{opts: opts}
}

// Add parks a key, honouring the constraints it came with.
//
// A lifetime constraint sets an expiry, and so does the certificate the key was
// parked with: a certificate past its ValidBefore signs nothing anybody will
// accept, so dropping it then is keeping the promise rather than breaking one.
// The earlier of the two wins. The confirm constraint — `ssh-add -c` — is kept
// on the key and read by the approval engine, which turns it into the full
// prompt for every use; it is the one case in the design where a third-party
// tool asks for exactly what this project does.
//
// A key already parked is replaced, which is what ssh-agent does with a
// second add of the same key: the new constraints are the ones the adder
// means now.
func (l *LocalKeys) Add(added sshagent.AddedKey, by *ladulasv1.ClientProcess) error {
	if l.opts.Accept != nil {
		if err := l.opts.Accept(); err != nil {
			return err
		}
	}

	entry, err := l.entry(added, by)
	if err != nil {
		return err
	}

	l.mu.Lock()

	expired := l.pruneLocked()

	reason := "parked through the agent"

	if i := l.indexOfBlobLocked(entry.ref.GetPublicKey()); i >= 0 {
		l.dropLocked(i)

		reason = "parked through the agent again, replacing the earlier copy"
	} else if len(l.keys) >= l.opts.Limit {
		l.mu.Unlock()

		l.emitExpired(expired)
		wipePrivate(entry.private)

		return ErrLocalKeysFull
	}

	if expires := entry.info.GetExpiresAt(); expires != nil {
		fingerprint := entry.info.GetFingerprint()
		wait := expires.AsTime().Sub(l.opts.Now())

		entry.timer = time.AfterFunc(wait, func() {
			l.expire(fingerprint)
		})
	}

	l.keys = append(l.keys, entry)

	l.mu.Unlock()

	l.emitExpired(expired)
	l.emit(LocalKeyEvent{
		Kind:   LocalKeyAdded,
		Key:    proto.CloneOf(entry.info),
		By:     by,
		Reason: reason,
	})

	return nil
}

// entry builds the parked entry for an added key, without touching the set.
func (l *LocalKeys) entry(
	added sshagent.AddedKey, by *ladulasv1.ClientProcess,
) (*localKey, error) {
	signer, err := ssh.NewSignerFromKey(added.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("ladulas: the key cannot be parked: %w", err)
	}

	keyPub := signer.PublicKey()
	now := l.opts.Now()

	info := &ladulasv1.LocalKeyInfo{
		Label:          added.Comment,
		Algorithm:      keyPub.Type(),
		KeyFingerprint: ssh.FingerprintSHA256(keyPub),
		AddedBy:        by,
		AddedAt:        timestamppb.New(now),
		Confirm:        added.ConfirmBeforeUse,
	}

	var expires time.Time

	if added.LifetimeSecs > 0 {
		expires = now.Add(time.Duration(added.LifetimeSecs) * time.Second)
	}

	if cert := added.Certificate; cert != nil {
		signer, err = ssh.NewCertSigner(cert, signer)
		if err != nil {
			return nil, fmt.Errorf("ladulas: the certificate cannot be parked: %w", err)
		}

		info.Certificate = true

		if cert.ValidBefore != ssh.CertTimeInfinity && cert.ValidBefore > 0 {
			// The cast is safe: a ValidBefore that does not fit int64 is one
			// past the year 292 billion, and CertTimeInfinity is excluded above.
			validBefore := time.Unix(int64(cert.ValidBefore), 0) //nolint:gosec // see above

			if expires.IsZero() || validBefore.Before(expires) {
				expires = validBefore
			}
		}
	}

	listed := signer.PublicKey()

	info.Fingerprint = ssh.FingerprintSHA256(listed)
	info.PublicKey = listed.Marshal()

	if !expires.IsZero() {
		info.ExpiresAt = timestamppb.New(expires)
	}

	return &localKey{
		info: info,
		ref: &ladulasv1.KeyRef{
			Fingerprint: info.GetFingerprint(),
			Algorithm:   listed.Type(),
			PublicKey:   info.GetPublicKey(),
			Comment:     added.Comment,
			Label:       added.Comment,
		},
		signer:  signer,
		private: added.PrivateKey,
	}, nil
}

// Remove drops the key with this blob, if it is parked. It reports whether it
// was.
func (l *LocalKeys) Remove(blob []byte, by *ladulasv1.ClientProcess) bool {
	l.mu.Lock()

	expired := l.pruneLocked()

	i := l.indexOfBlobLocked(blob)
	if i < 0 {
		l.mu.Unlock()

		l.emitExpired(expired)

		return false
	}

	dropped := l.dropLocked(i)

	l.mu.Unlock()

	l.emitExpired(expired)
	l.emit(LocalKeyEvent{
		Kind:   LocalKeyForgotten,
		Key:    dropped,
		By:     by,
		Reason: "removed through the agent",
	})

	return true
}

// RemoveAll drops every parked key, and says how many there were.
func (l *LocalKeys) RemoveAll(by *ladulasv1.ClientProcess) int {
	return l.dropAll(by, "removed through the agent")
}

// Wipe drops every parked key for a reason that is not a program asking:
// the store being sealed.
func (l *LocalKeys) Wipe(reason string) int {
	return l.dropAll(nil, reason)
}

func (l *LocalKeys) dropAll(by *ladulasv1.ClientProcess, reason string) int {
	l.mu.Lock()

	expired := l.pruneLocked()

	dropped := make([]*ladulasv1.LocalKeyInfo, 0, len(l.keys))

	for len(l.keys) > 0 {
		dropped = append(dropped, l.dropLocked(len(l.keys)-1))
	}

	l.mu.Unlock()

	l.emitExpired(expired)

	for _, info := range dropped {
		l.emit(LocalKeyEvent{
			Kind:   LocalKeyForgotten,
			Key:    info,
			By:     by,
			Reason: reason,
		})
	}

	return len(dropped)
}

// Forget drops the parked keys a label or fingerprint names, and returns
// them.
//
// A label can name more than one, and usually does: tsh parks the certificate
// and the bare key under the same comment, and to the person they are one
// credential. Forgetting by label drops all of them.
func (l *LocalKeys) Forget(ref string) ([]*ladulasv1.LocalKeyInfo, error) {
	l.mu.Lock()

	expired := l.pruneLocked()

	matched := l.matchLocked(ref)
	if len(matched) == 0 {
		l.mu.Unlock()

		l.emitExpired(expired)

		return nil, fmt.Errorf("%w: %s", ErrNoSuchLocalKey, ref)
	}

	dropped := make([]*ladulasv1.LocalKeyInfo, 0, len(matched))

	// Highest index first, so that dropping one does not move the next.
	for j := len(matched) - 1; j >= 0; j-- {
		dropped = append(dropped, l.dropLocked(matched[j]))
	}

	l.mu.Unlock()

	l.emitExpired(expired)

	for _, info := range dropped {
		l.emit(LocalKeyEvent{
			Kind:   LocalKeyForgotten,
			Key:    info,
			Reason: "forgotten",
		})
	}

	return dropped, nil
}

// Take removes the parked keys a label or fingerprint names and hands back
// the private half they share, for promotion into the store.
//
// Every entry the name matches must be the same key — a certificate and the
// bare key it is over are — or there is nothing to promote and the caller is
// told to name a fingerprint. Whether any of them carried a certificate is
// reported, because promotion drops it and the surfaces say so.
func (l *LocalKeys) Take(ref string) (crypto.PrivateKey, []*ladulasv1.LocalKeyInfo, error) {
	l.mu.Lock()

	expired := l.pruneLocked()

	matched := l.matchLocked(ref)
	if len(matched) == 0 {
		l.mu.Unlock()

		l.emitExpired(expired)

		return nil, nil, fmt.Errorf("%w: %s", ErrNoSuchLocalKey, ref)
	}

	keyFingerprint := l.keys[matched[0]].info.GetKeyFingerprint()

	for _, i := range matched[1:] {
		if l.keys[i].info.GetKeyFingerprint() != keyFingerprint {
			l.mu.Unlock()

			l.emitExpired(expired)

			return nil, nil, fmt.Errorf("%w: %s", ErrAmbiguousLocalKey, ref)
		}
	}

	// The bare key and its certificate share one private half, so any of the
	// entries can supply it; the others are dropped with it, since a parked
	// certificate over a key the store now holds would be the same key listed
	// twice.
	for i := range l.keys {
		if l.keys[i].info.GetKeyFingerprint() == keyFingerprint {
			matched = appendIndex(matched, i)
		}
	}

	private := l.keys[matched[0]].private

	taken := make([]*ladulasv1.LocalKeyInfo, 0, len(matched))

	for j := len(matched) - 1; j >= 0; j-- {
		entry := l.keys[matched[j]]

		// Dropped without wiping: the private half is what the caller is
		// taking, and it is the same object behind every entry.
		if entry.timer != nil {
			entry.timer.Stop()
		}

		taken = append(taken, entry.info)

		l.keys = append(l.keys[:matched[j]], l.keys[matched[j]+1:]...)
	}

	l.mu.Unlock()

	l.emitExpired(expired)

	for _, info := range taken {
		l.emit(LocalKeyEvent{
			Kind:   LocalKeyPromoted,
			Key:    info,
			Reason: "promoted into the store",
		})
	}

	return private, taken, nil
}

func appendIndex(indexes []int, i int) []int {
	for _, have := range indexes {
		if have == i {
			return indexes
		}
	}

	indexes = append(indexes, i)

	// Kept sorted, so that the highest-first drop above stays right.
	for j := len(indexes) - 1; j > 0 && indexes[j] < indexes[j-1]; j-- {
		indexes[j], indexes[j-1] = indexes[j-1], indexes[j]
	}

	return indexes
}

// List reports every parked key, oldest first.
func (l *LocalKeys) List() []*ladulasv1.LocalKeyInfo {
	l.mu.Lock()

	expired := l.pruneLocked()

	out := make([]*ladulasv1.LocalKeyInfo, 0, len(l.keys))

	for _, entry := range l.keys {
		out = append(out, proto.CloneOf(entry.info))
	}

	l.mu.Unlock()

	l.emitExpired(expired)

	return out
}

// Len is how many keys are parked.
func (l *LocalKeys) Len() int {
	l.mu.Lock()

	expired := l.pruneLocked()
	n := len(l.keys)

	l.mu.Unlock()

	l.emitExpired(expired)

	return n
}

// Refs is the parked keys as the agent lists them.
func (l *LocalKeys) Refs() []*ladulasv1.KeyRef {
	l.mu.Lock()

	expired := l.pruneLocked()

	out := make([]*ladulasv1.KeyRef, 0, len(l.keys))

	for _, entry := range l.keys {
		out = append(out, proto.CloneOf(entry.ref))
	}

	l.mu.Unlock()

	l.emitExpired(expired)

	return out
}

// Has says whether a label or fingerprint names a parked key, for a
// management verb that wants to say "that is a parked key" rather than "no
// such key".
func (l *LocalKeys) Has(ref string) bool {
	l.mu.Lock()

	expired := l.pruneLocked()
	has := len(l.matchLocked(ref)) > 0

	l.mu.Unlock()

	l.emitExpired(expired)

	return has
}

// lookup finds a parked key by blob: the signer to use, the reference to put
// on the request, and what the request should say about the key.
func (l *LocalKeys) lookup(
	blob []byte,
) (ssh.Signer, *ladulasv1.KeyRef, *ladulasv1.LocalKey, bool) {
	l.mu.Lock()

	expired := l.pruneLocked()

	i := l.indexOfBlobLocked(blob)
	if i < 0 {
		l.mu.Unlock()

		l.emitExpired(expired)

		return nil, nil, nil, false
	}

	entry := l.keys[i]

	signer, ref := entry.signer, proto.CloneOf(entry.ref)
	note := &ladulasv1.LocalKey{
		AddedBy:   entry.info.GetAddedBy(),
		AddedAt:   entry.info.GetAddedAt(),
		ExpiresAt: entry.info.GetExpiresAt(),
		Confirm:   entry.info.GetConfirm(),
	}

	l.mu.Unlock()

	l.emitExpired(expired)

	return signer, ref, note, true
}

// expire is the timer's end: the key is dropped if it is still the same one.
func (l *LocalKeys) expire(fingerprint string) {
	l.mu.Lock()

	var dropped []*ladulasv1.LocalKeyInfo

	for i, entry := range l.keys {
		if entry.info.GetFingerprint() == fingerprint && l.expiredLocked(entry) {
			dropped = append(dropped, l.dropLocked(i))

			break
		}
	}

	l.mu.Unlock()

	l.emitExpired(dropped)
}

// pruneLocked drops what has expired, for the reader that got there before
// the timer did, and returns it so that the caller can report the expiry once
// the lock is released. A timer that fires afterwards finds nothing and says
// nothing, so each expiry is reported exactly once.
func (l *LocalKeys) pruneLocked() []*ladulasv1.LocalKeyInfo {
	var dropped []*ladulasv1.LocalKeyInfo

	for i := len(l.keys) - 1; i >= 0; i-- {
		if l.expiredLocked(l.keys[i]) {
			dropped = append(dropped, l.dropLocked(i))
		}
	}

	return dropped
}

// emitExpired reports what pruneLocked dropped.
func (l *LocalKeys) emitExpired(dropped []*ladulasv1.LocalKeyInfo) {
	for _, info := range dropped {
		l.emit(LocalKeyEvent{
			Kind:   LocalKeyExpired,
			Key:    info,
			Reason: "the lifetime it was parked with ran out",
		})
	}
}

func (l *LocalKeys) expiredLocked(entry *localKey) bool {
	expires := entry.info.GetExpiresAt()

	return expires != nil && !l.opts.Now().Before(expires.AsTime())
}

func (l *LocalKeys) indexOfBlobLocked(blob []byte) int {
	for i, entry := range l.keys {
		if string(entry.info.GetPublicKey()) == string(blob) {
			return i
		}
	}

	return -1
}

// matchLocked is every parked key a label or fingerprint names, in order.
// Either fingerprint matches — the listed one and the underlying key's — so
// that a certificate can be named by the key it is over.
func (l *LocalKeys) matchLocked(ref string) []int {
	var out []int

	for i, entry := range l.keys {
		info := entry.info

		if info.GetFingerprint() == ref || info.GetKeyFingerprint() == ref ||
			(info.GetLabel() != "" && strings.EqualFold(info.GetLabel(), ref)) {
			out = append(out, i)
		}
	}

	return out
}

// dropLocked removes the entry at i, stops its timer and wipes what it can of
// the private half. It returns the entry's description for the event.
func (l *LocalKeys) dropLocked(i int) *ladulasv1.LocalKeyInfo {
	entry := l.keys[i]

	if entry.timer != nil {
		entry.timer.Stop()
	}

	wipePrivate(entry.private)

	l.keys = append(l.keys[:i], l.keys[i+1:]...)

	return entry.info
}

func (l *LocalKeys) emit(event LocalKeyEvent) {
	if l.opts.OnEvent != nil {
		l.opts.OnEvent(event)
	}
}

// wipePrivate zeroes the private material where the type lets it. Best effort,
// as the store's own Wipe is: an ed25519 key is a byte slice and can be
// cleared; an RSA or ECDSA key is big integers the garbage collector will get
// to, and there is no honest way to reach into them.
func wipePrivate(private crypto.PrivateKey) {
	switch key := private.(type) {
	case ed25519.PrivateKey:
		keystore.Wipe(key)
	case *ed25519.PrivateKey:
		if key != nil {
			keystore.Wipe(*key)
		}
	}
}

// LocalKeyDescription is the sentence a log line or a listing uses for a
// parked key: its label, who parked it, and when it goes.
func LocalKeyDescription(info *ladulasv1.LocalKeyInfo) string {
	label := info.GetLabel()
	if label == "" {
		label = info.GetFingerprint()
	}

	if info.GetCertificate() {
		label += " (certificate)"
	}

	parts := []string{label}

	if by := info.GetAddedBy(); by != nil && by.GetExecutable() != "" {
		parts = append(parts, "parked by "+by.GetExecutable())
	}

	if expires := info.GetExpiresAt(); expires != nil {
		parts = append(parts, "expires "+expires.AsTime().Local().Format(time.RFC1123))
	}

	if info.GetConfirm() {
		parts = append(parts, "confirm each use")
	}

	return strings.Join(parts, ", ")
}
