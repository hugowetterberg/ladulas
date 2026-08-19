package approval

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"sync"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hugowetterberg/ladulas/pkg/identity"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// AuditLog is the append-only JSONL log (§18): one protojson AuditEntry per
// line, flushed on every write.
//
// Tamper evidence today comes from the approver's signature over each decision,
// which cannot be forged without the identity key. Hash-chaining the log itself
// is deferred; when it lands it will be an added field rather than a new
// format.
type AuditLog struct {
	path string

	mu   sync.Mutex
	file *os.File

	observers struct {
		sync.RWMutex
		fns []func(*ladulasv1.AuditEntry)
	}
}

// OpenAuditLog opens or creates the log.
func OpenAuditLog(path string) (*AuditLog, error) {
	file, err := os.OpenFile(path, //nolint:gosec // the path is configuration
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}

	return &AuditLog{path: path, file: file}, nil
}

// Path returns the log file's path.
func (l *AuditLog) Path() string {
	return l.path
}

// Observe adds a function that is called with every entry after it has been
// written.
//
// It exists so that counting what an instance does does not need a second seam
// in every subsystem that does something. Every request, decision, signature,
// grant and key transfer already passes through here on its way to the log —
// that is what the log is — so a metrics set built on this one hook is
// instrumented wherever the audit trail is, which is everywhere by
// construction.
//
// The function is called on the caller's goroutine, after the write, so an
// observer that blocks holds up whatever was being decided. Metrics do not
// block; anything that might should hand off to a goroutine of its own.
func (l *AuditLog) Observe(fn func(*ladulasv1.AuditEntry)) {
	if l == nil || fn == nil {
		return
	}

	l.observers.Lock()
	defer l.observers.Unlock()

	l.observers.fns = append(l.observers.fns, fn)
}

func (l *AuditLog) notify(entry *ladulasv1.AuditEntry) {
	l.observers.RLock()
	fns := l.observers.fns
	l.observers.RUnlock()

	for _, fn := range fns {
		fn(entry)
	}
}

// Append writes an entry, filling in the identifier and timestamp.
func (l *AuditLog) Append(entry *ladulasv1.AuditEntry) error {
	if l == nil {
		return nil
	}

	if entry.GetEntryId() == "" {
		entry.EntryId = identity.NewRequestID()
	}

	if entry.GetTimestamp() == nil {
		entry.Timestamp = timestamppb.Now()
	}

	// A single line per entry, so the log stays greppable and tailable.
	body, err := protojson.MarshalOptions{Multiline: false}.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal audit entry: %w", err)
	}

	if err := l.write(body); err != nil {
		return err
	}

	// After the write, and outside its lock: an observer counting entries has no
	// business standing between two of them.
	l.notify(entry)

	return nil
}

func (l *AuditLog) write(body []byte) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if _, err := l.file.Write(append(body, '\n')); err != nil {
		return fmt.Errorf("write audit entry: %w", err)
	}

	if err := l.file.Sync(); err != nil {
		return fmt.Errorf("sync audit log: %w", err)
	}

	return nil
}

// Close closes the log file.
func (l *AuditLog) Close() error {
	if l == nil {
		return nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if err := l.file.Close(); err != nil {
		return fmt.Errorf("close audit log: %w", err)
	}

	return nil
}

// maxAuditLine caps how long a single entry may be when reading back. Entries
// carry commit context and binding chains, so the default bufio limit is not
// generous enough.
const maxAuditLine = 4 << 20

// ReadAuditLog reads the last limit entries, newest last. A limit of zero reads
// everything.
func ReadAuditLog(path string, limit int) ([]*ladulasv1.AuditEntry, error) {
	file, err := os.Open(path) //nolint:gosec // the path is configuration
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}

	defer func() {
		_ = file.Close()
	}()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64<<10), maxAuditLine)

	var entries []*ladulasv1.AuditEntry

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var entry ladulasv1.AuditEntry

		if err := protojson.Unmarshal(line, &entry); err != nil {
			return nil, fmt.Errorf("parse audit entry: %w", err)
		}

		entries = append(entries, &entry)

		if limit > 0 && len(entries) > limit {
			entries = entries[1:]
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read audit log: %w", err)
	}

	return entries, nil
}
