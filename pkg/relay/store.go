package relay

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// The registrations, which are the whole of the relay's state.
//
// A file rather than a database, because the shape is a map of a few hundred
// bytes per device and the write rate is "when a token changes". What matters
// about the arrangement is that it is replaceable: a deployment that wants
// Postgres implements Store and changes one line in main.

// MemoryStore keeps registrations in memory. It is what a test uses, and what a
// relay that would rather re-register every device after a restart can use —
// which is not as bad as it sounds, since a device re-registers whenever its
// token changes and on every launch that finds an unregistered one.
type MemoryStore struct {
	mu      sync.RWMutex
	devices map[string]*Device
}

var _ Store = (*MemoryStore)(nil)

// NewMemoryStore builds an empty one.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{devices: map[string]*Device{}}
}

// Device implements Store.
func (m *MemoryStore) Device(instanceID string) (*Device, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	device, ok := m.devices[instanceID]
	if !ok {
		return nil, false
	}

	copied := *device

	return &copied, true
}

// Put implements Store.
func (m *MemoryStore) Put(device *Device) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	copied := *device
	m.devices[device.InstanceID] = &copied

	return nil
}

// Len is how many devices are registered, which is the one number about this
// file worth watching: it only ever goes up by somebody installing the app, and
// down by a token the platform declared dead.
func (m *MemoryStore) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return len(m.devices)
}

// Drop implements Store.
func (m *MemoryStore) Drop(instanceID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.devices, instanceID)

	return nil
}

// FileStore is a MemoryStore that writes itself out.
//
// The whole file is rewritten on every change, which is fine at this size and
// is one fewer thing to get wrong than a log with a compaction step. The write
// is to a temporary file and a rename, so a relay killed mid-write comes back
// with the previous set rather than with half of this one.
type FileStore struct {
	path string

	mu      sync.RWMutex
	devices map[string]*Device
}

var _ Store = (*FileStore)(nil)

// OpenFileStore reads what is there, and starts empty when nothing is.
func OpenFileStore(path string) (*FileStore, error) {
	store := &FileStore{path: path, devices: map[string]*Device{}}

	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}

	if err != nil {
		return nil, fmt.Errorf("read the device registrations: %w", err)
	}

	var devices []*Device

	if err := json.Unmarshal(body, &devices); err != nil {
		return nil, fmt.Errorf("parse the device registrations: %w", err)
	}

	for _, device := range devices {
		store.devices[device.InstanceID] = device
	}

	return store, nil
}

// Device implements Store.
func (f *FileStore) Device(instanceID string) (*Device, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	device, ok := f.devices[instanceID]
	if !ok {
		return nil, false
	}

	copied := *device

	return &copied, true
}

// Put implements Store.
func (f *FileStore) Put(device *Device) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	copied := *device
	f.devices[device.InstanceID] = &copied

	return f.save()
}

// Len is how many devices are registered. See MemoryStore.Len.
func (f *FileStore) Len() int {
	f.mu.RLock()
	defer f.mu.RUnlock()

	return len(f.devices)
}

// Drop implements Store.
func (f *FileStore) Drop(instanceID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if _, ok := f.devices[instanceID]; !ok {
		return nil
	}

	delete(f.devices, instanceID)

	return f.save()
}

// save rewrites the file. Callers hold the lock.
func (f *FileStore) save() error {
	devices := make([]*Device, 0, len(f.devices))
	for _, device := range f.devices {
		devices = append(devices, device)
	}

	body, err := json.MarshalIndent(devices, "", "  ")
	if err != nil {
		return fmt.Errorf("encode the device registrations: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(f.path), 0o700); err != nil {
		return fmt.Errorf("create the registration directory: %w", err)
	}

	temporary := f.path + ".new"

	// Device tokens are not secrets in the sense a key is, but they are the
	// whole of what this file holds and there is no reason for anybody else on
	// the host to read them.
	if err := os.WriteFile(temporary, body, 0o600); err != nil {
		return fmt.Errorf("write the device registrations: %w", err)
	}

	if err := os.Rename(temporary, f.path); err != nil {
		return fmt.Errorf("replace the device registrations: %w", err)
	}

	return nil
}
