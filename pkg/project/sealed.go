package project

import (
	"fmt"
	"os"
	"path/filepath"

	"google.golang.org/protobuf/proto"
)

// The on-disk mechanics the two project stores share: a sealed protobuf record
// naming what is held, and content-addressed sealed blobs holding it.
//
// There are two stores because there are two questions. The approver's Cache
// holds pages it has read of other machines' projects; the publisher's
// VersionStore holds working-tree states of its own. They keep different things
// for different reasons and neither is the other's mirror — but the way bytes
// reach the disk is the same, and it is the part with the cipher in it, so it is
// written once.
//
// Free functions rather than a type to embed, because the two stores lock
// differently: Cache serialises a project directory's read-modify-write, and
// the version store serialises a document's. A shared type with a mutex in it
// would invite one to take the other's.

func sealMessage(cipher Cipher, path string, msg proto.Message) error {
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(msg)
	if err != nil {
		return fmt.Errorf("project: serialize: %w", err)
	}

	sealed, err := cipher.Seal(body)
	if err != nil {
		return fmt.Errorf("project: encrypt: %w", err)
	}

	if err := os.WriteFile(path, sealed, 0o600); err != nil {
		return fmt.Errorf("project: write %s: %w", path, err)
	}

	return nil
}

// unsealMessage reads a record into msg. A missing file is reported as
// os.ErrNotExist unwrapped, because both callers match on it to mean "nothing
// has been kept here yet", which is not a failure at either of them.
func unsealMessage(cipher Cipher, path string, msg proto.Message) error {
	sealed, err := os.ReadFile(path) //nolint:gosec // a path built from a checked key
	if err != nil {
		return err //nolint:wrapcheck // the callers match on os.ErrNotExist
	}

	body, err := cipher.Unseal(sealed)
	if err != nil {
		return fmt.Errorf("project: decrypt %s: %w", path, err)
	}

	if err := proto.Unmarshal(body, msg); err != nil {
		return fmt.Errorf("project: parse %s: %w", path, err)
	}

	return nil
}

func sealBlob(cipher Cipher, dir string, digest, content []byte) error {
	sealed, err := cipher.Seal(content)
	if err != nil {
		return fmt.Errorf("project: encrypt a page: %w", err)
	}

	path := blobPath(dir, digest)

	if err := os.WriteFile(path, sealed, 0o600); err != nil {
		return fmt.Errorf("project: write %s: %w", path, err)
	}

	return nil
}

func unsealBlob(cipher Cipher, dir string, digest []byte) ([]byte, error) {
	sealed, err := os.ReadFile(blobPath(dir, digest)) //nolint:gosec // a path built from a digest
	if err != nil {
		return nil, err //nolint:wrapcheck // the callers match on os.ErrNotExist
	}

	body, err := cipher.Unseal(sealed)
	if err != nil {
		return nil, fmt.Errorf("project: decrypt a page: %w", err)
	}

	return body, nil
}

// blobPath is where one blob lives. The digest is hex so that the name says
// nothing a directory listing should not, and both stores put blobs in a
// "blobs" subdirectory so that the record beside them is never mistaken for
// one.
func blobPath(dir string, digest []byte) string {
	return filepath.Join(dir, "blobs", fmt.Sprintf("%x", digest))
}
