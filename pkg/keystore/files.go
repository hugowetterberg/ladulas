package keystore

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// writeFileAtomic writes through a temporary file in the same directory and
// renames it into place, so a crash mid-write cannot leave a half-encrypted
// store behind.
func writeFileAtomic(path string, mode os.FileMode, write func(io.Writer) error) (outErr error) {
	dir := filepath.Dir(path)

	f, err := os.CreateTemp(dir, filepath.Base(path)+".tmp")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}

	tmp := f.Name()

	defer func() {
		if outErr != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()

	if err := f.Chmod(mode); err != nil {
		return fmt.Errorf("set file mode: %w", err)
	}

	if err := write(f); err != nil {
		return err
	}

	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync: %w", err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("close: %w", err)
	}

	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename into place: %w", err)
	}

	return nil
}
