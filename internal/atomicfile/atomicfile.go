package atomicfile

import (
	"fmt"
	"os"
	"path/filepath"
)

func Write(path string, data []byte, perm os.FileMode) error {
	return WriteOwned(path, data, perm, -1, -1)
}

func WriteOwned(path string, data []byte, perm os.FileMode, uid, gid int) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("atomic write %s: %w", path, err)
	}
	f, err := os.CreateTemp(dir, ".atomic-*")
	if err != nil {
		return fmt.Errorf("atomic write %s: %w", path, err)
	}
	tmpName := f.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("atomic write %s: %w", path, err)
	}
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return fmt.Errorf("atomic write %s: %w", path, err)
	}
	if uid != -1 || gid != -1 {
		if err := f.Chown(uid, gid); err != nil {
			f.Close()
			return fmt.Errorf("atomic write %s: %w", path, err)
		}
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("atomic write %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("atomic write %s: %w", path, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("atomic write %s: %w", path, err)
	}
	committed = true
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
