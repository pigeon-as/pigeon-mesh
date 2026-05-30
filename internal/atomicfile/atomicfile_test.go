package atomicfile

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/shoenig/test/must"
)

func TestWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "test.txt")

	must.NoError(t, Write(path, []byte("hello"), 0o600))

	data, err := os.ReadFile(path)
	must.NoError(t, err)
	must.EqOp(t, "hello", string(data))

	info, err := os.Stat(path)
	must.NoError(t, err)
	if runtime.GOOS != "windows" {
		must.EqOp(t, os.FileMode(0o600), info.Mode().Perm())
	}
}

func TestWriteOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")

	must.NoError(t, Write(path, []byte("first"), 0o644))
	must.NoError(t, Write(path, []byte("second"), 0o600))

	data, err := os.ReadFile(path)
	must.NoError(t, err)
	must.EqOp(t, "second", string(data))
}

func TestWriteNoTempLeftOnSuccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")

	must.NoError(t, Write(path, []byte("ok"), 0o600))

	entries, err := os.ReadDir(dir)
	must.NoError(t, err)
	must.SliceLen(t, 1, entries)
}
