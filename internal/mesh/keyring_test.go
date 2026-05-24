package mesh

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/shoenig/test/must"
)

func TestLoadKeyring_Single(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	path := filepath.Join(t.TempDir(), "keys.json")
	must.NoError(t, os.WriteFile(path, []byte(`["`+key+`"]`), 0o600))
	kr, err := LoadKeyring(path)
	must.NoError(t, err)
	must.SliceLen(t, 1, kr.GetKeys())
}

func TestLoadKeyring_Multiple(t *testing.T) {
	a := base64.StdEncoding.EncodeToString(make([]byte, 32))
	b := base64.StdEncoding.EncodeToString(append(make([]byte, 31), 1))
	path := filepath.Join(t.TempDir(), "keys.json")
	must.NoError(t, os.WriteFile(path, []byte(`["`+a+`","`+b+`"]`), 0o600))
	kr, err := LoadKeyring(path)
	must.NoError(t, err)
	must.SliceLen(t, 2, kr.GetKeys())
}

func TestLoadKeyring_MissingFile(t *testing.T) {
	_, err := LoadKeyring(filepath.Join(t.TempDir(), "nonexistent.json"))
	must.ErrorContains(t, err, "read keyring")
}

func TestLoadKeyring_MalformedJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	must.NoError(t, os.WriteFile(path, []byte(`not json`), 0o600))
	_, err := LoadKeyring(path)
	must.ErrorContains(t, err, "decode keyring")
}

func TestLoadKeyring_Empty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	must.NoError(t, os.WriteFile(path, []byte(`[]`), 0o600))
	_, err := LoadKeyring(path)
	must.ErrorContains(t, err, "no keys")
}

func TestLoadKeyring_BadBase64(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	must.NoError(t, os.WriteFile(path, []byte(`["@@@not-base64@@@"]`), 0o600))
	_, err := LoadKeyring(path)
	must.ErrorContains(t, err, "base64")
}

func TestLoadKeyring_WrongKeyLength(t *testing.T) {
	short := base64.StdEncoding.EncodeToString(make([]byte, 8))
	path := filepath.Join(t.TempDir(), "keys.json")
	must.NoError(t, os.WriteFile(path, []byte(`["`+short+`"]`), 0o600))
	_, err := LoadKeyring(path)
	must.ErrorContains(t, err, "key size")
}
