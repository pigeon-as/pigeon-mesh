package mesh

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"slices"

	"github.com/hashicorp/memberlist"
)

func containsKey(set [][]byte, k []byte) bool {
	return slices.ContainsFunc(set, func(x []byte) bool { return bytes.Equal(x, k) })
}

func LoadKeyring(path string) (*memberlist.Keyring, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read keyring %q: %w", path, err)
	}
	var encoded []string
	if err := json.Unmarshal(raw, &encoded); err != nil {
		return nil, fmt.Errorf("decode keyring %q: %w", path, err)
	}
	if len(encoded) == 0 {
		return nil, fmt.Errorf("keyring %q has no keys", path)
	}
	keys := make([][]byte, 0, len(encoded))
	for i, s := range encoded {
		key, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("keyring %q key[%d]: %w", path, i, err)
		}
		if err := memberlist.ValidateKey(key); err != nil {
			return nil, fmt.Errorf("keyring %q key[%d]: %w", path, i, err)
		}
		keys = append(keys, key)
	}
	return memberlist.NewKeyring(keys[1:], keys[0])
}
