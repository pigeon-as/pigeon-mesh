package mesh

import (
	"fmt"
	"strings"
)

type Tags map[string]string

func ParseTags(kvs []string) (Tags, error) {
	if len(kvs) == 0 {
		return nil, nil
	}
	out := make(Tags, len(kvs))
	for _, kv := range kvs {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("invalid tag: %q", kv)
		}
		out[k] = v
	}
	return out, nil
}
