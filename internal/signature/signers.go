package signature

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

func ParseSigners(spec string) ([]ed25519.PublicKey, error) {
	if path, ok := strings.CutPrefix(spec, "@"); ok {
		return LoadSigners(path)
	}
	var keys []ed25519.PublicKey
	for _, s := range strings.Split(spec, ",") {
		k, err := parseSignerKey(s)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return nil, errors.New("no signer keys")
	}
	return keys, nil
}

func LoadSigners(path string) ([]ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var keys []ed25519.PublicKey
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, err := parseSignerKey(line)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return nil, errors.New("no signer keys in file")
	}
	return keys, nil
}

func parseSignerKey(s string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("signer key %q: %w", s, err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("signer key %q: want %d bytes, got %d", s, ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

func LoadSignature(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}
	if len(raw) == 0 {
		return nil, errors.New("signature file is empty")
	}
	if _, err := parse(raw); err != nil {
		return nil, err
	}
	return raw, nil
}
