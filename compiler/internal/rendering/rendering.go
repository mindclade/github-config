// Package rendering provides deterministic, redacted JSON output.
package rendering

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const maxOutputBytes = 128 << 20

var (
	sensitiveKey = regexp.MustCompile(`(?i)(^|_)(access[_-]?token|authorization|client[_-]?secret|credential|password|private[_-]?key|secret|token)($|_)`)
	secretValue  = regexp.MustCompile(`(?i)(-----BEGIN [A-Z ]*PRIVATE KEY-----|github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{30,}|AKIA[0-9A-Z]{16})`)
)

// CanonicalJSON returns stable JSON: map keys are lexically ordered by the Go
// encoder, HTML escaping is disabled, and a final newline is always present.
func CanonicalJSON(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return nil, fmt.Errorf("encode canonical JSON: %w", err)
	}
	if buffer.Len() > maxOutputBytes {
		return nil, fmt.Errorf("canonical output exceeds %d bytes", maxOutputBytes)
	}
	return buffer.Bytes(), nil
}

// Digest returns the repository-wide digest representation.
func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// WriteJSON atomically writes canonical JSON. A path of "-" writes to stdout.
// Existing symlink targets are rejected to keep privileged workflow output local.
func WriteJSON(path string, value any, stdout io.Writer) error {
	data, err := CanonicalJSON(value)
	if err != nil {
		return err
	}
	if path == "-" {
		_, err = stdout.Write(data)
		return err
	}
	if path == "" {
		return errors.New("output path must not be empty")
	}
	clean := filepath.Clean(path)
	if info, statErr := os.Lstat(clean); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to replace symlink output %q", clean)
	} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return fmt.Errorf("inspect output %q: %w", clean, statErr)
	}
	directory := filepath.Dir(clean)
	if mkdirErr := os.MkdirAll(directory, 0o750); mkdirErr != nil {
		return fmt.Errorf("create output directory: %w", mkdirErr)
	}
	temporary, err := os.CreateTemp(directory, ".github-configctl-*")
	if err != nil {
		return fmt.Errorf("create temporary output: %w", err)
	}
	temporaryName := temporary.Name()
	defer func() { _ = os.Remove(temporaryName) }()
	// Catalogs, observations, and preflight reports contain organization
	// identities and access topology. Keep every file output private regardless
	// of the caller's umask; workflows can deliberately copy a redacted artifact
	// to a broader mode when policy permits.
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("set output permissions: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write output: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync output: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close output: %w", err)
	}
	if err := os.Rename(temporaryName, clean); err != nil {
		return fmt.Errorf("install output: %w", err)
	}
	return nil
}

// Redact recursively removes common credential fields and credential-shaped
// strings. It never mutates its input.
func Redact(value any) any {
	switch current := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(current))
		keys := make([]string, 0, len(current))
		for key := range current {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if isSensitiveKey(key) {
				result[key] = "[REDACTED]"
				continue
			}
			result[key] = Redact(current[key])
		}
		return result
	case []any:
		result := make([]any, len(current))
		for index, item := range current {
			result[index] = Redact(item)
		}
		return result
	case string:
		if secretValue.MatchString(current) {
			return "[REDACTED]"
		}
		return current
	default:
		return current
	}
}

// HasSecretLikeValue reports inline credentials while allowing references to a
// secret manager resource. The returned path contains no secret value.
func HasSecretLikeValue(value any) (string, bool) {
	return findSecret(value, "")
}

func findSecret(value any, path string) (string, bool) {
	switch current := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(current))
		for key := range current {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			childPath := path + "/" + escapePointer(key)
			normalized := strings.ReplaceAll(strings.ToLower(key), "-", "_")
			if isSensitiveKey(normalized) {
				if text, ok := current[key].(string); ok && text != "" {
					return childPath, true
				}
			}
			if found, ok := findSecret(current[key], childPath); ok {
				return found, true
			}
		}
	case []any:
		for index, item := range current {
			if found, ok := findSecret(item, fmt.Sprintf("%s/%d", path, index)); ok {
				return found, true
			}
		}
	case string:
		if secretValue.MatchString(current) {
			return path, true
		}
	}
	return "", false
}

func isReferenceKey(key string) bool {
	normalized := strings.ReplaceAll(strings.ToLower(key), "-", "_")
	return strings.HasSuffix(normalized, "_ref") ||
		strings.HasSuffix(normalized, "_reference") ||
		strings.HasSuffix(normalized, "_resource") ||
		strings.HasSuffix(normalized, "_name") ||
		strings.HasSuffix(normalized, "_authority") ||
		normalized == "secret_manager"
}

func isSensitiveKey(key string) bool {
	normalized := strings.ReplaceAll(strings.ToLower(key), "-", "_")
	if strings.HasPrefix(normalized, "secret_scanning") {
		return false
	}
	return sensitiveKey.MatchString(normalized) && !isReferenceKey(normalized)
}

func escapePointer(value string) string {
	value = strings.ReplaceAll(value, "~", "~0")
	return strings.ReplaceAll(value, "/", "~1")
}
