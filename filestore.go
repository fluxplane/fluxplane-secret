package secret

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const DefaultFileStorePath = "~/.fluxplane/auth"

// FileStore stores secrets as one JSON file per logical secret ref.
type FileStore struct {
	Dir string
	Now func() time.Time
}

// NewFileStore returns a JSON-backed secret store.
func NewFileStore(dir string) FileStore {
	if strings.TrimSpace(dir) == "" {
		dir = DefaultFileStorePath
	}
	return FileStore{Dir: expandHome(dir), Now: time.Now}
}

// SaveSecret writes a secret with restrictive permissions.
func (s FileStore) SaveSecret(_ context.Context, stored StoredSecret) error {
	ref := stored.Ref.Normalize()
	if ref.ResourceName() == "" {
		return fmt.Errorf("secret store: ref is empty")
	}
	if strings.TrimSpace(stored.Value) == "" {
		return fmt.Errorf("secret store: value is empty")
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return fmt.Errorf("secret store: create dir: %w", err)
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	stored.Ref = ref
	if stored.Kind == "" {
		stored.Kind = KindBearerToken
	}
	stored.UpdatedAt = now().UTC()
	data, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return fmt.Errorf("secret store: marshal: %w", err)
	}
	if err := writeFileAtomic(s.path(ref), data, 0o600); err != nil {
		return fmt.Errorf("secret store: write: %w", err)
	}
	return nil
}

// LoadSecret reads a stored secret.
func (s FileStore) LoadSecret(_ context.Context, ref Ref) (StoredSecret, bool, error) {
	ref = ref.Normalize()
	data, err := os.ReadFile(s.path(ref))
	if err != nil {
		if os.IsNotExist(err) {
			return StoredSecret{}, false, nil
		}
		return StoredSecret{}, false, fmt.Errorf("secret store: read: %w", err)
	}
	var out StoredSecret
	if err := json.Unmarshal(data, &out); err != nil {
		return StoredSecret{}, false, fmt.Errorf("secret store: parse: %w", err)
	}
	if out.Ref.Empty() {
		out.Ref = ref
	}
	return out, true, nil
}

// ResolveSecret implements Resolver.
func (s FileStore) ResolveSecret(ctx context.Context, ref Ref) (Material, bool, error) {
	stored, ok, err := s.LoadSecret(ctx, ref)
	if err != nil || !ok {
		return Material{}, ok, err
	}
	if strings.TrimSpace(stored.Value) == "" {
		return Material{}, false, nil
	}
	kind := stored.Kind
	if kind == "" {
		kind = KindBearerToken
	}
	return Material{Ref: stored.Ref.Normalize(), Kind: kind, Value: []byte(stored.Value), MediaType: stored.MediaType}, true, nil
}

// HasPluginSecrets reports whether any non-empty plugin secret exists for plugin/instance.
func (s FileStore) HasPluginSecrets(plugin, instance string) (bool, error) {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	plugin = strings.TrimSpace(plugin)
	instance = strings.TrimSpace(instance)
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.Dir, entry.Name()))
		if err != nil {
			return false, err
		}
		var stored StoredSecret
		if err := json.Unmarshal(data, &stored); err != nil {
			return false, err
		}
		ref := stored.Ref.Normalize()
		if ref.Scheme == SchemePlugin && ref.Plugin == plugin && ref.Instance == instance && strings.TrimSpace(stored.Value) != "" {
			return true, nil
		}
	}
	return false, nil
}

func (s FileStore) path(ref Ref) string {
	return filepath.Join(s.Dir, secretFilename(ref))
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-"+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func secretFilename(ref Ref) string {
	name := strings.Trim(ref.Normalize().ResourceName(), "/")
	if name == "" {
		name = "secret"
	}
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String() + ".json"
}

func expandHome(path string) string {
	path = strings.TrimSpace(path)
	if path == "~" || strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			if path == "~" {
				return home
			}
			return filepath.Join(home, strings.TrimPrefix(path, "~/"))
		}
	}
	return path
}
