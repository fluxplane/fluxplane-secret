package secret

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestFileStoreSavesLoadsAndResolvesSecret(t *testing.T) {
	store := NewFileStore(t.TempDir())
	ref := Plugin("jira", "main", "api_key")
	if err := store.SaveSecret(context.Background(), StoredSecret{Ref: ref, Kind: KindAPIKey, Value: "api-key", Metadata: map[string]string{"source": "test"}}); err != nil {
		t.Fatalf("SaveSecret: %v", err)
	}
	stored, ok, err := store.LoadSecret(context.Background(), ref)
	if err != nil || !ok {
		t.Fatalf("LoadSecret = %#v, %v, %v; want stored", stored, ok, err)
	}
	if stored.Ref.ResourceName() != ref.ResourceName() || stored.Kind != KindAPIKey || stored.Value != "api-key" {
		t.Fatalf("stored = %#v", stored)
	}
	material, ok, err := store.ResolveSecret(context.Background(), ref)
	if err != nil || !ok {
		t.Fatalf("ResolveSecret = %#v, %v, %v; want material", material, ok, err)
	}
	if material.Ref.ResourceName() != ref.ResourceName() || material.Kind != KindAPIKey || string(material.Value) != "api-key" {
		t.Fatalf("material = %#v", material)
	}
}

func TestFileStoreSaveLeavesNoTempFile(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	ref := Plugin("jira", "main", "api_key")
	for i := 0; i < 5; i++ {
		if err := store.SaveSecret(context.Background(), StoredSecret{Ref: ref, Value: "api-key"}); err != nil {
			t.Fatalf("SaveSecret iter %d: %v", i, err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".tmp-") {
			t.Fatalf("leaked tmp file %q after SaveSecret", entry.Name())
		}
	}
}

func TestFileStoreHasPluginSecrets(t *testing.T) {
	store := NewFileStore(t.TempDir())
	if ok, err := store.HasPluginSecrets("jira", "main"); err != nil || ok {
		t.Fatalf("empty HasPluginSecrets = %v, %v", ok, err)
	}
	if err := store.SaveSecret(context.Background(), StoredSecret{Ref: Plugin("jira", "main", "api_key"), Value: "api-key"}); err != nil {
		t.Fatal(err)
	}
	if ok, err := store.HasPluginSecrets("jira", "main"); err != nil || !ok {
		t.Fatalf("HasPluginSecrets = %v, %v", ok, err)
	}
}
