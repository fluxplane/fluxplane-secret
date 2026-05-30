package secret

import (
	"errors"
	"testing"
)

func TestRefResourceNameAndParseRoundTrip(t *testing.T) {
	tests := []Ref{
		Env("GITHUB_TOKEN"),
		EnvWildcard(),
		Plugin("github", "work", "access_token"),
		Kubernetes("default", "github", "token"),
	}
	for _, ref := range tests {
		resource := ref.ResourceName()
		parsed := ParseRef(resource)
		if parsed != ref.Normalize() {
			t.Fatalf("ParseRef(%q) = %#v, want %#v", resource, parsed, ref.Normalize())
		}
	}
}

func TestEmptyRef(t *testing.T) {
	if !(Ref{}).Empty() {
		t.Fatal("zero ref should be empty")
	}
	if EnvWildcard().Empty() {
		t.Fatal("env wildcard should be addressable")
	}
}

func TestPlaceholderHelpers(t *testing.T) {
	placeholder := PlaceholderFor(" handle ")
	if placeholder != "${secret:handle}" {
		t.Fatalf("PlaceholderFor trimmed handle = %q", placeholder)
	}
	handle, ok := ParsePlaceholder(string(placeholder))
	if !ok || handle != "handle" {
		t.Fatalf("ParsePlaceholder = %q, %v", handle, ok)
	}
	if PlaceholderFor("   ") != "" {
		t.Fatal("empty handle should produce empty placeholder")
	}
}

func TestReplacePlaceholdersStopsOnError(t *testing.T) {
	replaced, err := ReplacePlaceholders("before ${secret:one} after", func(string) (string, error) {
		return "", errors.New("boom")
	})
	if err == nil {
		t.Fatal("expected replacement error")
	}
	if replaced != "" {
		t.Fatalf("replaced on error = %q, want empty string", replaced)
	}
}
