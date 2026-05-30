package secret

import (
	"context"
	"regexp"
	"strings"
	"time"
)

// Scheme identifies how a secret ref is addressed.
type Scheme string

const (
	SchemeEnv        Scheme = "env"
	SchemePlugin     Scheme = "plugin"
	SchemeKubernetes Scheme = "kubernetes"
)

// Kind identifies the material shape stored or resolved for a secret.
type Kind string

const (
	KindAPIKey      Kind = "api_key"
	KindBearerToken Kind = "bearer_token"
	KindOAuth2Token Kind = "oauth2_token"
	KindBasic       Kind = "basic"
	KindPKI         Kind = "pki"
)

// Slot names one addressable credential field such as access_token, api_key,
// username, password, or client_secret.
type Slot string

// Use describes the broad semantic category for secret material. Use is not the
// addressable credential name; use Slot for that.
type Use string

const (
	UseAuthToken Use = "auth_token"
	UseAPIKey    Use = "api_key"
	UsePassword  Use = "password"
	UseTLS       Use = "tls"
	UseSigning   Use = "signing"
)

// StoreRef identifies a secret store or namespace.
type StoreRef string

// Ref identifies sensitive material without exposing its value.
//
// For SchemePlugin, Plugin stores the provider/plugin name, Instance stores the
// plugin instance, and Slot stores the credential slot. For SchemeKubernetes,
// Plugin stores namespace, Instance stores Secret name, and Slot stores key.
type Ref struct {
	Scheme   Scheme `json:"scheme,omitempty" yaml:"scheme,omitempty"`
	Plugin   string `json:"plugin,omitempty" yaml:"plugin,omitempty"`
	Instance string `json:"instance,omitempty" yaml:"instance,omitempty"`
	Slot     Slot   `json:"slot,omitempty" yaml:"slot,omitempty"`
}

// Empty reports whether ref has no addressable resource.
func (r Ref) Empty() bool {
	return r.Normalize().ResourceName() == ""
}

// Normalize returns a trimmed ref.
func (r Ref) Normalize() Ref {
	r.Scheme = Scheme(strings.TrimSpace(string(r.Scheme)))
	r.Plugin = strings.TrimSpace(r.Plugin)
	r.Instance = strings.TrimSpace(r.Instance)
	r.Slot = Slot(strings.TrimSpace(string(r.Slot)))
	return r
}

// ResourceName returns a stable slash-separated name suitable for policy and
// audit resources.
func (r Ref) ResourceName() string {
	r = r.Normalize()
	slot := string(r.Slot)
	switch r.Scheme {
	case "":
		return ""
	case SchemeEnv:
		if r.Slot == "" {
			return "env/*"
		}
		return "env/" + slot
	case SchemePlugin:
		return strings.Join(nonEmpty("plugin", r.Plugin, r.Instance, slot), "/")
	case SchemeKubernetes:
		return strings.Join(nonEmpty("kubernetes", r.Plugin, r.Instance, slot), "/")
	default:
		return strings.Join(nonEmpty(string(r.Scheme), r.Plugin, r.Instance, slot), "/")
	}
}

// Env returns an environment-variable secret ref.
func Env(name string) Ref {
	return Ref{Scheme: SchemeEnv, Slot: Slot(name)}.Normalize()
}

// EnvWildcard returns an environment-variable wildcard ref.
func EnvWildcard() Ref {
	return Ref{Scheme: SchemeEnv}
}

// Plugin returns a plugin-scoped secret ref.
func Plugin(plugin, instance string, slot Slot) Ref {
	return Ref{Scheme: SchemePlugin, Plugin: plugin, Instance: instance, Slot: slot}.Normalize()
}

// Kubernetes returns a Kubernetes Secret key ref. Plugin stores namespace,
// Instance stores secret name, and Slot stores key.
func Kubernetes(namespace, secretName string, key Slot) Ref {
	return Ref{Scheme: SchemeKubernetes, Plugin: namespace, Instance: secretName, Slot: key}.Normalize()
}

// ParseRef parses a canonical secret resource name into a Ref.
func ParseRef(value string) Ref {
	parts := strings.Split(strings.Trim(strings.TrimSpace(value), "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		return Ref{}
	}
	scheme := Scheme(parts[0])
	switch scheme {
	case SchemeEnv:
		return parseEnvRef(parts)
	case SchemePlugin, SchemeKubernetes:
		return parseHierarchicalRef(scheme, parts)
	default:
		return parseGenericRef(scheme, parts)
	}
}

func parseEnvRef(parts []string) Ref {
	if len(parts) < 2 || len(parts) == 2 && parts[1] == "*" {
		return EnvWildcard()
	}
	return Env(strings.Join(parts[1:], "/"))
}

func parseHierarchicalRef(scheme Scheme, parts []string) Ref {
	ref := Ref{Scheme: scheme}
	if len(parts) >= 2 {
		ref.Plugin = parts[1]
	}
	if len(parts) >= 3 {
		ref.Instance = parts[2]
	}
	if len(parts) >= 4 {
		ref.Slot = Slot(strings.Join(parts[3:], "/"))
	}
	return ref.Normalize()
}

func parseGenericRef(scheme Scheme, parts []string) Ref {
	ref := Ref{Scheme: scheme}
	if len(parts) >= 2 {
		ref.Slot = Slot(strings.Join(parts[1:], "/"))
	}
	return ref.Normalize()
}

// Scope carries queryable ownership and visibility metadata for a secret ref.
type Scope struct {
	TenantID    string            `json:"tenant_id,omitempty" yaml:"tenant_id,omitempty"`
	AppID       string            `json:"app_id,omitempty" yaml:"app_id,omitempty"`
	WorkspaceID string            `json:"workspace_id,omitempty" yaml:"workspace_id,omitempty"`
	UserID      string            `json:"user_id,omitempty" yaml:"user_id,omitempty"`
	AgentID     string            `json:"agent_id,omitempty" yaml:"agent_id,omitempty"`
	SessionID   string            `json:"session_id,omitempty" yaml:"session_id,omitempty"`
	ThreadID    string            `json:"thread_id,omitempty" yaml:"thread_id,omitempty"`
	ChannelID   string            `json:"channel_id,omitempty" yaml:"channel_id,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty" yaml:"annotations,omitempty"`
}

// Selector describes the secret material a caller wants the host to resolve.
type Selector struct {
	Ref         Ref               `json:"ref,omitempty" yaml:"ref,omitempty"`
	Store       StoreRef          `json:"store,omitempty" yaml:"store,omitempty"`
	Slot        Slot              `json:"slot,omitempty" yaml:"slot,omitempty"`
	Provider    string            `json:"provider,omitempty" yaml:"provider,omitempty"`
	Uses        []Use             `json:"uses,omitempty" yaml:"uses,omitempty"`
	Scope       Scope             `json:"scope,omitempty" yaml:"scope,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty" yaml:"annotations,omitempty"`
}

// Descriptor describes secret material without carrying its value.
type Descriptor struct {
	Ref         Ref               `json:"ref" yaml:"ref"`
	Store       StoreRef          `json:"store,omitempty" yaml:"store,omitempty"`
	Kind        Kind              `json:"kind,omitempty" yaml:"kind,omitempty"`
	Slot        Slot              `json:"slot,omitempty" yaml:"slot,omitempty"`
	Description string            `json:"description,omitempty" yaml:"description,omitempty"`
	Provider    string            `json:"provider,omitempty" yaml:"provider,omitempty"`
	Uses        []Use             `json:"uses,omitempty" yaml:"uses,omitempty"`
	Scope       Scope             `json:"scope,omitempty" yaml:"scope,omitempty"`
	Labels      map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty" yaml:"annotations,omitempty"`
}

// WireMaterial is a trusted host/plugin-process transport DTO. It is not safe
// for model-visible surfaces or logs.
type WireMaterial struct {
	Kind    Kind   `json:"kind,omitempty" yaml:"kind,omitempty"`
	Value   string `json:"value" yaml:"value"`
	Source  string `json:"source,omitempty" yaml:"source,omitempty"`
	Purpose string `json:"purpose,omitempty" yaml:"purpose,omitempty"`
	Ref     Ref    `json:"ref,omitempty" yaml:"ref,omitempty"`
}

// Material converts the trusted wire shape to shared secret material.
func (m WireMaterial) Material() Material {
	return Material{Ref: m.Ref.Normalize(), Kind: m.Kind, Value: []byte(m.Value)}
}

// WireMaterialFromMaterial converts trusted material to the wire DTO.
func WireMaterialFromMaterial(m Material) WireMaterial {
	return WireMaterial{Kind: m.Kind, Value: string(m.Value), Ref: m.Ref.Normalize()}
}

// CapabilityGrant allows one host capability while a secret access grant is valid.
type CapabilityGrant struct {
	Name     string `json:"name" yaml:"name"`
	Provider string `json:"provider,omitempty" yaml:"provider,omitempty"`
	Action   string `json:"action,omitempty" yaml:"action,omitempty"`
}

// AccessGrant authorizes a plugin instance to resolve selected secret purposes
// for a short period. It carries no secret material.
type AccessGrant struct {
	Token        string              `json:"token" yaml:"token"`
	Plugin       string              `json:"plugin" yaml:"plugin"`
	Instance     string              `json:"instance" yaml:"instance"`
	Operations   []string            `json:"operations,omitempty" yaml:"operations,omitempty"`
	Capabilities []CapabilityGrant   `json:"capabilities,omitempty" yaml:"capabilities,omitempty"`
	Purposes     []string            `json:"purposes,omitempty" yaml:"purposes,omitempty"`
	PurposeEnv   map[string][]string `json:"purpose_env,omitempty" yaml:"purpose_env,omitempty"`
	ExpiresAt    time.Time           `json:"expires_at" yaml:"expires_at"`
	CreatedAt    time.Time           `json:"created_at" yaml:"created_at"`
}

// Material is resolved secret material available only to trusted runtime code.
// Hosts should keep Value out of model-visible surfaces and logs.
type Material struct {
	Ref       Ref    `json:"ref,omitempty" yaml:"ref,omitempty"`
	Kind      Kind   `json:"kind,omitempty" yaml:"kind,omitempty"`
	Value     []byte `json:"-" yaml:"-"`
	MediaType string `json:"media_type,omitempty" yaml:"media_type,omitempty"`
}

// String returns Value as a string for trusted runtime code.
func (m Material) String() string { return string(m.Value) }

// Empty reports whether material has no non-whitespace value.
func (m Material) Empty() bool { return strings.TrimSpace(string(m.Value)) == "" }

// Redacted returns a stable non-secret marker for present/absent material.
func (m Material) Redacted() string {
	if m.Empty() {
		return ""
	}
	return "<redacted>"
}

// StoredSecret is persisted secret material plus non-sensitive metadata. Value is
// intentionally JSON-visible for trusted stores; never return StoredSecret on
// model-visible surfaces.
type StoredSecret struct {
	Ref         Ref               `json:"ref" yaml:"ref"`
	Store       StoreRef          `json:"store,omitempty" yaml:"store,omitempty"`
	Kind        Kind              `json:"kind,omitempty" yaml:"kind,omitempty"`
	Slot        Slot              `json:"slot,omitempty" yaml:"slot,omitempty"`
	Value       string            `json:"value" yaml:"value"`
	MediaType   string            `json:"media_type,omitempty" yaml:"media_type,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	ExpiresAt   time.Time         `json:"expires_at,omitempty" yaml:"expires_at,omitempty"`
	UpdatedAt   time.Time         `json:"updated_at,omitempty" yaml:"updated_at,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty" yaml:"annotations,omitempty"`
}

// Resolver resolves secret refs to raw material for trusted runtime code.
type Resolver interface {
	ResolveSecret(context.Context, Ref) (Material, bool, error)
}

// ResolverFunc adapts a function into a Resolver.
type ResolverFunc func(context.Context, Ref) (Material, bool, error)

// ResolveSecret implements Resolver.
func (f ResolverFunc) ResolveSecret(ctx context.Context, ref Ref) (Material, bool, error) {
	if f == nil {
		return Material{}, false, nil
	}
	return f(ctx, ref)
}

// Store persists and loads trusted secret material.
type Store interface {
	SaveSecret(context.Context, StoredSecret) error
	LoadSecret(context.Context, Ref) (StoredSecret, bool, error)
}

// Placeholder is the model-visible opaque secret token.
type Placeholder string

var placeholderRE = regexp.MustCompile(`\$\{secret:([A-Za-z0-9._~+/=-]+)\}`)

// PlaceholderFor renders a handle as a model-visible placeholder. Empty handles
// intentionally return an empty placeholder rather than ${secret:}.
func PlaceholderFor(handle string) Placeholder {
	handle = strings.TrimSpace(handle)
	if handle == "" {
		return ""
	}
	return Placeholder("${secret:" + handle + "}")
}

// ParsePlaceholder parses a complete placeholder.
func ParsePlaceholder(value string) (string, bool) {
	trimmed := strings.TrimSpace(value)
	matches := placeholderRE.FindStringSubmatch(trimmed)
	if len(matches) != 2 || matches[0] != trimmed {
		return "", false
	}
	return matches[1], true
}

// ReplacePlaceholders replaces all placeholders in value.
func ReplacePlaceholders(value string, replace func(handle string) (string, error)) (string, error) {
	if replace == nil {
		return value, nil
	}
	var first error
	out := placeholderRE.ReplaceAllStringFunc(value, func(match string) string {
		if first != nil {
			return match
		}
		handle, ok := ParsePlaceholder(match)
		if !ok {
			return match
		}
		replacement, err := replace(handle)
		if err != nil {
			first = err
			return match
		}
		return replacement
	})
	if first != nil {
		return "", first
	}
	return out, nil
}

// RedactPlaceholders removes model-visible secret handles from value.
func RedactPlaceholders(value string) string {
	return placeholderRE.ReplaceAllString(value, "${secret:redacted}")
}

func nonEmpty(values ...string) []string {
	out := values[:0]
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, strings.TrimSpace(value))
		}
	}
	return out
}
