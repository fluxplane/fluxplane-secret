package secret

// Ref identifies sensitive material without exposing its value.
type Ref string

// StoreRef identifies a secret store or namespace.
type StoreRef string

// Purpose describes why a caller needs secret material.
type Purpose string

const (
	PurposeAuthToken Purpose = "auth_token"
	PurposeAPIKey    Purpose = "api_key"
	PurposePassword  Purpose = "password"
	PurposeTLS       Purpose = "tls"
	PurposeSigning   Purpose = "signing"
)

// Scope carries queryable ownership and visibility metadata for a secret ref.
type Scope struct {
	TenantID    string            `json:"tenant_id,omitempty"`
	AppID       string            `json:"app_id,omitempty"`
	WorkspaceID string            `json:"workspace_id,omitempty"`
	UserID      string            `json:"user_id,omitempty"`
	AgentID     string            `json:"agent_id,omitempty"`
	SessionID   string            `json:"session_id,omitempty"`
	ChannelID   string            `json:"channel_id,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// Selector describes the secret material a caller wants the host to resolve.
type Selector struct {
	Ref         Ref               `json:"ref,omitempty"`
	Store       StoreRef          `json:"store,omitempty"`
	Name        string            `json:"name,omitempty"`
	Provider    string            `json:"provider,omitempty"`
	Purposes    []Purpose         `json:"purposes,omitempty"`
	Scope       Scope             `json:"scope,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// Descriptor describes secret material without carrying its value.
type Descriptor struct {
	Ref         Ref               `json:"ref"`
	Store       StoreRef          `json:"store,omitempty"`
	Name        string            `json:"name,omitempty"`
	Description string            `json:"description,omitempty"`
	Provider    string            `json:"provider,omitempty"`
	Purposes    []Purpose         `json:"purposes,omitempty"`
	Scope       Scope             `json:"scope,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// Material is resolved secret material. Hosts should keep this value out of
// model-visible surfaces and logs.
type Material struct {
	Ref       Ref    `json:"ref,omitempty"`
	Value     []byte `json:"-"`
	MediaType string `json:"media_type,omitempty"`
}
