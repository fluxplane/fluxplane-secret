package secret

import (
	"context"
	"fmt"
	"strings"
)

// Environment is the system environment boundary shape used by EnvResolver.
type Environment interface {
	Lookup(context.Context, string) (string, bool, error)
}

// EnvResolver resolves env-backed secrets. Authorization is enforced by callers
// such as auth.Broker; this resolver intentionally avoids relying on a system
// Environment's secret.read gate so secret.use can be a non-disclosing capability.
type EnvResolver struct {
	Environment Environment
	Kind        Kind
}

// ResolveSecret resolves env/<KEY> refs.
func (r EnvResolver) ResolveSecret(ctx context.Context, ref Ref) (Material, bool, error) {
	ref = ref.Normalize()
	if ref.Scheme != SchemeEnv {
		return Material{}, false, nil
	}
	if ref.Slot == "" {
		return Material{}, false, fmt.Errorf("secret env ref name is empty")
	}
	if r.Environment == nil {
		return Material{}, false, fmt.Errorf("secret env resolver environment is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	value, ok, err := r.Environment.Lookup(ctx, string(ref.Slot))
	if err != nil {
		return Material{}, false, err
	}
	if !ok || strings.TrimSpace(value) == "" {
		return Material{}, false, nil
	}
	kind := r.Kind
	if kind == "" {
		kind = KindAPIKey
	}
	return Material{Ref: ref, Kind: kind, Value: []byte(value)}, true, nil
}

// ChainResolver tries resolvers in order.
type ChainResolver []Resolver

// ResolveSecret implements Resolver.
func (c ChainResolver) ResolveSecret(ctx context.Context, ref Ref) (Material, bool, error) {
	for _, resolver := range c {
		if resolver == nil {
			continue
		}
		material, ok, err := resolver.ResolveSecret(ctx, ref)
		if err != nil || ok {
			return material, ok, err
		}
	}
	return Material{}, false, nil
}
