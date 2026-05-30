// Package secret defines inert references and metadata for sensitive material.
//
// Secret does not store, resolve, decrypt, prompt for, approve, or expose secret
// values. Runtime packages can use these contracts to pass opaque references,
// credential slots, and intended uses without coupling to a concrete store.
package secret
