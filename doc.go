// Package secret defines inert references and metadata for sensitive material.
//
// Secret does not store, resolve, decrypt, prompt for, approve, or expose secret
// values. Runtime packages can use these contracts to pass opaque references and
// describe intended credential purposes without coupling to a concrete store.
package secret
