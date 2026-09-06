// Package identity models the security principals AppSec Framework may act as,
// and the authentication material it uses to act as them.
//
// The central distinction this package exists to enforce is that an identity is
// not a credential. An Identity is the principal — a stable id, a label, and a
// reference to how to authenticate. A Secret is the material. They have
// different lifetimes, different serialisation rules and different blast
// radiuses: an identity id belongs in every report, and a secret belongs in
// none.
package identity

import (
	"encoding/json"
	"fmt"
)

// Secret holds a resolved credential value.
//
// It is a struct wrapping an unexported field rather than a string alias, so
// that the value cannot reach output by accident. Every route Go offers for
// rendering a value is closed deliberately:
//
//   - String satisfies fmt.Stringer, so %s, %v and print-style logging of a
//     Secret — or of any struct containing one — render the placeholder.
//   - GoString satisfies fmt.GoStringer, closing %#v.
//   - MarshalJSON closes encoding/json, including a Secret reached indirectly
//     through a struct that is marshalled wholesale.
//   - UnmarshalJSON refuses, so a Secret can never be populated from untrusted
//     input that happens to be decoded into a struct containing one.
//
// Reading the value requires calling Expose, which is named to be conspicuous
// in review and is called from exactly one place: the code that attaches the
// credential to an outbound request.
type Secret struct {
	value string
}

// NewSecret wraps a credential value.
func NewSecret(v string) Secret { return Secret{value: v} }

// Expose returns the underlying credential.
//
// Every call site is a place a secret can escape. There is intentionally no
// convenience accessor with a gentler name.
func (s Secret) Expose() string { return s.value }

// Empty reports whether no credential was resolved.
func (s Secret) Empty() bool { return s.value == "" }

// There is deliberately no Len accessor. The report promises to carry no
// credential material at all, length included, and an accessor that returns one
// is an invitation to publish it.

// String renders the placeholder, never the value.
func (s Secret) String() string { return "[REDACTED]" }

// GoString renders the placeholder under %#v.
func (s Secret) GoString() string { return "[REDACTED]" }

// MarshalJSON renders the placeholder, so a struct carrying a Secret cannot
// serialise one by being marshalled as a whole.
func (s Secret) MarshalJSON() ([]byte, error) { return json.Marshal("[REDACTED]") }

// UnmarshalJSON refuses. A Secret is produced by resolving a credential source,
// never by decoding a document.
func (s *Secret) UnmarshalJSON([]byte) error {
	return fmt.Errorf("identity: a Secret cannot be decoded from JSON")
}
