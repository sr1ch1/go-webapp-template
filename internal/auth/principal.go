// Package auth verifies Identity Provider JWTs and derives the caller's
// Principal. Providers are pluggable via a compile-time registry.
package auth

import "slices"

// Principal is the verified identity of the caller, extracted from a
// validated JWT. Roles are asserted by the Identity Provider.
type Principal struct {
	Subject     string   `json:"subject"`
	Email       string   `json:"email"`
	DisplayName string   `json:"display_name"`
	Roles       []string `json:"roles"`
}

// HasRole reports whether the Principal carries the given role.
func (p Principal) HasRole(role string) bool {
	return slices.Contains(p.Roles, role)
}
