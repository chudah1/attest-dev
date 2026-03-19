package revocation

import "context"

// Revoker is the interface satisfied by both the Postgres Store and the
// in-memory MemoryStore. Handlers depend on this, not on the concrete type.
type Revoker interface {
	// Revoke marks jti as revoked and cascades to all descendants.
	Revoke(ctx context.Context, jti, revokedBy string) error

	// IsRevoked reports whether jti has been revoked.
	IsRevoked(ctx context.Context, jti string) (bool, error)

	// TrackCredential registers a credential's chain so cascade revocation
	// works without a database. The Postgres Store ignores this call (it
	// uses the credentials table instead). The MemoryStore uses it.
	TrackCredential(jti string, chain []string)
}
