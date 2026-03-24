package revocation

import (
	"context"

	"github.com/attest-dev/attest/pkg/attest"
)

// Revoker is the interface satisfied by both the Postgres Store and the
// in-memory MemoryStore. Handlers depend on this, not on the concrete type.
type Revoker interface {
	// Revoke marks jti as revoked and cascades to all descendants.
	// orgID scopes the revocation to credentials belonging to the given org.
	Revoke(ctx context.Context, orgID, jti, revokedBy string) error

	// IsRevoked reports whether jti has been revoked.
	IsRevoked(ctx context.Context, orgID, jti string) (bool, error)

	// TrackCredential registers a credential so cascade revocation works.
	// orgID associates the credential with the issuing org.
	TrackCredential(ctx context.Context, orgID string, claims *attest.Claims) error
}
