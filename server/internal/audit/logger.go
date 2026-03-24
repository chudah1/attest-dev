package audit

import (
	"context"

	"github.com/attest-dev/attest/pkg/attest"
)

// Logger is the interface satisfied by both the Postgres Log and the
// in-memory MemoryLog. Handlers depend on this, not on the concrete type.
type Logger interface {
	Append(ctx context.Context, orgID string, event attest.AuditEvent) error
	Query(ctx context.Context, orgID string, taskID string) ([]attest.AuditEvent, error)
}
