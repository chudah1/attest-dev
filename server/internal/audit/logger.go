package audit

import (
	"context"

	"github.com/attest-dev/attest/pkg/attest"
)

// Logger is the interface satisfied by both the Postgres Log and the
// in-memory MemoryLog. Handlers depend on this, not on the concrete type.
type Logger interface {
	Append(ctx context.Context, event attest.AuditEvent) error
	Query(ctx context.Context, taskID string) ([]attest.AuditEvent, error)
}
