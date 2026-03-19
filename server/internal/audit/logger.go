package audit

import (
	"context"

	"github.com/warrant-dev/warrant/pkg/warrant"
)

// Logger is the interface satisfied by both the Postgres Log and the
// in-memory MemoryLog. Handlers depend on this, not on the concrete type.
type Logger interface {
	Append(ctx context.Context, event warrant.AuditEvent) error
	Query(ctx context.Context, taskID string) ([]warrant.AuditEvent, error)
}
