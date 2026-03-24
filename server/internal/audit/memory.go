package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"sync/atomic"
	"time"

	"github.com/attest-dev/attest/pkg/attest"
)

const genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// MemoryLog is a thread-safe, in-process audit log for dev/test use.
// It maintains the same hash-chaining semantics as the Postgres Log.
type MemoryLog struct {
	mu      sync.RWMutex
	entries []attest.AuditEvent // all entries in insertion order
	tails   map[string]string   // att_tid → most recent entry_hash
	seq     atomic.Int64        // monotonic ID counter
}

// NewMemoryLog returns a ready-to-use in-memory audit log.
func NewMemoryLog() *MemoryLog {
	return &MemoryLog{
		tails: make(map[string]string),
	}
}

// Append adds an event to the log, computing prev_hash and entry_hash
// using the same algorithm as the Postgres implementation.
func (m *MemoryLog) Append(_ context.Context, orgID string, event attest.AuditEvent) error {
	event.OrgID = orgID
	m.mu.Lock()
	defer m.mu.Unlock()

	tailKey := orgID + ":" + event.TaskID
	prevHash, ok := m.tails[tailKey]
	if !ok {
		prevHash = genesisHash
	}

	now := time.Now().UTC()
	raw := prevHash + string(event.EventType) + event.JTI + now.Format(time.RFC3339Nano)
	h := sha256.Sum256([]byte(raw))
	entryHash := hex.EncodeToString(h[:])

	event.ID = m.seq.Add(1)
	event.PrevHash = prevHash
	event.EntryHash = entryHash
	event.CreatedAt = now

	m.entries = append(m.entries, event)
	m.tails[tailKey] = entryHash

	return nil
}

// Query returns all events for taskID in insertion order.
func (m *MemoryLog) Query(_ context.Context, orgID string, taskID string) ([]attest.AuditEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var out []attest.AuditEvent
	for _, e := range m.entries {
		if e.OrgID == orgID && e.TaskID == taskID {
			out = append(out, e)
		}
	}
	return out, nil
}
