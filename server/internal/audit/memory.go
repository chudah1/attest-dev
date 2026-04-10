package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
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

// ListTasks returns recent task summaries for the given org.
func (m *MemoryLog) ListTasks(_ context.Context, orgID string, query TaskListQuery) ([]TaskSummary, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	limit := query.Limit
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	type aggregate struct {
		summary      TaskSummary
		credentialJTIs map[string]struct{}
		hasAgent     bool
	}

	byTask := make(map[string]*aggregate)
	for _, entry := range m.entries {
		if entry.OrgID != orgID {
			continue
		}

		agg := byTask[entry.TaskID]
		if agg == nil {
			agg = &aggregate{
				summary: TaskSummary{
					TaskID:      entry.TaskID,
					UserID:      entry.UserID,
					RootAgentID: entry.AgentID,
					CreatedAt:   entry.CreatedAt,
				},
				credentialJTIs: make(map[string]struct{}),
			}
			byTask[entry.TaskID] = agg
		}

		agg.summary.EventCount++
		if entry.CreatedAt.Before(agg.summary.CreatedAt) {
			agg.summary.CreatedAt = entry.CreatedAt
			agg.summary.RootAgentID = entry.AgentID
		}
		if agg.summary.LastEventAt.IsZero() || entry.CreatedAt.After(agg.summary.LastEventAt) || (entry.CreatedAt.Equal(agg.summary.LastEventAt) && entry.ID > 0) {
			agg.summary.LastEventAt = entry.CreatedAt
			agg.summary.LastEventType = entry.EventType
		}
		if entry.EventType == attest.EventRevoked {
			agg.summary.Revoked = true
		}
		if query.AgentID != "" && entry.AgentID == query.AgentID {
			agg.hasAgent = true
		}
		if entry.EventType == attest.EventIssued || entry.EventType == attest.EventDelegated {
			agg.credentialJTIs[entry.JTI] = struct{}{}
		}
	}

	summaries := make([]TaskSummary, 0, len(byTask))
	for _, agg := range byTask {
		agg.summary.CredentialCount = len(agg.credentialJTIs)
		if query.UserID != "" && agg.summary.UserID != query.UserID {
			continue
		}
		if query.AgentID != "" && !agg.hasAgent {
			continue
		}
		switch query.Status {
		case "active":
			if agg.summary.Revoked {
				continue
			}
		case "revoked":
			if !agg.summary.Revoked {
				continue
			}
		}
		summaries = append(summaries, agg.summary)
	}

	sort.Slice(summaries, func(i, j int) bool {
		if summaries[i].LastEventAt.Equal(summaries[j].LastEventAt) {
			return summaries[i].TaskID < summaries[j].TaskID
		}
		return summaries[i].LastEventAt.After(summaries[j].LastEventAt)
	})

	if len(summaries) > limit {
		summaries = summaries[:limit]
	}
	return summaries, nil
}
