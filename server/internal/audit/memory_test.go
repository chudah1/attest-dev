package audit

import (
	"context"
	"testing"

	"github.com/attest-dev/attest/pkg/attest"
)

// TestMemoryLog_BasicAppend tests appending a single event.
func TestMemoryLog_BasicAppend(t *testing.T) {
	log := NewMemoryLog()
	ctx := context.Background()

	event := attest.AuditEvent{
		EventType: attest.EventIssued,
		JTI:       "jti-123",
		TaskID:    "tid-456",
		UserID:    "user-789",
		AgentID:   "agent-001",
		Scope:     []string{"read:documents"},
	}

	err := log.Append(ctx, event)
	if err != nil {
		t.Fatalf("Append failed: %v", err)
	}

	// Query the log to verify the event was stored correctly
	events, _ := log.Query(ctx, "tid-456")
	if len(events) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(events))
	}

	stored := events[0]
	if stored.ID == 0 {
		t.Error("Expected non-zero ID after append")
	}

	if stored.PrevHash != genesisHash {
		t.Errorf("Expected genesisHash, got %s", stored.PrevHash)
	}

	if stored.EntryHash == "" {
		t.Error("Expected non-empty EntryHash")
	}
}

// TestMemoryLog_Chaining tests that entries chain correctly.
func TestMemoryLog_Chaining(t *testing.T) {
	log := NewMemoryLog()
	ctx := context.Background()

	event1 := attest.AuditEvent{
		EventType: attest.EventIssued,
		JTI:       "jti-1",
		TaskID:    "tid-1",
		UserID:    "user-1",
		AgentID:   "agent-1",
		Scope:     []string{"read:documents"},
	}

	event2 := attest.AuditEvent{
		EventType: attest.EventDelegated,
		JTI:       "jti-2",
		TaskID:    "tid-1",
		UserID:    "user-1",
		AgentID:   "agent-2",
		Scope:     []string{"read:documents"},
	}

	err := log.Append(ctx, event1)
	if err != nil {
		t.Fatalf("Append event1 failed: %v", err)
	}

	err = log.Append(ctx, event2)
	if err != nil {
		t.Fatalf("Append event2 failed: %v", err)
	}

	// Query to verify chaining
	events, _ := log.Query(ctx, "tid-1")
	if len(events) != 2 {
		t.Fatalf("Expected 2 events, got %d", len(events))
	}

	if events[1].PrevHash != events[0].EntryHash {
		t.Error("Expected event2 to chain from event1")
	}

	if events[1].ID != events[0].ID+1 {
		t.Error("Expected sequential IDs")
	}
}

// TestMemoryLog_Query tests querying audit events for a task.
func TestMemoryLog_Query(t *testing.T) {
	log := NewMemoryLog()
	ctx := context.Background()

	// Add 5 events for task 1
	for i := 1; i <= 5; i++ {
		event := attest.AuditEvent{
			EventType: attest.EventIssued,
			JTI:       "jti-" + string(rune('0'+i)),
			TaskID:    "tid-1",
			UserID:    "user",
			AgentID:   "agent",
			Scope:     []string{"read:documents"},
		}
		_ = log.Append(ctx, event)
	}

	// Query task 1
	events, err := log.Query(ctx, "tid-1")
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if len(events) != 5 {
		t.Errorf("Expected 5 events, got %d", len(events))
	}

	// Query non-existent task
	events2, _ := log.Query(ctx, "non-existent")
	if len(events2) != 0 {
		t.Error("Expected empty result for non-existent task")
	}
}
