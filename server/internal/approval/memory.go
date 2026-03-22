package approval

import (
	"context"
	"sync"
	"time"
)

type memoryStore struct {
	mu        sync.RWMutex
	approvals map[string]*ApprovalRequest
}

func NewMemoryStore() Store {
	return &memoryStore{
		approvals: make(map[string]*ApprovalRequest),
	}
}

func (m *memoryStore) RequestApproval(ctx context.Context, req ApprovalRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	req.CreatedAt = time.Now().UTC()
	req.Status = StatusPending
	
	// Copy to prevent external mutation
	r := req 
	m.approvals[r.ID] = &r
	return nil
}

func (m *memoryStore) Get(ctx context.Context, id string) (*ApprovalRequest, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	req, ok := m.approvals[id]
	if !ok {
		return nil, ErrNotFound
	}

	r := *req
	return &r, nil
}

func (m *memoryStore) GetPending(ctx context.Context, id string) (*ApprovalRequest, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	req, ok := m.approvals[id]
	if !ok || req.Status != StatusPending {
		return nil, ErrNotFound
	}

	// Copy to prevent external mutation
	r := *req
	return &r, nil
}

func (m *memoryStore) Resolve(ctx context.Context, id string, status Status, approvedBy string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	req, ok := m.approvals[id]
	if !ok || req.Status != StatusPending {
		return ErrNotFound
	}

	req.Status = status
	now := time.Now().UTC()
	req.ResolvedAt = &now
	if approvedBy != "" {
		req.ApprovedBy = &approvedBy
	}

	return nil
}
