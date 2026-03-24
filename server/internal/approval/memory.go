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

func (m *memoryStore) Get(ctx context.Context, orgID, id string) (*ApprovalRequest, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	req, ok := m.approvals[id]
	if !ok || req.OrgID != orgID {
		return nil, ErrNotFound
	}

	r := *req
	if r.Status == StatusPending && time.Since(r.CreatedAt) > 15*time.Minute {
		r.Status = StatusExpired
	}

	return &r, nil
}

func (m *memoryStore) GetPending(ctx context.Context, orgID, id string) (*ApprovalRequest, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	req, ok := m.approvals[id]
	if !ok || req.OrgID != orgID || req.Status != StatusPending {
		return nil, ErrNotFound
	}

	if time.Since(req.CreatedAt) > 15*time.Minute {
		// Lazily expire, though Resolve handles it as well.
		req.Status = StatusExpired
		return nil, ErrNotFound
	}

	r := *req
	return &r, nil
}

func (m *memoryStore) Resolve(ctx context.Context, orgID, id string, status Status, approvedBy string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	req, ok := m.approvals[id]
	if !ok || req.OrgID != orgID || req.Status != StatusPending {
		return ErrNotFound
	}

	if time.Since(req.CreatedAt) > 15*time.Minute {
		req.Status = StatusExpired
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
