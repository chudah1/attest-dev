package org

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore is the production implementation backed by PostgreSQL.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore returns a PostgresStore using the given connection pool.
func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

func (s *PostgresStore) CreateOrg(ctx context.Context, name string) (*Org, string, *APIKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", nil, fmt.Errorf("generate rsa key: %w", err)
	}
	keyDER := x509.MarshalPKCS1PrivateKey(privateKey)

	now := time.Now().UTC()
	orgID := uuid.NewString()
	keyID := uuid.NewString()
	apiKeyID := uuid.NewString()
	rawKey := generateAPIKey()

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, "", nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err = tx.Exec(ctx,
		`INSERT INTO organizations (id, name, status, created_at) VALUES ($1, $2, 'active', $3)`,
		orgID, name, now,
	); err != nil {
		return nil, "", nil, fmt.Errorf("insert org: %w", err)
	}

	if _, err = tx.Exec(ctx,
		`INSERT INTO org_keys (id, org_id, private_key, created_at) VALUES ($1, $2, $3, $4)`,
		keyID, orgID, keyDER, now,
	); err != nil {
		return nil, "", nil, fmt.Errorf("insert org key: %w", err)
	}

	if _, err = tx.Exec(ctx,
		`INSERT INTO api_keys (id, org_id, key_hash, name, created_at) VALUES ($1, $2, $3, 'default', $4)`,
		apiKeyID, orgID, hashKey(rawKey), now,
	); err != nil {
		return nil, "", nil, fmt.Errorf("insert api key: %w", err)
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, "", nil, fmt.Errorf("commit: %w", err)
	}

	org := &Org{ID: orgID, Name: name, Status: "active", CreatedAt: now}
	apiKey := &APIKey{ID: apiKeyID, OrgID: orgID, Name: "default", CreatedAt: now}
	return org, rawKey, apiKey, nil
}

func (s *PostgresStore) ResolveAPIKey(ctx context.Context, rawKey string) (*Org, *APIKey, error) {
	h := hashKey(rawKey)
	row := s.pool.QueryRow(ctx, `
		SELECT o.id, o.name, o.status, o.created_at, k.id, k.name, k.created_at
		FROM api_keys k
		JOIN organizations o ON o.id = k.org_id
		WHERE k.key_hash = $1
		  AND k.revoked_at IS NULL
		  AND o.status = 'active'
	`, h)

	var o Org
	var ak APIKey
	err := row.Scan(&o.ID, &o.Name, &o.Status, &o.CreatedAt, &ak.ID, &ak.Name, &ak.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, ErrInvalidKey
	}
	if err != nil {
		return nil, nil, fmt.Errorf("resolve api key: %w", err)
	}
	ak.OrgID = o.ID
	return &o, &ak, nil
}

func (s *PostgresStore) GetSigningKey(ctx context.Context, orgID string) (*OrgKey, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, private_key, created_at
		FROM org_keys
		WHERE org_id = $1 AND retired_at IS NULL
		ORDER BY created_at DESC
		LIMIT 1
	`, orgID)

	var keyID string
	var keyDER []byte
	var createdAt time.Time
	err := row.Scan(&keyID, &keyDER, &createdAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("no active signing key for org %q", orgID)
	}
	if err != nil {
		return nil, fmt.Errorf("query signing key: %w", err)
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(keyDER)
	if err != nil {
		return nil, fmt.Errorf("parse signing key: %w", err)
	}

	return &OrgKey{
		KeyID:      keyID,
		OrgID:      orgID,
		PrivateKey: privateKey,
		CreatedAt:  createdAt,
	}, nil
}

func (s *PostgresStore) CreateAPIKey(ctx context.Context, orgID, name string) (*APIKey, string, error) {
	rawKey := generateAPIKey()
	now := time.Now().UTC()
	apiKeyID := uuid.NewString()

	_, err := s.pool.Exec(ctx,
		`INSERT INTO api_keys (id, org_id, key_hash, name, created_at) VALUES ($1, $2, $3, $4, $5)`,
		apiKeyID, orgID, hashKey(rawKey), name, now,
	)
	if err != nil {
		return nil, "", fmt.Errorf("insert api key: %w", err)
	}

	ak := &APIKey{ID: apiKeyID, OrgID: orgID, Name: name, CreatedAt: now}
	return ak, rawKey, nil
}

func (s *PostgresStore) ListAPIKeys(ctx context.Context, orgID string) ([]*APIKey, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, org_id, name, created_at, revoked_at
		FROM api_keys
		WHERE org_id = $1
		ORDER BY created_at DESC
	`, orgID)
	if err != nil {
		return nil, fmt.Errorf("list api keys: %w", err)
	}
	defer rows.Close()

	var keys []*APIKey
	for rows.Next() {
		var ak APIKey
		if err := rows.Scan(&ak.ID, &ak.OrgID, &ak.Name, &ak.CreatedAt, &ak.RevokedAt); err != nil {
			return nil, fmt.Errorf("scan api key: %w", err)
		}
		keys = append(keys, &ak)
	}
	return keys, rows.Err()
}

func (s *PostgresStore) RevokeAPIKey(ctx context.Context, orgID, keyID string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE api_keys SET revoked_at = NOW() WHERE id = $1 AND org_id = $2 AND revoked_at IS NULL`,
		keyID, orgID,
	)
	if err != nil {
		return fmt.Errorf("revoke api key: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PostgresStore) RotateSigningKey(ctx context.Context, orgID string) (*OrgKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate rsa key: %w", err)
	}
	keyDER := x509.MarshalPKCS1PrivateKey(privateKey)

	now := time.Now().UTC()
	newKeyID := uuid.NewString()

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Retire all current active keys for this org.
	if _, err = tx.Exec(ctx,
		`UPDATE org_keys SET retired_at = $1 WHERE org_id = $2 AND retired_at IS NULL`,
		now, orgID,
	); err != nil {
		return nil, fmt.Errorf("retire old keys: %w", err)
	}

	// Insert the new key.
	if _, err = tx.Exec(ctx,
		`INSERT INTO org_keys (id, org_id, private_key, created_at) VALUES ($1, $2, $3, $4)`,
		newKeyID, orgID, keyDER, now,
	); err != nil {
		return nil, fmt.Errorf("insert new key: %w", err)
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}

	return &OrgKey{
		KeyID:      newKeyID,
		OrgID:      orgID,
		PrivateKey: privateKey,
		CreatedAt:  now,
	}, nil
}
