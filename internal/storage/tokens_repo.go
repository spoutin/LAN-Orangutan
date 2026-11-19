package storage

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/spoutin/LAN-Orangutan/internal/types"
)

// hashToken returns the hex-encoded SHA-256 hash of rawToken.
func hashToken(rawToken string) string {
	sum := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(sum[:])
}

// CreateAPIToken generates storage for an API token.
func (s *Storage) CreateAPIToken(name, rawToken string) (*types.APIToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	trimmed := strings.TrimSpace(rawToken)
	if trimmed == "" {
		return nil, fmt.Errorf("token cannot be empty")
	}
	if len(trimmed) < 16 {
		return nil, fmt.Errorf("token must be at least 16 characters")
	}

	prefix := trimmed[:10]

	thash := hashToken(trimmed)

	res, err := s.db.Exec(`
		INSERT INTO api_tokens (name, token_hash, token_prefix, created_at)
		VALUES (?, ?, ?, CURRENT_TIMESTAMP)
	`, name, thash, prefix)
	if err != nil {
		return nil, err
	}

	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}

	return &types.APIToken{
		ID:          id,
		Name:        name,
		TokenPrefix: prefix,
		CreatedAt:   time.Now(),
	}, nil
}

// ListAPITokens returns all configured API tokens.
func (s *Storage) ListAPITokens() ([]*types.APIToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`
		SELECT id, name, token_prefix, created_at, last_used_at
		FROM api_tokens
		ORDER BY id ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []*types.APIToken
	for rows.Next() {
		var t types.APIToken
		var lastUsed sql.NullTime
		if err := rows.Scan(&t.ID, &t.Name, &t.TokenPrefix, &t.CreatedAt, &lastUsed); err != nil {
			return nil, err
		}
		if lastUsed.Valid {
			t.LastUsedAt = &lastUsed.Time
		}
		tokens = append(tokens, &t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return tokens, nil
}

// DeleteAPIToken removes an API token by ID.
func (s *Storage) DeleteAPIToken(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec("DELETE FROM api_tokens WHERE id = ?", id)
	return err
}

// ValidateAndTouchAPIToken validates the token and updates its last_used_at timestamp.
func (s *Storage) ValidateAndTouchAPIToken(rawToken string) (bool, error) {
	trimmed := strings.TrimSpace(rawToken)
	if trimmed == "" {
		return false, nil
	}

	thash := hashToken(trimmed)

	s.mu.Lock()
	defer s.mu.Unlock()

	var id int64
	err := s.db.QueryRow("SELECT id FROM api_tokens WHERE token_hash = ?", thash).Scan(&id)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}

	_, _ = s.db.Exec("UPDATE api_tokens SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?", id)
	return true, nil
}
