package storage

import (
	"database/sql"

	"github.com/spoutin/LAN-Orangutan/internal/types"
)

// GetSetting retrieves a setting value by key
func (s *Storage) GetSetting(key string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var val string
	err := s.db.QueryRow("SELECT value FROM settings WHERE key = ?", key).Scan(&val)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", err
	}
	return val, nil
}

// SetSetting saves or updates a setting by key
func (s *Storage) SetSetting(key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(`
		INSERT INTO settings (key, value)
		VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value
	`, key, value)
	return err
}

// ContinuousScanEnabled reports whether background scanning should run
func (s *Storage) ContinuousScanEnabled(configDefault bool) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var val string
	err := s.db.QueryRow("SELECT value FROM settings WHERE key = 'continuous_scan'").Scan(&val)
	if err != nil {
		return configDefault
	}
	return val == "true"
}

// SetContinuousScan saves override for background scanning
func (s *Storage) SetContinuousScan(enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	val := "false"
	if enabled {
		val = "true"
	}

	_, err := s.db.Exec(`
		INSERT INTO settings (key, value)
		VALUES ('continuous_scan', ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value
	`, val)
	return err
}

// GetNetworkNotification retrieves the webhook configuration for a specific network CIDR
func (s *Storage) GetNetworkNotification(cidr string) (*types.NetworkNotification, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var n types.NetworkNotification
	var enabledVal int
	err := s.db.QueryRow(`
		SELECT network_cidr, slack_webhook, enabled 
		FROM network_notifications 
		WHERE network_cidr = ?
	`, cidr).Scan(&n.NetworkCIDR, &n.SlackWebhook, &enabledVal)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	n.Enabled = enabledVal != 0
	return &n, nil
}

// GetNetworkNotifications retrieves all per-network notification configurations
func (s *Storage) GetNetworkNotifications() ([]types.NetworkNotification, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`
		SELECT network_cidr, slack_webhook, enabled 
		FROM network_notifications
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []types.NetworkNotification
	for rows.Next() {
		var n types.NetworkNotification
		var enabledVal int
		if err := rows.Scan(&n.NetworkCIDR, &n.SlackWebhook, &enabledVal); err == nil {
			n.Enabled = enabledVal != 0
			list = append(list, n)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return list, nil
}

// SaveNetworkNotification upserts a webhook configuration for a specific network CIDR
func (s *Storage) SaveNetworkNotification(cidr string, webhook string, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(`
		INSERT INTO network_notifications (network_cidr, slack_webhook, enabled)
		VALUES (?, ?, ?)
		ON CONFLICT(network_cidr) DO UPDATE SET
			slack_webhook = excluded.slack_webhook,
			enabled = excluded.enabled
	`, cidr, webhook, boolToInt(enabled))
	return err
}
