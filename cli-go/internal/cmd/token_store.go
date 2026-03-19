package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type storedToken struct {
	AccessToken string    `json:"access_token"`
	ClientID    string    `json:"client_id,omitempty"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
	Issuer      string    `json:"issuer,omitempty"`
	TokenType   string    `json:"token_type,omitempty"`
}

func defaultTokenFilePath() string {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return ".aof-token.json"
	}
	return filepath.Join(configDir, "aof", "token.json")
}

func readStoredToken(path string) (*storedToken, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var token storedToken
	if err := json.Unmarshal(raw, &token); err != nil {
		return nil, fmt.Errorf("decode token file: %w", err)
	}
	token.AccessToken = strings.TrimSpace(token.AccessToken)
	if token.AccessToken == "" {
		return nil, fmt.Errorf("token file is missing access_token")
	}
	return &token, nil
}

func writeStoredToken(path string, token *storedToken) error {
	if token == nil || strings.TrimSpace(token.AccessToken) == "" {
		return fmt.Errorf("cannot store empty access token")
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create token directory: %w", err)
	}

	raw, err := json.MarshalIndent(token, "", "  ")
	if err != nil {
		return fmt.Errorf("encode token: %w", err)
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return fmt.Errorf("write token file: %w", err)
	}
	return nil
}
