package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// envOrDotfile reads a KEY from the process environment, falling back to
// ~/.hermes/.env (same convention as VAULT_TOKEN below) if unset.
func envOrDotfile(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	home, _ := os.UserHomeDir()
	f, err := os.Open(home + "/.hermes/.env")
	if err != nil {
		return def
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, key+"=") {
			v := strings.TrimPrefix(line, key+"=")
			return strings.Trim(v, `"'`)
		}
	}
	return def
}

func vaultAddrFromEnv() string {
	return envOrDotfile("VAULT_ADDR", "http://127.0.0.1:8200")
}

var vaultAddr = vaultAddrFromEnv()

// vaultToken reads VAULT_TOKEN from env or ~/.hermes/.env
func vaultToken() (string, error) {
	if t := os.Getenv("VAULT_TOKEN"); t != "" {
		return t, nil
	}
	home, _ := os.UserHomeDir()
	f, err := os.Open(home + "/.hermes/.env")
	if err != nil {
		return "", fmt.Errorf("VAULT_TOKEN not set and ~/.hermes/.env unreadable: %w", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "VAULT_TOKEN=") {
			v := strings.TrimPrefix(line, "VAULT_TOKEN=")
			v = strings.Trim(v, `"'`)
			return v, nil
		}
	}
	return "", fmt.Errorf("VAULT_TOKEN not found in ~/.hermes/.env")
}

func vaultKVPrefix() string {
	return envOrDotfile("VAULT_KV_PREFIX", "agents/app")
}

// vaultSecret reads <prefix>/<name> via Vault's KV v2 HTTP API.
func vaultSecret(name string) (map[string]string, error) {
	token, err := vaultToken()
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("%s/v1/kv/data/%s/%s", vaultAddr, vaultKVPrefix(), name)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("X-Vault-Token", token)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("vault GET %s: status %d: %s", url, resp.StatusCode, string(body))
	}
	var parsed struct {
		Data struct {
			Data map[string]string `json:"data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, err
	}
	return parsed.Data.Data, nil
}

type PGConfig struct {
	Host, Port, DBName, User, Password string
}

func pgConfig() (PGConfig, error) {
	s, err := vaultSecret("postgres")
	if err != nil {
		return PGConfig{}, err
	}
	host := s["host"]
	if host == "" {
		host = "127.0.0.1"
	}
	port := s["port"]
	if port == "" {
		port = "5433"
	}
	db := s["dbname"]
	if db == "" {
		db = "yshtola"
	}
	user := s["user"]
	if user == "" {
		user = "yshtola"
	}
	return PGConfig{Host: host, Port: port, DBName: db, User: user, Password: s["password"]}, nil
}

func (c PGConfig) DSN() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s", c.User, c.Password, c.Host, c.Port, c.DBName)
}

func etherscanAPIKey() (string, error) {
	s, err := vaultSecret("etherscan")
	if err != nil {
		return "", err
	}
	k := s["api_key"]
	if k == "" {
		return "", fmt.Errorf("etherscan api_key empty in vault")
	}
	return k, nil
}

// small helper used by main.go
func mustAtoi(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}
