package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Store is the proxy's config directory:
//
//	identity.pem  the client certificate and key presented to cohesiond (0600)
//	server.json   where cohesiond is and its pinned key fingerprint
//	clients.db    SQLite: clients allowed through the proxy and their token hashes
type Store struct {
	dir string
}

// Server is how the proxy reaches cohesiond, taken from the setup code.
type Server struct {
	IP          string `json:"ip"`
	Fingerprint string `json:"server_fingerprint"`
}

var errNotConfigured = errors.New("not set up; run `cohesion-proxy setup <setup-code>` first")

func openStore(dir string) (*Store, error) {
	if dir == "" {
		// ~/.config on macOS too, rather than ~/Library/Application Support.
		base := os.Getenv("XDG_CONFIG_HOME")
		if base == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return nil, fmt.Errorf("no config directory: %w", err)
			}
			base = filepath.Join(home, ".config")
		}
		dir = filepath.Join(base, "cohesion-proxy")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("cannot create %s: %w", dir, err)
	}
	return &Store{dir: dir}, nil
}

func (s *Store) path(name string) string { return filepath.Join(s.dir, name) }

func (s *Store) LoadIdentity() ([]byte, error) {
	return s.read("identity.pem")
}

func (s *Store) SaveIdentity(pem []byte) error {
	return os.WriteFile(s.path("identity.pem"), pem, 0o600)
}

func (s *Store) LoadServer() (Server, error) {
	var server Server
	data, err := s.read("server.json")
	if err != nil {
		return server, err
	}
	err = json.Unmarshal(data, &server)
	return server, err
}

func (s *Store) SaveServer(server Server) error {
	return s.writeJSON("server.json", server, 0o644)
}

func (s *Store) read(name string) ([]byte, error) {
	data, err := os.ReadFile(s.path(name))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errNotConfigured
	}
	return data, err
}

// writeJSON replaces name atomically, so a running server never reads half a file.
func (s *Store) writeJSON(name string, v any, perm os.FileMode) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path(name + ".tmp")
	if err := os.WriteFile(tmp, append(data, '\n'), perm); err != nil {
		return err
	}
	return os.Rename(tmp, s.path(name))
}
