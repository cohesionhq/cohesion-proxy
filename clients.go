package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Clients is clients.db: everyone allowed through the proxy, each with a
// token. Only a token's hash is kept, so the plaintext is shown once, when
// issued.
type Clients struct {
	db *sql.DB
}

// Client is one row of clients.db.
type Client struct {
	ID       int64
	Name     string
	Created  time.Time
	LastUsed *time.Time
}

const tokenPrefix = "cxp_"

// Each entry runs once, in order, tracked by PRAGMA user_version. Append; never edit.
var migrations = []string{
	`CREATE TABLE clients (
		id INTEGER PRIMARY KEY,
		name TEXT NOT NULL UNIQUE,
		token_sha256 TEXT NOT NULL UNIQUE,
		created_at INTEGER NOT NULL,
		last_used_at INTEGER
	)`,
}

func (s *Store) OpenClients() (*Clients, error) {
	db, err := sql.Open("sqlite", "file:"+s.path("clients.db")+
		"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("cannot open clients.db: %w", err)
	}
	return &Clients{db: db}, nil
}

func migrate(db *sql.DB) error {
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	for i := version; i < len(migrations); i++ {
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[i]); err != nil {
			tx.Rollback()
			return err
		}
		if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, i+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func (c *Clients) Close() error { return c.db.Close() }

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Issue adds a client and returns its token.
func (c *Clients) Issue(name string) (string, error) {
	token := tokenPrefix + rand.Text()
	_, err := c.db.Exec(`INSERT INTO clients (name, token_sha256, created_at) VALUES (?, ?, ?)`,
		name, hashToken(token), time.Now().Unix())
	if err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed: clients.name") {
		return "", fmt.Errorf("a client named %q already exists; revoke it first", name)
	}
	return token, err
}

func (c *Clients) List() ([]Client, error) {
	rows, err := c.db.Query(`SELECT id, name, created_at, last_used_at FROM clients ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var clients []Client
	for rows.Next() {
		var client Client
		var created int64
		var lastUsed sql.NullInt64
		if err := rows.Scan(&client.ID, &client.Name, &created, &lastUsed); err != nil {
			return nil, err
		}
		client.Created = time.Unix(created, 0)
		if lastUsed.Valid {
			t := time.Unix(lastUsed.Int64, 0)
			client.LastUsed = &t
		}
		clients = append(clients, client)
	}
	return clients, rows.Err()
}

func (c *Clients) Revoke(name string) error {
	res, err := c.db.Exec(`DELETE FROM clients WHERE name = ?`, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("no client named %q", name)
	}
	return nil
}

// Authenticate returns the name of the client holding token and records its
// use, or "" for an unknown token.
func (c *Clients) Authenticate(token string) (string, error) {
	var name string
	err := c.db.QueryRow(`UPDATE clients SET last_used_at = ? WHERE token_sha256 = ? RETURNING name`,
		time.Now().Unix(), hashToken(token)).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return name, err
}

func runClient(store *Store, args []string) error {
	const usage = "usage: cohesion-proxy client <issue NAME | list | revoke NAME>"
	if len(args) == 0 {
		return errors.New(usage)
	}
	clients, err := store.OpenClients()
	if err != nil {
		return err
	}
	defer clients.Close()

	switch {
	case args[0] == "issue" && len(args) == 2:
		token, err := clients.Issue(args[1])
		if err != nil {
			return err
		}
		fmt.Println(token)
		return nil
	case args[0] == "list" && len(args) == 1:
		list, err := clients.List()
		if err != nil {
			return err
		}
		for _, client := range list {
			lastUsed := "never"
			if client.LastUsed != nil {
				lastUsed = client.LastUsed.Format(time.RFC3339)
			}
			fmt.Printf("%s\tcreated %s\tlast used %s\n", client.Name, client.Created.Format(time.RFC3339), lastUsed)
		}
		return nil
	case args[0] == "revoke" && len(args) == 2:
		return clients.Revoke(args[1])
	}
	return errors.New(usage)
}

// requireClient admits requests whose Authorization header carries a client's
// token as "Bearer <token>". Each request is checked against clients.db, so
// issuing or revoking a client takes effect without restarting the server.
func requireClient(clients *Clients, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		presented, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || presented == "" {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		name, err := clients.Authenticate(presented)
		if err != nil {
			logf("cannot check token: %v", err)
			http.Error(w, "cannot check token", http.StatusInternalServerError)
			return
		}
		if name == "" {
			logf("rejected token for %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		logf("%s %s %s from %s", name, r.Method, r.URL.Path, r.RemoteAddr)
		next.ServeHTTP(w, r)
	})
}
