package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"time"

	"github.com/coder/websocket"
)

// The port cohesiond listens on unless started with --port, and the one a
// setup code implies when its address names none.
const defaultPort = 3000

// Largest request body /command forwards.
const maxCommandBody = 32 << 20

// Upstream is the proxy's mutual-TLS connection to cohesiond.
type Upstream struct {
	base string // https://ip:port
	http *http.Client
	// WebSocket upgrades need HTTP/1.1, so they get their own transport.
	ws *http.Client
}

func newUpstream(server Server, identity []byte) (*Upstream, error) {
	httpTLS, err := clientTLS(identity, server.Fingerprint, "h2", "http/1.1")
	if err != nil {
		return nil, err
	}
	wsTLS, err := clientTLS(identity, server.Fingerprint, "http/1.1")
	if err != nil {
		return nil, err
	}
	return &Upstream{
		base: "https://" + net.JoinHostPort(server.IP, strconv.Itoa(server.Port)),
		http: &http.Client{Transport: &http.Transport{
			TLSClientConfig:   httpTLS,
			ForceAttemptHTTP2: true,
		}},
		ws: &http.Client{Transport: &http.Transport{TLSClientConfig: wsTLS}},
	}, nil
}

func runServe(store *Store, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:8080", "address to serve plain HTTP on")
	fs.Parse(args)

	server, err := store.LoadServer()
	if err != nil {
		return err
	}
	identity, err := store.LoadIdentity()
	if err != nil {
		return err
	}
	upstream, err := newUpstream(server, identity)
	if err != nil {
		return err
	}
	clients, err := store.OpenClients()
	if err != nil {
		return err
	}
	defer clients.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /command", upstream.command)
	mux.HandleFunc("GET /connect", upstream.connect)
	srv := &http.Server{
		Addr:              *listen,
		Handler:           requireClient(clients, mux),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdown)
	}()

	logf("proxying cohesiond at %s on http://%s", upstream.base, *listen)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// command forwards a one-off request to cohesiond's /command and relays its
// reply frame as sent.
func (u *Upstream) command(w http.ResponseWriter, r *http.Request) {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, u.base+"/command",
		http.MaxBytesReader(w, r.Body, maxCommandBody))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", r.Header.Get("Content-Type"))
	res, err := u.http.Do(req)
	if err != nil {
		logf("/command: %v", err)
		http.Error(w, fmt.Sprintf("cohesiond unreachable: %v", err), http.StatusBadGateway)
		return
	}
	defer res.Body.Close()
	if ct := res.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(res.StatusCode)
	io.Copy(w, res.Body)
}

// connect opens a session on cohesiond's /connect WebSocket for each client
// WebSocket and relays messages both ways until either side closes.
func (u *Upstream) connect(w http.ResponseWriter, r *http.Request) {
	// Dial first, so a client never gets a socket with nothing behind it.
	upstream, res, err := websocket.Dial(r.Context(), "wss"+u.base[len("https"):]+"/connect",
		&websocket.DialOptions{HTTPClient: u.ws})
	if err != nil {
		if res != nil && res.StatusCode == http.StatusForbidden {
			err = errors.New("cohesiond no longer trusts this proxy; run setup again")
		}
		logf("/connect: %v", err)
		http.Error(w, fmt.Sprintf("cohesiond unreachable: %v", err), http.StatusBadGateway)
		return
	}
	upstream.SetReadLimit(-1)

	// Clients authenticate by token, not origin; non-browser clients send none.
	client, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		upstream.Close(websocket.StatusInternalError, "client upgrade failed")
		return
	}
	client.SetReadLimit(-1)

	// Detached from the request context, which ends once the handler hijacks.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errs := make(chan error, 2)
	go func() { errs <- pipe(ctx, upstream, client) }()
	go func() { errs <- pipe(ctx, client, upstream) }()
	err = <-errs

	// Pass a clean close on to the other side; anything else is a broken session.
	status, reason := websocket.CloseStatus(err), ""
	switch status {
	case websocket.StatusNoStatusRcvd:
		status = websocket.StatusNormalClosure
	case -1:
		status, reason = websocket.StatusGoingAway, "peer disconnected"
	}
	client.Close(status, reason)
	upstream.Close(status, reason)
}

// pipe copies messages from src to dst until src closes or either errors.
func pipe(ctx context.Context, dst, src *websocket.Conn) error {
	for {
		typ, data, err := src.Read(ctx)
		if err != nil {
			return err
		}
		if err := dst.Write(ctx, typ, data); err != nil {
			return err
		}
	}
}

var logger = log.New(os.Stderr, "", log.LstdFlags)

func logf(format string, args ...any) { logger.Printf(format, args...) }
