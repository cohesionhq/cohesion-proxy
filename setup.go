package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// SetupCode is what cohesiond prints at start: base64("<key>|<ip>|<fingerprint>").
type SetupCode struct {
	Key         string
	IP          net.IP
	Fingerprint string
}

func decodeSetupCode(code string) (SetupCode, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(code))
	if err != nil {
		return SetupCode{}, errors.New("setup code is not base64")
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != 3 {
		return SetupCode{}, errors.New("malformed setup code")
	}
	ip := net.ParseIP(parts[1])
	if ip == nil {
		return SetupCode{}, fmt.Errorf("setup code has an invalid IP %q", parts[1])
	}
	return SetupCode{Key: parts[0], IP: ip, Fingerprint: parts[2]}, nil
}

func runSetup(store *Store, args []string) error {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	name := fs.String("name", "", "how cohesiond lists this client (default: cohesion-proxy on <hostname>)")
	fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("usage: cohesion-proxy setup [-name NAME] <setup-code>")
	}
	code, err := decodeSetupCode(fs.Arg(0))
	if err != nil {
		return err
	}
	if *name == "" {
		host, _ := os.Hostname()
		*name = "cohesion-proxy on " + host
	}

	identity, err := newIdentityPEM(*name)
	if err != nil {
		return fmt.Errorf("cannot create identity: %w", err)
	}
	server := Server{IP: code.IP.String(), Fingerprint: code.Fingerprint}
	upstream, err := newUpstream(server, identity)
	if err != nil {
		return err
	}
	client, err := upstream.register(code.Key, *name)
	if err != nil {
		return err
	}

	// Saved only once cohesiond trusts the identity.
	if err := store.SaveIdentity(identity); err != nil {
		return err
	}
	if err := store.SaveServer(server); err != nil {
		return err
	}
	fmt.Printf("Registered as %q (client %d) with cohesiond at %s; configuration saved to %s.\n",
		client.ClientName, client.ID, upstream.base, store.dir)
	return nil
}

type registeredClient struct {
	ID         int64  `json:"id"`
	ClientName string `json:"client_name"`
}

// register asks cohesiond to trust this identity's key, over plain HTTPS: its
// session routes refuse a client until it is registered.
func (u *Upstream) register(setupKey, name string) (registeredClient, error) {
	body, _ := json.Marshal(map[string]string{"setup_key": setupKey, "client_name": name})
	http := &http.Client{Transport: u.http.Transport, Timeout: 15 * time.Second}
	res, err := http.Post(u.base+"/register", "application/json", bytes.NewReader(body))
	if err != nil {
		return registeredClient{}, fmt.Errorf("cannot reach cohesiond at %s: %w", u.base, err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return registeredClient{}, fmt.Errorf("cohesiond answered /register with %s", res.Status)
	}

	// A reply frame: {"seq":0,"type":"reply","id":null,"ok":{"type":"client","data":{...}}}
	// or {..., "error":{...}}.
	var frame struct {
		Ok *struct {
			Data registeredClient `json:"data"`
		} `json:"ok"`
		Error *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(res.Body).Decode(&frame); err != nil {
		return registeredClient{}, fmt.Errorf("unexpected /register response: %w", err)
	}
	if frame.Error != nil {
		return registeredClient{}, fmt.Errorf("cohesiond refused registration: %s", frame.Error.Message)
	}
	if frame.Ok == nil {
		return registeredClient{}, errors.New("unexpected /register response: no outcome")
	}
	return frame.Ok.Data, nil
}
