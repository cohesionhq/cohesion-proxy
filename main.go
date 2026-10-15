// Command cohesion-proxy registers itself with a cohesiond as a mutual-TLS
// client, then serves cohesiond's /command and /connect endpoints over plain
// HTTP to callers holding a token it issued.
//
// This deliberately widens cohesiond's security boundary: anyone with a token
// acts as this proxy's registered client.
package main

import (
	"flag"
	"fmt"
	"os"
)

const usage = `usage: cohesion-proxy [-config DIR] <command> [args]

commands:
  setup [-name NAME] <setup-code>   register with cohesiond using its setup code
  serve [-listen ADDR]              proxy /command and /connect over HTTP
  client issue <name>               add a client and print its token (shown once)
  client list                       list clients
  client revoke <name>              remove a client

-config defaults to $XDG_CONFIG_HOME/cohesion-proxy (or ~/.config/cohesion-proxy).
`

func main() {
	global := flag.NewFlagSet("cohesion-proxy", flag.ExitOnError)
	global.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	configDir := global.String("config", "", "config directory")
	global.Parse(os.Args[1:])

	args := global.Args()
	if len(args) == 0 {
		global.Usage()
		os.Exit(2)
	}
	store, err := openStore(*configDir)
	if err != nil {
		fail(err)
	}

	switch args[0] {
	case "setup":
		err = runSetup(store, args[1:])
	case "serve":
		err = runServe(store, args[1:])
	case "client":
		err = runClient(store, args[1:])
	default:
		global.Usage()
		os.Exit(2)
	}
	if err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "cohesion-proxy:", err)
	os.Exit(1)
}
