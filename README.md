# cohesion-proxy

Registers with a [Cohesion](https://github.com/cohesionhq/cohesion) daemon as a
mutual-TLS client, then serves cohesiond's `/command` and `/connect` (WebSocket)
endpoints over plain HTTP to clients holding a token it issued.

This intentionally widens cohesiond's security boundary: every client with a
token acts as the proxy's single registered cohesiond client.

```sh
go build -o cohesion-proxy .
./cohesion-proxy setup <setup-code>        # the code cohesiond prints at start
./cohesion-proxy client issue my-laptop    # prints a token once
./cohesion-proxy serve -listen 127.0.0.1:8080
```

Clients send `Authorization: Bearer <token>` on every request, including the
WebSocket upgrade. `client list` and `client revoke <name>` manage clients;
changes apply without restarting `serve`. An open WebSocket stays open after
its client is revoked.

State lives in `~/.config/cohesion-proxy` (or `$XDG_CONFIG_HOME`, or `-config DIR`):
`identity.pem`, `server.json`, and `clients.db` (SQLite, token hashes only).

## Licence

MIT. See [LICENSE](LICENSE).
