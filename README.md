# oauth

OAuth 2.0 / OpenID Connect client library for Beamtalk, wrapping the
OpenID-certified [`oidcc`](https://github.com/erlef/oidcc) engine.
Authorization code + PKCE for native apps (loopback redirect), refresh,
userinfo and revocation; GitLab and Google presets first.

Status: design accepted, implementation in progress. See
[ADR 0001](docs/ADR/0001-beamtalk-native-oauth-client.md).

## Building

```bash
just build
```

## Testing

```bash
just test
```
