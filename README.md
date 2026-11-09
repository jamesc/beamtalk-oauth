# oauth

OAuth 2.0 / OpenID Connect client library for Beamtalk, wrapping the
OpenID-certified [`oidcc`](https://github.com/erlef/oidcc) engine.
Authorization code + PKCE for native apps (loopback redirect), refresh,
userinfo, revocation and token info, with GitLab and Google presets.

Identity code is not written here: discovery, JWKS, ID-token validation,
PKCE challenges, client authentication and token-endpoint calls all go
through `oidcc` and `jose`. This package adds the Beamtalk surface
(`Result`s, a structured `OAuthError`, redacting value objects), the
single-use session store, callback handling, the loopback receiver,
provider presets, RFC 7009 revocation and provider token info. Every HTTP
call goes through the `http` package's `HTTPClient`, never `httpc`. The
design is in [ADR 0001](docs/ADR/0001-beamtalk-native-oauth-client.md).

## Requirements

- Erlang/OTP 27 or newer for the library (`oidcc` needs 27). The
  current Beamtalk nightly toolchain itself needs OTP 28, so CI runs 28.
- No Elixir runtime: `oidcc`, `jose` and `telemetry` build with rebar3
  from `[native.dependencies]`.

## Install

Add the dependency to your `beamtalk.toml`:

```toml
[dependencies]
oauth = "0.1.0"
```

Until 0.1.0 is published to the registry, add it from the repository:
`beamtalk deps add oauth --git https://github.com/jamesc/beamtalk-oauth`.
Either way it pulls in `http` and the native `oidcc` dependency.

## Native app quick start

A CLI or desktop app opens the system browser and receives the redirect
on a loopback listener it runs itself (RFC 8252).

- **GitLab**: register a non-confidential application with the `openid`
  scope and the redirect URI `http://127.0.0.1:8765/callback`. GitLab
  accepts a loopback redirect on any port for it, so the receiver's
  OS-assigned port works.
- **Google**: create a "Desktop app" OAuth client. It has no registered
  redirect URI (any loopback port is accepted), but it does get a client
  secret the token endpoint requires, so register it with
  `ClientRegistration forClient: id secret: secret redirect: rx redirectUri`.
  The secret is not confidential in a desktop app; PKCE and the session
  store protect the flow.

```beamtalk
server := (OAuthServer fromPreset: ProviderPresets gitlab) unwrap
rx := LoopbackReceiver start unwrap
reg := (ClientRegistration forClient: "APP_ID" redirect: rx redirectUri) unwrap
store := SessionStore spawn
sess := OAuthSession newSessionFor: server client: reg
store create: sess boundTo: rx binding
rx expectState: sess state                // before the URL is opened
url := (OAuthFlows authorizeUrl: server client: reg scopes: #("openid") session: sess) unwrap
Transcript showCr: url                    // or open the system browser
query := (rx awaitCallback: 300000) unwrap
cb := (OAuthFlows handleCallback: query store: store boundTo: rx binding) unwrap
toks := (OAuthFlows exchangeCode: server client: reg callback: cb store: store) unwrap
toks subject                              // validated by oidcc
(OAuthFlows userInfo: server client: reg tokenSet: toks) unwrap
toks := (OAuthFlows refresh: server client: reg tokenSet: toks) unwrap
(OAuthFlows revoke: server client: reg token: toks) unwrap
store stop
```

Things to know:

- `rx expectState:` must come before the browser gets the URL. The
  receiver records only a `GET /callback` carrying that state, so the
  browser's `/favicon.ico` request or a junk request from a web page
  cannot use up its one slot. It stops listening once `awaitCallback:`
  answers; call `rx stop` yourself if the flow is abandoned earlier
  (`examples/native_login.bt` uses `ensure:`).
- `awaitCallback:` blocks the calling process while the user signs in.
  Call it from a plain or forked process, not inside an actor method.
- `handleCallback:` consumes the session, so a callback works once.
  `exchangeCode:` then spends the single-use ticket in the `Callback`.
- `refresh:` answers a merged `TokenSet`: the old refresh token and ID
  token carry forward when the response omits them. Store the answer.
- `TokenSet` `printString` and `asJson` redact every token. Use
  `toks bearerHeader` for API calls and `toks needsRefresh` to decide when
  to refresh.

A runnable version for gitlab.com is in
[`examples/native_login.bt`](examples/native_login.bt):

```beamtalk
// OAUTH_GITLAB_CLIENT_ID=<application id> beamtalk repl
Workspace load: "examples/native_login.bt"
NativeLogin run
```

For a long-running service, start a `ProviderWorker` (in your supervision
tree) instead of `fromPreset:`/`fromDiscovery:`. It keeps the provider
configuration and JWKS fresh, and `worker server unwrap` answers an
`OAuthServer` for the same calls.

## Server-side web apps

A Beamtalk web app is a confidential client: register a client secret
and an HTTPS redirect URI, and use
`ClientRegistration forClient:secret:redirect:`. The flow is the same,
split across two requests, with one difference: `state` alone does not
stop login CSRF (RFC 6749 §10.12), so the session is bound to the
browser that started it.

1. Login request: make a fresh binding with `Secrets generate`, set it as
   a cookie, then `store create: sess boundTo: binding` and redirect to
   `authorizeUrl`.
2. Callback request: read the cookie back and call
   `OAuthFlows handleCallback: rawQuery store: store boundTo: cookieValue`.

The cookie should be `HttpOnly; Secure; SameSite=Lax;
Path=<callback path>; Max-Age=600`. Use `SameSite=Lax`, not `Strict`: the
callback is a cross-site top-level GET from the provider, and `Strict`
would withhold the cookie. An existing app session id also works as the
binding; a constant does not. Pass the raw query string to
`handleCallback:` where the framework offers it, so a duplicated
parameter is caught. The library never sets or reads cookies itself.

A callback presented with another binding answers `session_mismatch` and
burns the session, so it cannot be retried. Show the user one generic
failure and log the specific code.

## Providers

`ProviderPresets gitlab` and `ProviderPresets google` are data: the
issuer, default scopes, extra authorize parameters, the revocation and
token-info endpoints, and corrections to the provider's discovery
document.

- **GitLab** (gitlab.com, or self-hosted with
  `OAuthServer fromDiscovery: "https://gitlab.example" preset: ProviderPresets gitlab`):
  the preset adds the `none` client auth method GitLab supports but does
  not advertise, which public native clients need.
- **Google**: adds `access_type=offline` and `prompt=consent` so a refresh
  token is issued.

Any other OpenID provider works with `OAuthServer fromDiscovery: issuer`.

## Errors

Failures answer `Result error:` an `OAuthError` with a `code`, a
`description`, an HTTP `status` when there was one, and a `detail` with
secrets redacted. Programming mistakes (an empty binding, say) raise
instead.

| Code | Meaning |
|------|---------|
| provider codes, verbatim | `invalid_grant`, `invalid_client`, `access_denied`, `login_required`, ... |
| `provider_error` | the callback carried an unregistered error code (in `detail`) |
| `oidcc` reasons | `missing_claim`, `token_expired`, `sub_invalid`, `no_supported_auth_method`, `no_supported_code_challenge`, ... |
| `transport` | the request failed (connect, TLS, timeout), or revocation / token info got an error answer that is not JSON |
| `http_error` | the provider answered an error status whose body has no `error` member |
| `oidcc_crash` | `oidcc` raised on a malformed provider answer |
| `bad_subject` | the userinfo `sub` is not the ID token's subject |
| `parse` | a malformed response or callback |
| `config` | invalid configuration or a token set missing what the call needs |
| `insecure_endpoint` | a plain-HTTP endpoint or a non-loopback `http` redirect URI |
| `session_mismatch` | wrong binding; a session for another issuer or redirect URI; tokens issued to another client |
| `reused_state` | the session or callback ticket was already used, or is unknown to this store |
| `expired_session` | the session or callback ticket outlived its TTL (10 minutes by default) |
| `issuer_mismatch` | a callback `iss` or the tokens' issuer is not the expected one |
| `missing_id_token` | the token response had no ID token |
| `no_userinfo_endpoint` | the provider has no userinfo endpoint |
| `callback_timeout` | no matching callback reached the `LoopbackReceiver` in time |

## Supported and not

Supported in 0.1:

- authorization code with PKCE (always required, S256 only), for native
  apps on a loopback redirect and for server-side web apps;
- ID-token validation by `oidcc` on every login and refresh;
- refresh, userinfo, RFC 7009 revocation, provider token info;
- discovery with `fromDiscovery:`, or a supervised `ProviderWorker`;
- GitLab and Google presets.

Planned: client credentials and GitHub (0.2); `private_key_jwt`,
RP-initiated logout and introspection (0.3).

Not supported, by design:

- **The device authorization grant (RFC 8628).** Device-code phishing is
  a well-documented attack: the attacker starts a flow and persuades the
  victim to enter the user code, then receives the victim's tokens.
  Identity platforms let administrators block the flow for this reason.
  A general-purpose login library should not hand that capability to
  every app built on it. Headless users (SSH, containers) should use the
  provider's personal access tokens.
- Implicit and hybrid flows, server-side token issuing, CIBA, and FAPI
  certification.
- Plain-HTTP providers. `#allowUnsafeHttp` exists only for this package's
  tests and also needs a test-only application flag.

## Development

```bash
just build    # compile
just test     # BUnit suite, against a local fixture provider
just ci       # fmt + lint + build + test
```

The suite never touches the network, and a guard fails it if anything
calls `httpc`. `test/e2e_native_login_test.bt` runs a whole native login
against the fixture provider: a real `LoopbackReceiver`, a browser hop
followed with `HTTPClient` (plus the stray `/favicon.ico`), then the
exchange, userinfo, token info, refresh and revoke.

### Live GitLab test

`test/live_gitlab_test.bt` signs in to gitlab.com for real. It is skipped
unless `OAUTH_LIVE_GITLAB_CLIENT_ID` is set, and it needs a person at a
browser on the same machine. Register a non-confidential GitLab
application with the `openid` scope and the redirect URI
`http://127.0.0.1:8765/callback`, then:

```bash
OAUTH_LIVE_GITLAB_CLIENT_ID=<application id> beamtalk test test/live_gitlab_test.bt
```

The test opens the authorize URL with `open` (macOS) or `xdg-open`
(override with `OAUTH_LIVE_BROWSER`) and writes it to
`_build/live_gitlab_authorize_url.txt`. Sign in within five minutes
(`OAUTH_LIVE_TIMEOUT_MS` changes that). It exchanges the code, checks
userinfo, refreshes and revokes. No token is printed.

## License

Apache-2.0. See [LICENSE](LICENSE).
