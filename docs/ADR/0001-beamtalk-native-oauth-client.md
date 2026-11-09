# ADR 0001: OAuth 2.0 / OIDC client library over `oidcc` (`beamtalk-oauth`)

## Status
Accepted (2026-11-09). Revised the same day from an earlier "Accepted"
hand-rolled design: an ADR review found `oidcc`, which the original
survey missed, and the author chose to wrap it rather than write
identity code. Re-accepted after Phase 0 (see Implementation) confirmed
the build, the HTTP adapter and a live GitLab login.

## Context

Beamtalk applications need to sign users in with third-party providers.
The first driver is GitLab (authorization code + PKCE, refresh tokens,
revocation); Google and GitHub follow. Anthropic is
explicitly out of scope: it offers no third-party login, and its
supported path is bring-your-own-key.

Hex survey (revised after review):

- `oidcc` (Erlang Ecosystem Foundation, Apache-2.0; 3.9.2 released
  2026-11-03; OpenID-certified at 3.0.0 for Basic, Config, Form Post,
  3rd-Party-Init and RP-Initiated Logout RP; security-audited, funded by
  the EEF Security WG) is a pure-Erlang OIDC relying-party library:
  discovery, provider-configuration and JWKS refresh worker,
  authorization URL with PKCE, token retrieval, refresh, client
  credentials, JWT bearer, userinfo, ID-token validation, introspection
  (RFC 7662), all client-auth methods including `private_key_jwt`, PAR,
  JAR/JARM, DPoP, logout. It has **no device flow (RFC 8628) and no
  revocation (RFC 7009)**. It builds with rebar3 alone; the `lib/*.ex`
  Elixir wrappers in its Hex tarball are ignored by rebar3. Minimum
  OTP 27. Runtime deps: `jose`, `telemetry` (+ `telemetry_registry` at
  build time); OTP apps `inets`, `ssl`, `public_key`.
- `jose` (MIT; 1.11.13 released 2026-10-26 with a batch of security
  fixes; maintenance resumed after a dormant period) provides JWKS, JWS
  and JWT. No non-OTP runtime deps; selects OTP's `json` module when
  Elixir is absent.
- Assent has full client-side PKCE and a GitLab OIDC strategy, but it is
  Elixir and requires the Elixir `~> 1.18` runtime.
- Elixir `oauth2` passes extra params through but has no PKCE helper.
- `p1_oauth2` is server-side only (verified in source).
- `oauth2c` (kivra `oauth2_client`, 2018) covers client-credentials and
  refresh only, with no PKCE or authorization code (verified in source).

Constraints on the solution space:

1. Wrapper policy is Erlang-only. No Elixir dependencies, so Assent and
   the Elixir `oauth2` library are excluded regardless of merit.
2. Wrapping Hex Erlang packages is an established path:
   `[native.dependencies]` plus a `native/` Erlang shim, built by the
   bundled rebar3 (language ADR 0072). Precedent: `beamtalk-yaml` wraps
   `yamerl` this way. Beamtalk already requires OTP 27+.
3. Building blocks: stdlib `Binary` (base64url; padding stripped via
   `replaceAll:with:`), the `http` package's `HTTPClient`, OTP `:crypto`
   via the `Erlang` FFI (`crypto:strong_rand_bytes/1` returns a
   `Binary`; stdlib `Random` is a PRNG and unsuitable for secrets), and
   the ok/error-to-`Result` FFI conversion (language ADR 0076).
4. Package conventions are fixed: repo `beamtalk-oauth`, `beamtalk.toml`,
   `src/` one class per `.bt` file, `test/` BUnit `*_test.bt`, `Justfile`,
   `AGENTS.md`.

## Decision

Build `beamtalk-oauth` as a Beamtalk-idiomatic surface over `oidcc`.
**We do not write identity code**: discovery and issuer validation,
JWKS handling, ID-token validation, PKCE challenge computation, client
authentication and token-endpoint calls for OIDC providers all go
through `oidcc` and `jose`. Beamtalk code owns what `oidcc` deliberately
leaves to the caller or does not cover:

- the value-object surface (`Result`, `OAuthError`, redacting
  `TokenSet`), per language ADRs 0060, 0015 and 0076;
- generating `state`, `nonce` and the PKCE verifier (CSPRNG), and the
  `SessionStore` that holds them single-use;
- callback parsing and error mapping;
- provider presets;
- the HTTP transport: an `oidcc_http_adapter` over the `http` package's
  `HTTPClient` (Mint), so every outbound call shares one TLS, redirect,
  body-cap and proxy configuration;
- provider-specific calls with no standard: `tokenInfo`, and GitHub
  (0.2).

Revocation (RFC 7009), the one standard protocol we need that `oidcc`
lacks, is **Beamtalk-owned for now**: a form POST of `token` and
`token_type_hint` to the discovered `revocation_endpoint` over
`HTTPClient`. Public clients send `client_id`; confidential clients use
`client_secret_basic` or `client_secret_post`, whichever the provider
advertises. A 200 with any body (or none) is success, including for an
already-invalid token (RFC 7009 §2.2); anything else maps to
`OAuthError`. This keeps 0.1 on a Hex release of `oidcc`. A tested
`oidcc` implementation exists on a fork branch (see Implementation);
once upstream releases revocation (`erlef/oidcc` #252, labelled
`certification`), the Beamtalk version is replaced by a shim call.

OIDC providers (GitLab, Google) always request the `openid` scope.
`oidcc` validates every ID token, so `idToken` and `nonce` exist from
0.1 instead of waiting for a hand-rolled 0.3 validator. This also
satisfies `oidcc`'s refresh, which requires an ID token whose `sub`
matches the original.

Recorded sub-decisions:

- The session store is **explicit**: the app creates and wires a
  `SessionStore` Actor. No implicit global state.
- The repo is **`beamtalk-oauth`** and the package is **`oauth`**,
  following the established convention (repo `beamtalk-http` ships
  manifest `name = "http"`; module naming per language ADRs 0016/0070).
  Confirmed 2026-11-09.
- `tokenInfo` is **generalized** across presets with a normalized result
  shape, not GitLab-only. Confirmed 2026-11-09. (It is provider-specific
  HTTP, not RFC 7662: none of the three providers offers standard
  introspection to clients.)
- **Wrap `oidcc`; do not hand-roll identity code.** Author decision,
  2026-11-09.

### Layering

```text
Beamtalk surface   OAuthFlows, OAuthServer, ClientRegistration, OAuthSession,
                   TokenSet, OAuthError, SessionStore, ProviderPresets
        │
native shim        native/beamtalk_oauth_oidcc.erl: Beamtalk values <-> oidcc
                   records/maps, forces require_pkce, maps {error, _} terms
        │
oidcc + jose       discovery, JWKS, ID-token validation, token endpoint,
(Hex 3.9.2)        userinfo, client auth
        │
native adapter     native/beamtalk_oauth_http_adapter.erl: oidcc_http_adapter
                   behaviour; sends request:url:options: to the HTTPClient
                   class object passed in its config
        │
http / mint        HTTPClient over Mint: TLS verify, no redirects,
                   #maxBodyBytes, proxy (once added upstream)

Beamtalk-owned     tokenInfo (per preset), GitHub in 0.2: directly on
                   HTTPClient (no identity validation involved)
```

### Class model

```beamtalk
// Provider metadata. Wraps an oidcc client context (provider
// configuration + JWKS). Two constructors:
//  - fromDiscovery: one-shot load, for REPL and scripts;
//  - a ProviderWorker (below) for long-running services, which keeps
//    configuration and JWKS refreshed (JWKS rotation matters now that
//    ID tokens are validated from 0.1).
// Non-OIDC endpoints oidcc does not model (revocation,
// token-info) come from discovery metadata or the preset.
typed Value subclass: OAuthServer
  field: issuer :: String = ""
  field: context = nil   // opaque oidcc client context, never printed
  field: revocationEndpoint :: String | Nil = nil
  field: tokenInfoEndpoint :: String | Nil = nil

  class fromDiscovery: issuer :: String -> Result(OAuthServer, OAuthError) => ...
```

```beamtalk
// Supervised oidcc_provider_configuration_worker, owned by the app's
// supervision tree (explicit, like SessionStore). oidcc itself starts
// no processes.
Actor subclass: ProviderWorker native: beamtalk_oauth_provider_worker
  server -> Result(OAuthServer, OAuthError) => ...
```

```beamtalk
// Our side of the relationship. No "no secret <=> #none" invariant:
// Google desktop clients send a non-confidential secret. oidcc picks
// the auth method from the provider's advertised
// token_endpoint_auth_methods_supported and what the registration holds.
typed Value subclass: ClientRegistration
  field: clientId :: String = ""
  field: clientSecret :: String | Nil = nil
  field: redirectUri :: String = ""

  class forClient: id redirect: uri -> Result(ClientRegistration, OAuthError) =>
    // new: map form keeps clientSecret at its default; the keyword
    // constructor would require every slot
    Result ok: (ClientRegistration new: #{#clientId => id, #redirectUri => uri})
```

```beamtalk
// One flow attempt. Built by newSession, persisted through SessionStore,
// passed to authorizeUrl, then single-use consumed before exchangeCode.
// Records issuer and redirect URI so exchangeCode can refuse a session
// minted for a different provider or callback (mix-up defense).
typed Value subclass: OAuthSession
  field: state :: String = ""
  field: nonce :: String = ""
  field: codeVerifier :: String = ""
  field: issuer :: String = ""
  field: redirectUri :: String = ""
  field: createdAt :: Integer = 0

  class newSessionFor: server :: OAuthServer client: reg :: ClientRegistration -> OAuthSession =>
    OAuthSession new: #{
      #state => Secrets generate,
      #nonce => Secrets generate,
      #codeVerifier => Secrets generate,
      #issuer => server issuer,
      #redirectUri => reg redirectUri
    }
    // createdAt: stamped by SessionStore create:boundTo: (Open Question 8)
```

```beamtalk
// The only randomness this library produces. oidcc computes the S256
// challenge from our verifier; it does not generate secrets for callers.
Object subclass: Secrets
  class generate -> String =>
    // 32 CSPRNG bytes -> 43-char base64url. asBase64Url pads to 44 chars
    // with '=', which is outside RFC 7636's unreserved charset, so the
    // padding MUST be stripped.
    (Erlang crypto strong_rand_bytes: 32) asBase64Url replaceAll: "=" with: ""
```

```beamtalk
// Tokens plus lifecycle. printString AND asJson redact secrets.
// idToken holds claims oidcc has already validated; the raw JWT is kept
// only for logout's id_token_hint.
typed Value subclass: TokenSet
  field: accessToken :: String = ""
  field: tokenType :: String = "bearer"
  field: expiresIn :: Integer | Nil = nil
  field: obtainedAt :: Integer = 0
  field: refreshToken :: String | Nil = nil
  field: scope :: String | Nil = nil
  field: idTokenClaims :: Dictionary | Nil = nil
  field: idToken :: String | Nil = nil

  isExpired -> Boolean => ...
  needsRefresh -> Boolean => ...
  bearerHeader -> String => "Bearer " ++ self.accessToken
  subject -> String | Nil => self.idTokenClaims ifNotNil: [:c | c at: "sub" ifAbsent: [nil]]
```

```beamtalk
// Grant operations. OIDC paths delegate to oidcc through the shim;
// revoke and tokenInfo are Beamtalk-owned on HTTPClient: they delegate
// to TokenRevocation (BT-4563).
Object subclass: OAuthFlows
  class authorizeUrl: server client: reg scopes: scopes session: sess -> Result(String, OAuthError) => ...
    // oidcc_authorization:create_redirect_url with state, nonce,
    // pkce_verifier and require_pkce => true (always: oidcc otherwise
    // silently omits PKCE when the provider does not advertise
    // code_challenge_methods_supported)
  class authorizeUrl: server client: reg scopes: scopes session: sess extraParams: dict -> Result(String, OAuthError) => ...
    // e.g. Google access_type=offline, prompt=consent (from the preset)
  class handleCallback: query :: Dictionary store: store boundTo: binding :: String -> Result(Callback, OAuthError) => ...
    // parses code/state/error/error_description/iss, rejects missing or
    // duplicate params, consumes the session with the user-agent binding
    // (see "Login CSRF" below)
  class exchangeCode: server client: reg callback: cb store: store -> Result(TokenSet, OAuthError) => ...
    // oidcc_token:retrieve; asserts the session's issuer and redirect URI
    // match server and reg; nonce and ID token checked by oidcc
  class completeLoopbackLogin: rx server: server client: reg store: store timeout: ms -> Result(TokenSet, OAuthError) => ...
    // the native-login helper: rx awaitCallback, handleCallback,
    // exchangeCode in a loop that re-arms after a forged callback (see
    // "Forged loopback callbacks: re-arm"). maxRearms: variant; default 3
  class refresh: server client: reg tokenSet: toks -> Result(TokenSet, OAuthError) => ...
    // oidcc_token:refresh with expected_subject from toks. Answers a
    // merged TokenSet: response values win, and the old refreshToken
    // carries forward when the response omits one (Google usually does).
  class clientCredentials: server client: reg scopes: scopes -> Result(TokenSet, OAuthError) => ...
    // 0.2
  class userInfo: server tokenSet: toks -> Result(Dictionary, OAuthError) => ...
  class revoke: server client: reg token: tok -> Result(Nil, OAuthError) => ...
    // RFC 7009 on HTTPClient (oidcc has none yet); sends
    // token_type_hint; 200 for an unknown token is success
  class tokenInfo: server client: reg token: tok -> Result(Dictionary, OAuthError) => ...
    // Normalized #{active, subject, scopes, expiresIn}; per-preset
    // endpoint and field mapping (GitLab GET /oauth/token/info, Google
    // GET tokeninfo).
```

```beamtalk
// Provider presets are data: issuer, scopes, default authorize params,
// the endpoints discovery omits, and oidcc document overrides (passed as
// quirks => #{document_overrides => ...}; a top-level key is silently
// ignored) for metadata the provider gets wrong. GitLab (checked against
// gitlab.com discovery, 2026-11-09) needs one:
// token_endpoint_auth_methods_supported lists only
// client_secret_basic/client_secret_post, so a public native client (no
// secret) fails with no_supported_auth_method unless the preset adds
// "none". Verified with a live login in Phase 0. (GitLab also supports
// the device code grant without advertising its endpoint; this library
// does not offer that flow, see "Non-goals".)
// 0.1: gitlab, google (both OIDC). github arrives in 0.2 on a separate
// plain-OAuth path (Open Question 5).
Object subclass: ProviderPresets
  class gitlab -> Dictionary => ...
  class google -> Dictionary => ...
```

```beamtalk
// Holds in-flight sessions single-use, each bound to the user agent that
// started it. Sessions expire after 10 minutes by default (policy,
// configurable; RFC 6749 §4.1.2's 10-minute maximum is for authorization
// codes, not state), enforced in consume:, with a periodic sweep so
// abandoned attempts cannot accumulate. Sessions live in a private ETS
// table the actor owns (Beamtalk actors have no format_status hook), so
// crash reports and sys:get_state never show verifiers or bindings.
Actor subclass: SessionStore
  state: table = nil   // private ETS table, created in initialize

  create: sess :: OAuthSession boundTo: binding :: String -> Result(OAuthSession, OAuthError) => ...
    // refuses with "session_store_full" once #maxSessions are held (BT-4568)
  consume: state :: String boundTo: binding :: String -> Result(OAuthSession, OAuthError) => ...
    // single-use: second consume fails with "reused_state";
    // consume past TTL fails with "expired_session";
    // binding differs from the one given at create: (compared with
    // crypto:hash_equals/2, constant time) fails with "session_mismatch"
    // and still burns the session, so a probed state cannot be retried
```

#### Login CSRF: user-agent binding

The primary consumers are native apps (CLI and desktop, RFC 8252):
the app opens the system browser and receives the callback on a
loopback listener it runs itself. Browser-hosted apps cannot embed an
Erlang runtime, so the only web case is a Beamtalk server-side app
acting as a confidential client.

`state` alone does not stop login CSRF (RFC 6749 §10.12) in a shared
store: an attacker can start a login, approve it with their own account,
and send the victim the callback URL, which the victim's browser then
completes. So the binding is mandatory: there is no
`create:`/`consume:` without `boundTo:`, and an empty binding is a
programming error (raises).

The binding is an opaque value tied to whoever started the flow:

- **Native apps (primary)**: a per-flow `Secrets generate` value held in
  memory by the process that runs the loopback listener. Here the store
  is already private to one user's app instance, so the attacker's
  session can never be in it; the binding costs one argument and keeps
  the API identical for both cases.
- **Server-side web apps**: a fresh `Secrets generate` value set as a
  cookie when the login starts, `HttpOnly; Secure; SameSite=Lax;
  Path=<callback path>; Max-Age=600`, read back on the callback.
  `SameSite=Lax`, not `Strict`: the callback is a cross-site top-level
  GET from the provider, and `Strict` would withhold the cookie. An
  existing app session id also works.

The library does not set or read cookies; it stays framework-agnostic.
The store keeps the binding, not the session value, so `OAuthSession`
remains plain data.

Considered and not chosen: a sealed-cookie store (state, nonce and
verifier encrypted into the cookie, no server state). It would also fix
multi-node deployments, but it means this library owns AEAD encryption
and key rotation, assumes it controls cookies, and does nothing for the
native apps that are the main audience. It can be added later as a
second store behind the same `create:boundTo:` / `consume:boundTo:`
protocol if a multi-node web deployment needs it.

```beamtalk
// One-shot loopback callback listener for native apps (RFC 8252 §7.3),
// on the http package's HTTPServer: binds 127.0.0.1 on an OS-assigned
// port, accepts exactly one request on /callback, answers a static
// "you can close this tab" page (no provider data echoed), then stops.
// It owns the per-flow binding, so native apps never see one.
// A Value handle, not an Actor: an actor's methods run in the actor, so
// awaitCallback: could only wait inside a 5s sync call. The one-shot
// state lives in an internal LoopbackGate actor (BT-4560), which the
// server's block handler forwards each request to with its raw query.
Value subclass: LoopbackReceiver
  class start -> Result(LoopbackReceiver, OAuthError) => ...
    // The gate monitors the owner (the starter until awaitCallback:
    // begins, then the waiter) and stops the listener if it crashes, so
    // a port is never left open with no one to read it. A receiver no
    // one awaits stops after a lifetime (10 min; startWithLifetime:)
    // (BT-4570).
  redirectUri -> String => ...      // "http://127.0.0.1:{port}/callback"
  binding -> String => ...
  expectState: expected :: String -> LoopbackReceiver => ...
    // the flow's state (sess state), set BEFORE the authorize URL is
    // opened. Only a /callback whose state matches (constant time) is
    // recorded; a missing, wrong or repeated state, or a repeated
    // code/error/iss (RFC 6749 §3.1), answers 404 and leaves the slot
    // open, so a junk request from a web page or a local port scan
    // cannot use it up (BT-4569). A setter, not awaitCallback:state:,
    // because the redirect can beat the await. One flow per receiver:
    // a second expectState: raises. A timeout reports how many
    // callbacks were refused. State is visible to local processes
    // (browser argv, history), so one that reads it can still take the
    // slot with a junk code; it cannot get that code accepted, and the
    // flow re-arms (BT-4572, "Forged loopback callbacks: re-arm").
  awaitCallback: timeoutMs :: Integer -> Result(Dictionary, OAuthError) => ...
    // the raw query, for handleCallback:store:boundTo:. Waits in the
    // caller's process for a message from the handler, NOT a sync actor
    // call: the user may take minutes, and actor calls time out at 5s.
    // Timeout answers "callback_timeout" and stops the listener.
    // Only GET /callback counts: browsers fetch /favicon.ico right after
    // the redirect, and any other path answers 404 without touching the
    // pending result.
  awaitCallback: timeoutMs keepListening: keep -> Result(Dictionary, OAuthError) => ...
  rearm -> Result(LoopbackReceiver, OAuthError) => ...
    // keepListening: true leaves the listener up after a callback, still
    // owned by the waiter (its exit stops the listener, BT-4570); rearm
    // clears the slot, keeping port and expected state (BT-4572)
  stop -> Symbol => ...             // idempotent; #ok, like Actor>>stop
```

```beamtalk
// The structured error language ADR 0060 requires at public
// boundaries. Codes are strings:
//  - provider codes verbatim, from oidcc's {http_error, Status, Body}
//    (invalid_grant, invalid_client, access_denied, ...);
//  - oidcc reasons, snake_cased (sub_invalid, token_expired,
//    issuer_mismatch, missing_claim, no_supported_code_challenge, ...);
//  - local codes ("transport", "parse", "config", "expired_session",
//    "reused_state", "session_mismatch", "insecure_endpoint").
// `detail` keeps the original term for debugging, redacted of secrets.
typed Value subclass: OAuthError
  field: code :: String = ""
  field: description :: String = ""
  field: status :: Integer | Nil = nil
  field: detail = nil
```

#### Forged loopback callbacks: re-arm

`state` gates the loopback slot (BT-4569), but it is not secret on the
local machine: the authorize URL shows up in the argv of the process
that opens the browser and in browser history. A local process that
reads it can send `/callback?code=junk&state=<real>` before the
provider's redirect. The junk code is never accepted (PKCE, the
session store), but it used to end the login twice over: the receiver
stopped listening, and `handleCallback:` burned the session.

Decision (BT-4572, 2026-11-09): **re-arm on a failed exchange**.
`OAuthFlows completeLoopbackLogin:server:client:store:timeout:` runs
await, `handleCallback:` and `exchangeCode:`. When the token endpoint
answers `invalid_grant`, it puts the same session back
(`SessionStore restore:boundTo:`: same verifier, nonce and binding,
original expiry, so a re-arm never extends a session) and re-arms the
receiver on the same port for the same state
(`LoopbackReceiver rearm`, after an `awaitCallback:keepListening:`),
then waits again for the time left. Only `invalid_grant` re-arms; a
provider `error=` callback, any callback failure, any other exchange
error and a timeout end the login as before. Re-arms are capped (3 by
default), all within the one overall timeout; past either limit the
last error is answered. The waiter stays the receiver's owner between
the callback and the re-arm, so the BT-4570 guarantee holds: if it
exits, the listener stops.

Residual limit: this defeats a forged callback that carries a junk
code, nothing more. A local attacker can still delay the login until
the cap or the timeout (a tight loop of junk callbacks spends every
re-arm in moments), or end it with a forged callback that fails before
the exchange: an `error=` (which looks the same as the provider's), a
wrong `iss`, or no `code`. A real redirect that lands while a junk
callback holds the slot answers 404 and is lost. And a real code the
provider refuses with `invalid_grant` (a redirect URI it rejects, say)
now waits out the timeout before answering. None of these hijack the
login; whether to re-arm on more of them is BT-4613.

Considered and not chosen: keeping the URL out of argv (handing it to
the browser another way). It is platform-specific, and the URL still
lands in browser history.

### Seams and rules

- **One HTTP stack: `http`/Mint.** The shim passes
  `request_opts => #{http_adapter => {beamtalk_oauth_http_adapter, Cfg}}`
  on every `oidcc` call, so `oidcc` never touches `httpc` (a test guard
  fails the suite on any `httpc:request` call). The adapter sends
  `request:url:options:` to the `HTTPClient` class object passed in its
  config (via `beamtalk_message_dispatch:send/3` until BT-4556 provides
  a supported API) and converts the returned `Result` and
  `HTTPResponse` to what `oidcc` expects. TLS verification, no-redirect behaviour,
  `#maxBodyBytes` and (later) proxy settings are then identical for
  every provider call.
- **Proxies.** Desktop apps on corporate networks need them, and neither
  `beamtalk-mint` nor `HTTPClient` supports one today. Elixir Mint does,
  and the port missed it: `:proxy` on connect (forward proxying for
  `http` targets, `CONNECT` tunnelling for `https`, including through an
  `https` proxy) plus `:proxy_headers` for `Proxy-Authorization`. Like
  Mint, the transport does not read environment variables; the client
  layer does. Plan, as needed and outside this repo:
  - `beamtalk-mint`: `CONNECT` tunnel and forward proxy. The groundwork
    exists: `connectTlsOn:host:port:options:` (BT-4540) runs TLS over a
    caller-owned socket, which is exactly the post-`CONNECT` step.
  - `beamtalk-http`: a `#proxy` request/client option, and resolution
    of `HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY` (the curl convention CLI
    users expect). OS proxy settings (PAC, WPAD, system keychains) are
    out of scope.
  - `beamtalk-oauth` only passes options through; it never implements
    proxying itself.
- **Tests do not hit the network.** OIDC paths run against a fixture
  provider (discovery + JWKS + token endpoint, signing ID tokens with a
  test key via `jose`). `oidcc`'s `allow_unsafe_http` quirk is used only
  by the test suite.
- **Hard rules:**
  - Server endpoints: HTTPS only, except through the explicit test-only
    opt-in.
  - Redirect URIs: HTTPS, or a loopback IP literal on any port
    (`http://127.0.0.1:{port}` / `http://[::1]:{port}`). RFC 8252 §8.3
    marks `localhost` NOT RECOMMENDED, and §7.3 has the port chosen at
    runtime.
  - `printString`, `asJson` and actor state (`sys:get_state`, crash
    reports) redact secrets
    (tokens, secrets, verifiers).
  - PKCE is always required (`require_pkce => true`); S256 only.
  - No HTTP call follows redirects (`HTTPClient` never does, so a
    redirected token request cannot resend a code or secret), and every
    response body is capped with `#maxBodyBytes`.

### REPL example

Native app (the primary case):

```beamtalk
server := (OAuthServer fromPreset: ProviderPresets gitlab) unwrap
rx := LoopbackReceiver start unwrap
reg := (ClientRegistration forClient: "APP_ID" redirect: rx redirectUri) unwrap
store := SessionStore spawn
sess := OAuthSession newSessionFor: server client: reg
(store create: sess boundTo: rx binding) unwrap
rx expectState: sess state                // before the URL is opened
url := (OAuthFlows authorizeUrl: server client: reg scopes: #("openid", "read_user") session: sess) unwrap
Transcript showCr: url                    // or open the system browser
toks := (OAuthFlows completeLoopbackLogin: rx server: server client: reg store: store timeout: 300000) unwrap
toks subject                              // validated by oidcc
(OAuthFlows userInfo: server client: reg tokenSet: toks) unwrap
toks := (OAuthFlows refresh: server client: reg tokenSet: toks) unwrap
(OAuthFlows revoke: server client: reg token: toks) unwrap
```

`fromPreset:` rather than a bare `fromDiscovery:`: the GitLab preset adds
the `none` client auth method that a public native client needs. The
runnable form is `examples/native_login.bt`, and
`test/e2e_native_login_test.bt` runs the same sequence against the
fixture provider (BT-4565).

### Error example

```beamtalk
result := OAuthFlows exchangeCode: server client: reg callback: usedCb store: store
result isError            // => true
(result error) code       // => "invalid_grant" (provider code, verbatim)
```

## Prior Art

- **oidcc (Erlang)**: adopted as the engine. Certified OIDC RP logic is
  exactly the code a small library should not reimplement.
- **openid-client (TS)**: adopted its surface grouping (discovery,
  per-grant functions, client-auth methods, token lifecycle,
  revocation). Rejected its implicit-session conveniences;
  our store is explicit. FAPI-grade items stay non-goals even where
  `oidcc` supports them.
- **Assent (Elixir)**: adopted provider strategies as data. Rejected as
  a dependency: Elixir-only.
- **Elixir `oauth2`**: rejected for the same policy reason, and it has no
  PKCE helper.
- **`p1_oauth2`, `oauth2c` (Erlang)**: rejected after source inspection:
  wrong side (server) and stale/no-PKCE respectively.
- **Smalltalk-family prior art**: no established community OAuth2 client
  library was found in Squeak/Pharo (prior art found: delegating login to
  an external service such as Auth0, or vendor-specific clients such as
  VAST's). The lesson adopted anyway: provider-specific classes with
  implicit session state are exactly what this design refuses.

## User Impact

- **Newcomer**: login is `authorizeUrl`, `handleCallback`,
  `exchangeCode`, each returning a printable `Result`. Provider and
  network failures surface as data (`isError` + `code`); programming
  misuse still raises (language ADR 0015). Concern: the explicit store
  is one more concept than "just call login".
- **App developer**: `refresh`, `userInfo`, `revoke` complete the app.
  `toks subject` is a validated identity, not a decoded-but-unchecked
  JWT. New OIDC providers are presets plus fixtures.
- **Smalltalk developer**: message-passing preserved; the Erlang
  engine is invisible behind Values and `Result`s. `SessionStore` and
  `ProviderWorker` being Actors may surprise, but explicitness beats
  hidden globals.
- **Erlang/BEAM developer**: the engine is the ecosystem's certified
  RP, so behaviour matches what they already trust. `oidcc` telemetry
  events fire for every HTTP call. No Elixir runtime in the tree.
- **Operator**: adds `oidcc`, `jose` and `telemetry` (the latter two
  start their own small supervisors) plus `inets`/`ssl`/`public_key`.
  Security updates for identity logic come from upstream rather than
  from this repo. No global state in this library; JWKS refresh runs in
  the app-owned `ProviderWorker`.

## Steelman Analysis

### Wrap `oidcc` (chosen)
- **Security reviewer**: "ID-token validation, JWKS rotation, algorithm
  allow-lists and issuer checks are where hand-rolled clients fail.
  Certified, audited, maintained code beats anything a small library
  can write."
- **BEAM veteran**: "It's the EEF's answer to this exact problem; use
  it and send fixes upstream."
- **App developer**: "Validated `sub` from day one, not in 0.3."
- Genuinely strongest on correctness and long-term maintenance.

### Hand-roll Beamtalk-native (rejected; the original decision)
- **Smalltalk purist**: "No foreign object model; every line is
  inspectable in the image."
- **Operator**: "Dependency tree stays OTP + `http`, nothing native to
  build."
- **Language designer**: "GitHub and other plain-OAuth providers fit
  naturally; `oidcc` is OIDC-first."
- Genuinely strongest on fit and footprint. Loses because it makes this
  repo the owner of identity-validation security forever.

### Wrap Assent via the Erlang proxy (rejected)
- **App developer**: "GitLab OIDC strategy already written."
- Loses on policy (Erlang-only wrappers) and runtime weight.

### Tension
Footprint and plain-OAuth fit favor hand-rolling; correctness and
maintenance of identity code favor wrapping. The author, with
identity-platform experience, judged that identity code is the part not
to own. The cost is a shim, an HTTP adapter, a small Beamtalk-owned
revoke until upstream ships one, and GitHub needing
its own plain-OAuth path (Open Question 5).

## Alternatives Considered

### Alternative A: Wrap Assent through the Erlang proxy
Technically feasible (module proxy, ok/error unwrap). Rejected:
violates the Erlang-only wrapper policy; drags in the Elixir runtime.

### Alternative B: Port or proxy Elixir `oauth2`
Rejected: same policy violation, and it lacks PKCE helpers.

### Alternative C: Hand-roll the whole client in Beamtalk
The original decision: Beamtalk-native discovery, PKCE, token calls,
and (in 0.3) JWT validation over `jose`. Smaller dependency tree, one
HTTP stack, and plain-OAuth providers fit without special cases.
Rejected: it puts ID-token validation, JWKS rotation, issuer checks and
client authentication in this repo, where a certified, audited,
actively maintained implementation already exists.

### Alternative D: `jose` only, hand-roll the flows
The review's interim recommendation: hand-roll OAuth flows, use `jose`
only for JWT work in 0.3. Rejected: it still hand-rolls discovery
validation and the OIDC claim rules (iss, aud, azp, exp, nonce, clock
skew), which is identity code under another name.

### Alternative E: Extend Erlang `oauth2c` with PKCE
Policy-compliant, but unmaintained since 2018 and service-account
shaped. Rejected: a fork inherits maintenance without the benefit of
certification.

### Alternative F: Do nothing
Each app hand-rolls provider calls. Rejected: every app would
re-solve state storage, PKCE and error mapping, and none would validate
ID tokens properly.

## Consequences

### Positive

- No identity-validation code in this repo; ID tokens validated from
  0.1 by certified code.
- Upstream security fixes (e.g. `jose` 1.11.13's advisories) arrive by
  version bump.
- Large feature surface available for later at shim cost only
  (`private_key_jwt`, introspection, logout, PAR if ever wanted).
- `oidcc` telemetry gives operators per-call spans for free.

### Negative

- Native dependency tree: `oidcc`, `jose`, `telemetry`,
  `telemetry_registry`, plus `inets`/`ssl`/`public_key`. First package
  in the ecosystem to carry an identity engine; builds now need rebar3
  (bundled) and OTP 27+.
- Two Erlang modules (`native/`) to maintain: the shim, translating
  records and error terms, and the HTTP adapter. `oidcc` API changes
  land in the shim.
- Revocation is ours until `oidcc` releases it: one RFC 7009 call with
  its own client-auth selection, duplicating logic `oidcc` keeps
  internally. Small, but it is the one protocol call outside the engine.
- Cross-repo work: proxy support lands in `beamtalk-mint` and
  `beamtalk-http`.
- Known upstream issues to track: `oidcc` #550 (JSON nulls decode as
  `null` atoms since 3.8.0); an unreleased fix for JWE decryption with
  `jose` 1.11.13 (affects encrypted ID tokens only).
- GitHub does not fit the engine (no discovery, no ID tokens, and
  `oidcc` refresh requires one).

### Neutral

- Operational notes: the store is single-node (multi-node deploys fail
  closed: a callback landing on another node cannot find its session,
  so logins fail behind a non-sticky load balancer); store calls are
  synchronous; store death loses in-flight sessions (fail-closed); the
  app must store the `TokenSet` that `refresh:` returns.

## Implementation

New repo `beamtalk-oauth`, plus work elsewhere:

- **`beamtalk-mint` / `beamtalk-http`**: proxy support, as needed (see
  "Seams and rules").
- **`oidcc` fork (off the critical path)**: branch `rfc7009-revocation`
  on the author's fork adds `oidcc_token_revocation:revoke/3` and the
  `oidcc:revoke_token/5` facade with Elixir wrappers, tested in
  `oidcc`'s own suite. It is a candidate upstream PR referencing #252,
  held for now; 0.1 does not consume it. Device flow, written before it
  was dropped, is parked separately on `rfc8628-device-flow`.
- **`beamtalk` toolchain (optional)**: git sources and rebar3 overrides
  in `[native.dependencies]` (BT-4555, in progress). Not needed for 0.1:
  Phase 0 found `jose` builds without an override. Useful for consuming
  the fork in tests.

Manifest (language ADRs 0026, 0070, 0072):

```toml
[dependencies]
http = "..."              # HTTPClient (oidcc adapter, tokenInfo) and
                          # HTTPServer (LoopbackReceiver)

[native.dependencies]
oidcc = "3.9.2"           # pulls jose, telemetry
```

Slice plan (sizes rough, calibrated on `beamtalk-mint` and the
`beamtalk-yaml` shim):

- **Phase 0 — wire check (S)**. Run 2026-11-09 with `beamtalk` 0.4.0
  and `http` 0.3.2; the probe shim is in `native/`.
  - Done: Hex `oidcc` 3.9.2 and `jose` build from `[native.dependencies]`
    with no Elixir and **no `jose` override** on OTP 28 (and 29). OTP 27
    is untested: the nightly `beamtalk` toolchain's build worker is
    compiled for OTP 28 and does not boot on 27, so CI runs OTP 28 only.
  - Done: the generated `oauth.app` lists `oidcc` in `applications`, so
    a release starts it with `jose`, `telemetry` and `inets`. The REPL
    loads modules without starting the package app, so shim entry points
    call `application:ensure_all_started(oidcc)`.
  - Done: the HTTP adapter. Erlang cannot name a Beamtalk class
    portably (the compiled `class_*` arity no longer matches language
    ADR 0055), so Beamtalk passes the `HTTPClient` class object in the
    adapter config and the adapter sends it `request:url:options:` via
    `beamtalk_message_dispatch:send/3`. Beamtalk Strings cross as
    `{beamtalk_string, Bin}` and a `Result` arrives as a map
    (`isOk`/`okValue`/`errReason`), so the adapter tags outgoing values
    and untags responses into the `httpc` shape `oidcc` expects.
  - Done: `oidcc` discovery plus JWKS for GitLab and Google over the
    adapter.
  - Done: `oidcc_token:retrieve` against a local `HTTPServer` fixture
    serving an ES256-signed ID token. It sent `code_verifier` and HTTP
    Basic client auth, validated iss/aud/nonce/exp, and rejected a
    mismatched nonce. `oidcc` error terms embed the full claim set, so
    `OAuthError detail` goes through the same redaction as logs.
  - Done (live, gitlab.com, public client): a full login with
    PKCE S256 and the `none` auth override, ID token validated by
    `oidcc`, then `/oauth/userinfo` with only the `openid` scope (it
    returns profile and group claims). GitLab accepted loopback
    redirects on ephemeral ports 50278 and 50524 with only
    `http://127.0.0.1:8765/callback` registered, so `LoopbackReceiver`
    needs no fixed-port option. Google documents the same behaviour for
    desktop clients; it was not exercised live.
- **0.1 (M)**: shim + HTTP adapter; `OAuthServer fromDiscovery:`, `ProviderWorker`;
  `ClientRegistration`; `OAuthSession` + `Secrets`; `SessionStore`;
  `LoopbackReceiver`; `OAuthFlows` authorize / callback / exchange /
  refresh (merging) / userinfo / revoke / `tokenInfo`; presets gitlab +
  google; `OAuthError` mapping; `TokenSet` with validated
  `idTokenClaims`. Covers desktop apps and local CLIs. Headless users
  (SSH, containers) use the provider's personal access tokens.
- **0.2 (M)**: client credentials, GitHub. GitHub is a
  Beamtalk-owned plain-OAuth path outside `oidcc`: `Accept:
  application/json` on the token call, errors detected in HTTP 200
  bodies, comma-separated scopes, its own revoke and check-authorization
  calls, and identity from `/user` (plus `/user/emails` when email is
  null). No identity validation is involved: there is no ID token, only
  an authenticated API call. If an `oidcc` release has shipped
  revocation by then, replace the Beamtalk-owned revoke with a shim
  call.
- **0.3 (S-M)**: shim exposure of `private_key_jwt`, RP-initiated logout,
  introspection for providers that offer it.
- **Never**: server-side issuing, CIBA, implicit/hybrid flows, FAPI
  certification (even though `oidcc` supports FAPI 2.0 profiles), and
  the device authorization grant (RFC 8628). Device-code phishing is a
  well-documented attack: the attacker starts a flow and persuades the
  victim to enter the user code, then receives the victim's tokens.
  Identity platforms let administrators block the flow for this reason
  (e.g. Entra Conditional Access). A general-purpose login library should
  not hand that capability to every app built on it. Headless users use
  the provider's personal access tokens. Author decision, 2026-11-09.

Testing: BUnit suite with a fixture OIDC provider (discovery, JWKS, token
and userinfo endpoints, ID tokens signed with a test key); state, nonce
and session-mismatch cases; login CSRF (callback completed with a
different binding fails with `session_mismatch` and burns the session;
missing binding raises); single-use session enforcement; error
mapping (`invalid_grant`, `sub_invalid`, HTTP 500, malformed JSON);
`Secrets generate` matches `^[A-Za-z0-9_-]{43}$`. One optional live
GitLab test behind an env flag, off by default.

## Open Questions

Resolved:

1. Base64url: `asBase64Url` exists; padding is stripped on every
   generated value.
2. `tokenInfo`: generalized, normalized shape (`active`, `subject`,
   `scopes`, `expiresIn`), per preset.
3. Wrap vs hand-roll: wrap `oidcc` (author decision, 2026-11-09).
   This also resolves the review's questions on the 0.3 JWT stack,
   `userInfo` without `openid` (OIDC presets always request it), and
   the `ClientRegistration` auth-method invariant (dropped; `oidcc`
   negotiates).

4. Login CSRF: mandatory user-agent binding on `SessionStore`
   (`boundTo:`), not a sealed-cookie store. See "Login CSRF: user-agent
   binding". Decided 2026-11-09.
5. GitHub: a separate Beamtalk-owned plain-OAuth path in 0.2, outside
   `oidcc`; 0.1 ships gitlab + google only. Confirmed 2026-11-09.
6. Native apps are the primary audience: 0.1 ships `LoopbackReceiver`;
   0.1 sizes M. Device flow was added to 0.1 and then dropped entirely
   (see "Never" under Implementation). Confirmed 2026-11-09.

7. `SessionStore` storage: a private ETS table owned by the actor. The
   first plan was actor state (a `Dictionary`), but Beamtalk actors have
   no `format_status/1` hook, so the sessions would show in
   `sys:get_state` and crash reports. A private table is unreadable from
   other processes, survives hot code reloading, and dies with the actor
   (fail closed); a consume inside the actor is still atomic. Revised
   2026-11-09 (BT-4559).
8. Time: pure `TokenSet isExpiredAt:`/`needsRefreshAt:` plus
   `isExpired`/`needsRefresh` conveniences reading the system clock;
   `SessionStore spawnWith: #{#ttl => ..., #now => [...]}` for tests;
   flows stamp `obtainedAt` at request send time. `oidcc`'s
   `max_clock_skew` is set to 60 s, because laptop clocks drift and the
   default of 0 fails ID-token `iat`/`exp` checks; it is `oidcc`
   application env, so it is node-wide (documented). Decided 2026-11-09.
9. `ProviderWorker` is an optimization, not a requirement:
   `fromDiscovery:` is fine everywhere because the shim always passes
   `oidcc`'s `refresh_jwks` callback, which reloads keys on an unknown
   `kid`. Short-lived CLIs use `fromDiscovery:`; long-running apps may use
   the worker to avoid per-login discovery. Decided 2026-11-09.
10. Revocation: Beamtalk-owned on `HTTPClient` for now, so 0.1 builds
    on Hex `oidcc` 3.9.2. The `oidcc` implementation on fork branch
    `rfc7009-revocation` is held as a future upstream PR; adopt
    `oidcc`'s once released. Decided 2026-11-09 (revised the same day
    from consuming the fork).
11. HTTP: one stack, `http`/Mint, via an `oidcc_http_adapter`; proxy
    support added to `beamtalk-mint`/`beamtalk-http` as needed. Decided
    2026-11-09.
12. Toolchain: with revocation Beamtalk-owned, 0.1 needs no git sources
    in `[native.dependencies]`, and Phase 0 found `jose` needs no
    override, so BT-4555 is off the critical path. Decided 2026-11-09.
13. The fork: split into `rfc7009-revocation` (upstream PR candidate,
    held) and `rfc8628-device-flow` (parked). Neither is consumed by
    0.1. Decided 2026-11-09.

## Implementation Tracking

**Epic:** BT-4557
**Issues:** BT-4558 (core values), BT-4559 (`SessionStore`), BT-4560
(`LoopbackReceiver`), BT-4561 (native layer, `OAuthServer`, presets,
fixture provider), BT-4562 (`OAuthFlows`), BT-4563 (revocation,
`tokenInfo`), BT-4564 (`ProviderWorker`), BT-4565 (end-to-end test,
examples, README)
**Related (beamtalk):** BT-4556 (supported native-to-Beamtalk send
API), BT-4555 (git sources in `[native.dependencies]`, optional)
**Status:** Planned

## Migration Path

Not applicable: greenfield library, no existing behavior or consumers.

## References

- RFC 6749 (OAuth 2.0), RFC 7009 (revocation), RFC 7636 (PKCE), RFC 8252
  (native apps, loopback redirects), RFC 8414 (discovery), RFC 9207 (`iss` callback parameter), OpenID Connect
  Core and Discovery 1.0
- Language ADRs: 0015 (exception hierarchy), 0026 (package manifest),
  0042 (Value/Actor split), 0060 (Result hybrid errors), 0070
  (namespaces), 0072 (native Erlang sources and Hex deps), 0076
  (ok/error-to-Result at FFI boundary)
- [oidcc](https://github.com/erlef/oidcc) ([Hex](https://hex.pm/packages/oidcc));
  source references: `oidcc_token.erl` (refresh `sub` check),
  `oidcc_authorization.erl` (PKCE skip without `require_pkce`)
- [erlang-jose](https://github.com/potatosalad/erlang-jose)
  ([Hex](https://hex.pm/packages/jose))
- [OpenID certified implementations](https://openid.net/developers/certified-openid-connect-implementations/)
- [openid-client](https://github.com/panva/openid-client)
- [Assent](https://hex.pm/packages/assent)
- [GitLab OAuth2 docs](https://docs.gitlab.com/api/oauth2/)
- Precedent: `beamtalk-yaml` (`yamerl` via `[native.dependencies]`)
- [Mint proxy options](https://mint.hexdocs.pm/Mint.HTTP.html) (`:proxy`,
  `:proxy_headers`, `CONNECT` tunnelling)
- [`oidcc` #252: OAuth 2.0 Token Revocation](https://github.com/erlef/oidcc/issues/252)
