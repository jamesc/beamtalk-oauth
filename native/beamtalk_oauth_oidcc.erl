%% Copyright 2026 James Casey
%% SPDX-License-Identifier: Apache-2.0

-module(beamtalk_oauth_oidcc).

-moduledoc """
Shim between Beamtalk values and `oidcc` records and maps.

Every `oidcc` call made here carries
`request_opts => #{http_adapter => {beamtalk_oauth_http_adapter, Cfg}}`,
so `oidcc` never falls back to `httpc`, and every call that validates a
token also carries a `refresh_jwks` callback that reloads the key set
through the same adapter.

Arguments arrive from Beamtalk untouched: Strings as
`{beamtalk_string, Bin}` (at any depth), Symbols as atoms, nil as `nil`.
Results go back the same way: binaries meant as text are tagged, absent
values are `nil`, and `{ok, _}` / `{error, _}` become a `Result`.

A discovered provider is held as the opaque
`{beamtalk_oauth_provider, Map}`: the provider configuration record, its
JWKS and the request options. Beamtalk stores it in `OAuthServer` and
hands it back; it never looks inside.

Every flow entry point (`authorize_url/3`, `retrieve_token/3`,
`refresh_token/3`, `userinfo/3`) first checks the caller's expected
`issuer` against the issuer in the provider configuration itself, not
the copy Beamtalk holds, so a hand-built `OAuthServer` that pairs one
issuer with another provider's context is refused before any request
(`{session_mismatch, issuer}`).

Errors are `oidcc`'s own reasons, plus `{insecure_endpoint, Field, Url}`
from the HTTPS-only check, `{http_client, Reason}` from the adapter,
and, from this shim, `{insecure_endpoint, claim_source, Url}` (a
userinfo `_claim_sources` endpoint that is not HTTPS),
`{missing_param, Key}`, `{session_mismatch, issuer}`,
`{issuer_mismatch, iss | missing_iss}`, `missing_id_token`,
`no_userinfo_endpoint` and `{oidcc_crash, Class}` (an exception inside
`oidcc`, caught so its stacktrace cannot carry secrets).
`OAuthError fromOidcc:` maps all of them.
""".

-include_lib("oidcc/include/oidcc_provider_configuration.hrl").
-include_lib("oidcc/include/oidcc_token.hrl").

-export([
    ensure_started/0,
    unsafe_http_enabled/0,
    discover/2,
    load_opts/1,
    provider_info/4,
    client_context/3,
    call_opts/1,
    check_https/2,
    check_claim_sources/2,
    authorize_url/3,
    check_endpoints/2,
    retrieve_token/3,
    refresh_token/3,
    userinfo/3,
    token_to_map/1,
    to_beamtalk/1
]).

-export_type([provider/0]).

-doc "A discovered provider, opaque to Beamtalk.".
-opaque provider() :: {beamtalk_oauth_provider, #{
    config := oidcc_provider_configuration:t(),
    jwks := jose_jwk:key(),
    request_opts := oidcc_http_util:request_opts(),
    provider_worker => pid()
}}.

%% `oidcc` checks ID-token `iat`/`exp`/`nbf` with no tolerance by default;
%% laptop clocks drift (ADR 0001, Open Question 8).
-define(MAX_CLOCK_SKEW, 60).

%% How long token validation waits for a `ProviderWorker`'s JWKS reload
%% before going on with the keys it has.
-define(WORKER_JWKS_TIMEOUT, 3000).

%% Endpoint fields of the provider configuration that must be HTTPS.
-define(ENDPOINT_FIELDS, [
    issuer,
    authorization_endpoint,
    token_endpoint,
    userinfo_endpoint,
    jwks_uri,
    registration_endpoint,
    revocation_endpoint,
    introspection_endpoint,
    end_session_endpoint,
    pushed_authorization_request_endpoint
]).

-doc """
Start `oidcc` (and with it `jose`, `telemetry`, `inets`, `ssl`). The REPL
loads the package without starting its application, so every entry
point calls this.

Also sets `oidcc`'s `max_clock_skew` application env to 60 seconds unless
the application already set one. It is node-wide.
""".
-spec ensure_started() -> ok.
ensure_started() ->
    {ok, _} = application:ensure_all_started(oidcc),
    case application:get_env(oidcc, max_clock_skew) of
        undefined -> application:set_env(oidcc, max_clock_skew, ?MAX_CLOCK_SKEW);
        {ok, _} -> ok
    end,
    ok.

-doc """
Discovery: load the provider configuration for `Issuer` and its JWKS.

`Opts` (atom keys):

* `client` (required) — the `HTTPClient` class object the adapter sends
  requests to;
* `document_overrides` — a map merged over the discovery document
  (`oidcc`'s `quirks => #{document_overrides => ...}`);
* `allow_unsafe_http` — `true` to accept `http` endpoints. Test-only: the
  fixture provider is plain HTTP. Refused (`unsafe_http_disabled`) unless
  `unsafe_http_enabled/0`;
* `max_body_bytes` — the response cap, default 1 MiB;
* `timeout` — per-request timeout in milliseconds.

The issuer must be HTTPS before any request is made, and every endpoint
the document names must be HTTPS. `allow_unsafe_http` relaxes that to
plain HTTP on a loopback host (`127.0.0.1`, `::1`, `localhost`) only.

Answers `{ok, #{issuer, context, revocation_endpoint, metadata}}`, where
`context` is the opaque provider and `metadata` the configuration record
as a map, or `{error, Reason}`.
""".
-spec discover(Issuer :: term(), Opts :: map()) -> {ok, map()} | {error, term()}.
discover(Issuer0, Opts) when is_map(Opts) ->
    ensure_started(),
    Issuer = bin(Issuer0),
    Unsafe = maps:get(allow_unsafe_http, Opts, false) =:= true,
    LoadOpts = #{request_opts := RequestOpts} = load_opts(Opts),
    maybe
        ok ?= check_unsafe_allowed(Unsafe),
        ok ?= check_url(issuer, Issuer, Unsafe),
        {ok, {Config, _ConfigExpiry}} ?=
            oidcc_provider_configuration:load_configuration(Issuer, LoadOpts),
        ok ?= check_endpoints(Config, Unsafe),
        {ok, {Jwks, _JwksExpiry}} ?=
            oidcc_provider_configuration:load_jwks(
                Config#oidcc_provider_configuration.jwks_uri, LoadOpts
            ),
        {ok, provider_info(Config, Jwks, RequestOpts, undefined)}
    end.

-doc """
Whether the test-only `allow_unsafe_http` option may be used: the
application env `beamtalk_oauth` / `allow_unsafe_http_for_tests` is
`true`. Only the test suite sets it (`FixtureProvider start`), so a
production config that asks for plain HTTP is refused rather than obeyed.
""".
-spec unsafe_http_enabled() -> boolean().
unsafe_http_enabled() ->
    application:get_env(beamtalk_oauth, allow_unsafe_http_for_tests, false) =:= true.

check_unsafe_allowed(false) ->
    ok;
check_unsafe_allowed(true) ->
    case unsafe_http_enabled() of
        true -> ok;
        false -> {error, unsafe_http_disabled}
    end.

-doc """
The options `oidcc` loads a provider configuration and JWKS with:
`#{request_opts, quirks}`, built from the same `Opts` as `discover/2`
(`client`, `document_overrides`, `allow_unsafe_http`, `max_body_bytes`,
`timeout`). `request_opts` carries the adapter, so a load made with these
options never reaches `httpc`. `ProviderWorker` hands them to
`oidcc_provider_configuration_worker` as its
`provider_configuration_opts`.
""".
-spec load_opts(Opts :: map()) -> #{request_opts := map(), quirks := map()}.
load_opts(Opts) when is_map(Opts) ->
    Unsafe = maps:get(allow_unsafe_http, Opts, false) =:= true andalso unsafe_http_enabled(),
    Overrides = untag(maps:get(document_overrides, Opts, #{})),
    #{
        request_opts => request_opts(Opts),
        quirks => #{document_overrides => Overrides, allow_unsafe_http => Unsafe}
    }.

-doc """
`ok` when the configuration names every endpoint field the HTTPS check
knows and each is HTTPS (or, with `AllowUnsafe`, plain HTTP on a loopback
host); `{error, Reason}` otherwise.
""".
-spec check_endpoints(oidcc_provider_configuration:t(), AllowUnsafe :: boolean()) ->
    ok | {error, term()}.
check_endpoints(Config, Unsafe) ->
    Endpoints = config_map(Config),
    maybe
        ok ?= check_complete(Endpoints),
        check_https(Endpoints, Unsafe)
    end.

-doc """
What Beamtalk's `OAuthServer fromShim:preset:` reads, for a loaded
configuration and JWKS: `#{issuer, context, revocation_endpoint,
metadata}`. `context` is the opaque provider; `metadata` the
configuration record as a map.

`Worker` is the `ProviderWorker` process (`beamtalk_oauth_provider_worker`)
the configuration came from, or `undefined`. With a worker, the context's
`refresh_jwks` callback asks the worker to reload, so the new keys are
kept for every later caller (see `call_opts/1`).
""".
-spec provider_info(
    oidcc_provider_configuration:t(),
    jose_jwk:key(),
    RequestOpts :: map(),
    Worker :: pid() | undefined
) -> map().
provider_info(Config, Jwks, RequestOpts, Worker) ->
    Context0 = #{config => Config, jwks => Jwks, request_opts => RequestOpts},
    Context =
        case is_pid(Worker) of
            true -> Context0#{provider_worker => Worker};
            false -> Context0
        end,
    #{
        issuer => str(Config#oidcc_provider_configuration.issuer),
        context => {beamtalk_oauth_provider, Context},
        revocation_endpoint => opt_str(Config#oidcc_provider_configuration.revocation_endpoint),
        metadata => to_beamtalk(config_map(Config))
    }.

-doc """
An `oidcc` client context for `Provider` and a client id. `Secret` is the
client secret, or `nil` (or an empty string) for a public client, which
`oidcc` calls `unauthenticated`.
""".
-spec client_context(provider(), ClientId :: term(), Secret :: term()) ->
    oidcc_client_context:t().
client_context({beamtalk_oauth_provider, #{config := Config, jwks := Jwks}}, ClientId0, Secret) ->
    ClientId =
        case text(ClientId0) of
            {ok, Id} when Id =/= <<>> -> Id;
            _ -> erlang:error(invalid_client_id)
        end,
    oidcc_client_context:from_manual(Config, Jwks, ClientId, secret(Secret));
client_context(_NotAProvider, _ClientId, _Secret) ->
    %% No function_clause: its stacktrace would carry the secret.
    erlang:error(invalid_provider).

-doc """
The options every `oidcc` call for `Provider` starts from: the adapter in
`request_opts`, and a `refresh_jwks` callback for a token that names an
unknown `kid`.

A provider from `discover/2` reloads the JWKS through the adapter itself;
the new keys last for that one call. A provider from a `ProviderWorker`
asks the worker to reload instead (rate-limited there), so the worker
keeps the new keys for every later caller. If the worker has gone, or has
no keys yet, it reloads directly; if the worker is busy past 3 s, it goes
on with the keys it has, and validation fails rather than overrunning the
caller's 5 s actor-call budget.
""".
-spec call_opts(provider()) -> map().
call_opts({beamtalk_oauth_provider, #{config := Config, request_opts := RequestOpts} = Ctx}) ->
    JwksUri = Config#oidcc_provider_configuration.jwks_uri,
    Direct = fun() ->
        case
            oidcc_provider_configuration:load_jwks(JwksUri, #{request_opts => RequestOpts})
        of
            {ok, {Jwks, _Expiry}} -> {ok, Jwks};
            {error, Reason} -> {error, Reason}
        end
    end,
    Refresh =
        case Ctx of
            #{provider_worker := Worker} ->
                fun(Jwks, Kid) -> worker_jwks(Worker, Kid, Jwks, Direct) end;
            _ -> fun(_Jwks, _Kid) -> Direct() end
        end,
    #{request_opts => RequestOpts, refresh_jwks => Refresh}.

%% Ask the `ProviderWorker' to reload its JWKS for `Kid' and answer its
%% keys. The oidcc worker behind it skips the reload when it already has
%% that key. A worker that has stopped or has no keys yet falls back to
%% `Direct'; one that does not answer within ?WORKER_JWKS_TIMEOUT (busy
%% with a slow load) leaves validation with the keys it already has.
%%
%% oidcc drops an unknown-kid refresh that is queued while a load runs
%% (`drop_queued_unknown_kid_refreshes/0'): the load that just ran is taken
%% to cover it. If that load started before the provider rotated, the new
%% key is missed once; the next token naming it triggers another reload.
worker_jwks(Worker, Kid, Current, Direct) ->
    try gen_server:call(Worker, {beamtalk_oauth_unknown_kid, Kid}, ?WORKER_JWKS_TIMEOUT) of
        undefined -> Direct();
        busy -> {ok, Current};
        Jwks -> {ok, Jwks}
    catch
        exit:{timeout, _} -> {ok, Current};
        exit:_ -> Direct()
    end.

-doc """
`ok` when every URL in `Endpoints` (a map of field name to URL, or to a
map of URLs, as in `mtls_endpoint_aliases`) is HTTPS;
`{error, {insecure_endpoint, Field, Url}}` for the first that is not.
With `AllowUnsafe`, plain HTTP is also accepted on a loopback host
(`127.0.0.1`, `::1`, `localhost`), never elsewhere. Absent fields
(`undefined`, `null`, `nil`) are skipped. The HTTP adapter checks each
request URL as the field `request_url`, and `check_claim_sources/2` each
distributed-claim endpoint as `claim_source`.
""".
-spec check_https(Endpoints :: map(), AllowUnsafe :: boolean()) ->
    ok | {error, {insecure_endpoint, atom() | binary(), term()}}.
check_https(Endpoints, AllowUnsafe) when is_map(Endpoints) ->
    Fields = [
        F
     || F <- ?ENDPOINT_FIELDS ++ [mtls_endpoint_aliases, request_url, claim_source],
        maps:is_key(F, Endpoints)
    ],
    check_fields(Fields, Endpoints, AllowUnsafe =:= true).

check_fields([], _Endpoints, _Unsafe) ->
    ok;
check_fields([Field | Rest], Endpoints, Unsafe) ->
    case check_value(Field, maps:get(Field, Endpoints), Unsafe) of
        ok -> check_fields(Rest, Endpoints, Unsafe);
        Error -> Error
    end.

check_value(_Field, Absent, _Unsafe) when Absent =:= undefined; Absent =:= null; Absent =:= nil ->
    ok;
check_value(Field, Aliases, Unsafe) when is_map(Aliases) ->
    check_aliases(maps:values(Aliases), Field, Unsafe);
check_value(Field, Url, Unsafe) ->
    case text(Url) of
        {ok, Bin} -> check_url(Field, Bin, Unsafe);
        error -> {error, {insecure_endpoint, Field, Url}}
    end.

check_aliases([], _Field, _Unsafe) ->
    ok;
check_aliases([Url | Rest], Field, Unsafe) ->
    case check_value(Field, Url, Unsafe) of
        ok -> check_aliases(Rest, Field, Unsafe);
        Error -> Error
    end.

check_url(Field, Url, Unsafe) ->
    case uri_string:parse(Url) of
        #{scheme := Scheme, host := Host} when Host =/= <<>> ->
            case {string:lowercase(Scheme), Unsafe andalso is_loopback(Host)} of
                {<<"https">>, _} -> ok;
                {<<"http">>, true} -> ok;
                _ -> {error, {insecure_endpoint, Field, Url}}
            end;
        _ ->
            {error, {insecure_endpoint, Field, Url}}
    end.

is_loopback(Host) ->
    lists:member(string:lowercase(Host), [<<"127.0.0.1">>, <<"::1">>, <<"localhost">>]).

%% `config_map/1' zips `record_info' with the compiled record. If the two
%% ever disagreed (an oidcc upgrade against a stale header), endpoint
%% fields would go missing and the HTTPS check would pass them unseen.
check_complete(Endpoints) ->
    case [F || F <- ?ENDPOINT_FIELDS, not maps:is_key(F, Endpoints)] of
        [] -> ok;
        Missing -> {error, {provider_configuration_mismatch, Missing}}
    end.

-doc """
The authorization-request URL for `Provider`, from
`oidcc_authorization:create_redirect_url/2` with PKCE always required
(`require_pkce => true`) and S256 only.

`Client` is `#{client_id, client_secret}`; `Params` is
`#{issuer, redirect_uri, state, nonce, pkce_verifier, scopes, extra}`,
where `scopes` is a list of Strings and `extra` a list of
`{Name, Value}` String pairs appended to the query. The call carries
`call_opts/1`, so a pushed authorization request (PAR) also goes
through the adapter.

A provider that does not advertise S256 in
`code_challenge_methods_supported` answers
`{error, no_supported_code_challenge}`: `oidcc` would otherwise fall
back to `plain`.
""".
-spec authorize_url(provider(), Client :: map(), Params :: map()) ->
    {ok, term()} | {error, term()}.
authorize_url({beamtalk_oauth_provider, #{config := Config}} = Provider, Client, Params) when
    is_map(Client), is_map(Params)
->
    ensure_started(),
    maybe
        {ok, [ClientId]} ?= required(Client, [client_id]),
        {ok, [Issuer, Redirect, State, Nonce, Verifier]} ?=
            required(Params, [issuer, redirect_uri, state, nonce, pkce_verifier]),
        ok ?= check_issuer(Provider, Issuer),
        ok ?= check_s256(Config),
        Context = client_context(Provider, ClientId, maps:get(client_secret, Client, nil)),
        Opts = (call_opts(Provider))#{
            redirect_uri => Redirect,
            state => State,
            nonce => Nonce,
            pkce_verifier => Verifier,
            require_pkce => true,
            scopes => [untag(S) || S <- maps:get(scopes, Params, [])],
            url_extension => [{untag(K), untag(V)} || {K, V} <- maps:get(extra, Params, [])]
        },
        {ok, Url} ?= guard(fun() -> oidcc_authorization:create_redirect_url(Context, Opts) end),
        {ok, str(Url)}
    end;
authorize_url(_Provider, _Client, _Params) ->
    {error, invalid_provider}.

check_s256(#oidcc_provider_configuration{code_challenge_methods_supported = Methods}) ->
    case is_list(Methods) andalso lists:member(<<"S256">>, Methods) of
        true -> ok;
        false -> {error, no_supported_code_challenge}
    end.

%% Run an `oidcc` call. A crash inside `oidcc` (a malformed provider
%% answer, an empty algorithm list) must not escape: its stacktrace can
%% hold the ID token, the client context (secret) and the options
%% (verifier, nonce). It becomes a fixed reason, like the adapter's.
guard(Fun) ->
    try
        Fun()
    catch
        Class:_Reason -> {error, {oidcc_crash, Class}}
    end.

%% `ok` when the RFC 9207 callback `iss` agrees with the configuration.
check_callback_iss({beamtalk_oauth_provider, #{config := Config}}, Iss0) ->
    #oidcc_provider_configuration{
        issuer = Issuer, authorization_response_iss_parameter_supported = Advertised
    } = Config,
    case text(Iss0) of
        {ok, Issuer} -> ok;
        {ok, _Other} -> {error, {issuer_mismatch, iss}};
        error when Advertised =:= true -> {error, {issuer_mismatch, missing_iss}};
        error -> ok
    end.

check_id_token(#oidcc_token{id = #oidcc_token_id{}}) -> ok;
check_id_token(_Token) -> {error, missing_id_token}.

check_userinfo_endpoint({beamtalk_oauth_provider, #{config := Config}}) ->
    case Config#oidcc_provider_configuration.userinfo_endpoint of
        undefined -> {error, no_userinfo_endpoint};
        _ -> ok
    end.

%% `ok` when `Expected` is the issuer of `Provider`'s own configuration.
check_issuer({beamtalk_oauth_provider, #{config := Config}}, Expected) ->
    case Config#oidcc_provider_configuration.issuer of
        Expected -> ok;
        _ -> {error, {session_mismatch, issuer}}
    end.

-doc """
Exchange an authorization code at `Provider`'s token endpoint, with the
ID token validated by `oidcc` and PKCE always required.

`Client` is `#{client_id, client_secret}` (secret `nil` for a public
client); `Params` is `#{issuer, code, redirect_uri, nonce,
pkce_verifier}` plus an optional `iss`, where `issuer` is the issuer the
flow was started for. Before any request, `issuer` is checked against
the provider configuration, and so is the callback's RFC 9207 `iss`:
it must equal the configuration's issuer when present, and must be
present when the configuration sets
`authorization_response_iss_parameter_supported`
(`{error, {issuer_mismatch, iss}}` / `{issuer_mismatch, missing_iss}`).

A token response without an ID token answers
`{error, missing_id_token}`: `oidcc` accepts one, but then checks no
nonce and validates no subject.

Answers `{ok, token_to_map(Token)}` or `{error, Reason}`.
""".
-spec retrieve_token(provider(), Client :: map(), Params :: map()) ->
    {ok, map()} | {error, term()}.
retrieve_token({beamtalk_oauth_provider, _} = Provider, Client, Params) when
    is_map(Client), is_map(Params)
->
    ensure_started(),
    maybe
        {ok, [ClientId]} ?= required(Client, [client_id]),
        {ok, [Issuer, Code, Redirect, Nonce, Verifier]} ?=
            required(Params, [issuer, code, redirect_uri, nonce, pkce_verifier]),
        ok ?= check_issuer(Provider, Issuer),
        ok ?= check_callback_iss(Provider, maps:get(iss, Params, nil)),
        Context = client_context(Provider, ClientId, maps:get(client_secret, Client, nil)),
        Opts = (call_opts(Provider))#{
            redirect_uri => Redirect,
            nonce => Nonce,
            pkce_verifier => Verifier,
            require_pkce => true
        },
        {ok, Token} ?= guard(fun() -> oidcc_token:retrieve(Code, Context, Opts) end),
        ok ?= check_id_token(Token),
        {ok, token_to_map(Token)}
    end;
retrieve_token(_Provider, _Client, _Params) ->
    %% No function_clause: its stacktrace would carry the secret.
    {error, invalid_provider}.

-doc """
Refresh at `Provider`'s token endpoint with `oidcc_token:refresh/3`.

The response may omit the ID token (OpenID Connect Core §12.2). When it
has one, `oidcc` validates it (signature, `iss`, `aud`, expiry) and
requires its `sub` to be `expected_subject` (`{error, sub_invalid}`
otherwise). When it has none, `oidcc` still answers `sub_invalid`, so
the shim reads the response body the adapter captured and answers its
access token, refresh token, expiry and scope with `id_token => nil`;
no identity is taken from it.

`oidcc` also refuses to refresh unless the provider lists
`refresh_token` in `grant_types_supported`, and RFC 8414's default for
an absent member leaves it out. The shim adds it for this call: a
provider that does not support the grant answers at its token endpoint.

`Client` is as for `retrieve_token/3`; `Params` is
`#{issuer, refresh_token, expected_subject}`, where `issuer` is the
issuer of the original ID token. Answers `{ok, token_to_map(Token)}`.
""".
-spec refresh_token(provider(), Client :: map(), Params :: map()) ->
    {ok, map()} | {error, term()}.
refresh_token({beamtalk_oauth_provider, _} = Provider0, Client, Params) when
    is_map(Client), is_map(Params)
->
    ensure_started(),
    maybe
        {ok, [ClientId]} ?= required(Client, [client_id]),
        {ok, [Issuer, RefreshToken, Subject]} ?=
            required(Params, [issuer, refresh_token, expected_subject]),
        ok ?= check_issuer(Provider0, Issuer),
        Provider = with_refresh_grant(Provider0),
        Context = client_context(Provider, ClientId, maps:get(client_secret, Client, nil)),
        Opts = (capture(call_opts(Provider)))#{expected_subject => Subject},
        _ = beamtalk_oauth_http_adapter:take_captured(),
        try guard(fun() -> oidcc_token:refresh(RefreshToken, Context, Opts) end) of
            {ok, Token} ->
                {ok, token_to_map(Token)};
            {error, sub_invalid} ->
                without_id_token(beamtalk_oauth_http_adapter:take_captured());
            {error, _} = Error ->
                Error
        after
            beamtalk_oauth_http_adapter:take_captured()
        end
    end;
refresh_token(_Provider, _Client, _Params) ->
    {error, invalid_provider}.

%% The provider with `refresh_token` among its grant types.
with_refresh_grant({beamtalk_oauth_provider, #{config := Config} = Map}) ->
    Grants =
        case Config#oidcc_provider_configuration.grant_types_supported of
            List when is_list(List) -> List;
            _ -> []
        end,
    Config1 = Config#oidcc_provider_configuration{
        grant_types_supported = lists:usort([<<"refresh_token">> | Grants])
    },
    {beamtalk_oauth_provider, Map#{config := Config1}}.

%% `Opts` with the adapter told to capture POST response bodies.
capture(#{request_opts := #{http_adapter := {Mod, Cfg}} = RequestOpts} = Opts) ->
    Opts#{request_opts := RequestOpts#{http_adapter := {Mod, Cfg#{capture => true}}}}.

%% A refresh response `oidcc` accepted but refused for having no ID token
%% (`sub_invalid`): the token map without one. A response that does carry
%% an ID token, or that cannot be read, stays `sub_invalid`.
without_id_token(Body) when is_binary(Body) ->
    try json:decode(Body) of
        #{<<"access_token">> := Access} = Map when is_binary(Access) ->
            case maps:get(<<"id_token">>, Map, null) of
                null -> plain_token(Map);
                _IdToken -> {error, sub_invalid}
            end;
        _ ->
            {error, sub_invalid}
    catch
        _:_ -> {error, sub_invalid}
    end;
without_id_token(_None) ->
    {error, sub_invalid}.

plain_token(Map) ->
    maybe
        {ok, Type} ?= opt_text(Map, <<"token_type">>, <<"Bearer">>),
        {ok, Refresh} ?= opt_text(Map, <<"refresh_token">>, nil),
        {ok, Expires} ?= opt_expiry(maps:get(<<"expires_in">>, Map, null)),
        {ok, Scope} ?= opt_scope(maps:get(<<"scope">>, Map, null)),
        {ok, #{
            access_token => str(maps:get(<<"access_token">>, Map)),
            token_type => str(Type),
            expires_in => Expires,
            refresh_token => opt_tag(Refresh),
            scope => Scope,
            id_token => nil,
            id_token_claims => nil
        }}
    end.

opt_text(Map, Key, Default) ->
    case maps:get(Key, Map, null) of
        null -> {ok, Default};
        Bin when is_binary(Bin) -> {ok, Bin};
        _ -> {error, {invalid_property, binary_to_atom(Key)}}
    end.

opt_expiry(null) -> {ok, nil};
opt_expiry(N) when is_integer(N) -> {ok, N};
opt_expiry(Bin) when is_binary(Bin) ->
    try
        {ok, binary_to_integer(Bin)}
    catch
        error:badarg -> {error, {invalid_property, expires_in}}
    end;
opt_expiry(_) ->
    {error, {invalid_property, expires_in}}.

opt_scope(null) -> {ok, nil};
opt_scope(<<>>) -> {ok, nil};
opt_scope(Bin) when is_binary(Bin) -> {ok, str(Bin)};
opt_scope(List) when is_list(List) ->
    case lists:all(fun is_binary/1, List) of
        true -> {ok, str(lists:join(<<" ">>, List))};
        false -> {error, {invalid_property, scope}}
    end;
opt_scope(_) ->
    {error, {invalid_property, scope}}.

opt_tag(nil) -> nil;
opt_tag(Bin) -> str(Bin).

-doc """
Userinfo from `Provider` with `oidcc_userinfo:retrieve/3`, the answer's
`sub` checked against `expected_subject` (`{error, bad_subject}`
otherwise).

A userinfo response may name distributed claims (OpenID Connect Core
§5.6.2), which `oidcc` fetches from each `_claim_sources[].endpoint`.
The adapter hands a JSON or signed-JWT userinfo response to
`check_claim_sources/2` before `oidcc` sees it, so a source endpoint that
is not HTTPS fails the call with `{insecure_endpoint, claim_source, Url}`
before any source is fetched, and before `oidcc` checks the response's
signature and subject. An encrypted userinfo JWT cannot be read there:
its plain-HTTP sources are refused one by one by the adapter's own
request-URL check (`{http_client, insecure_url}`), after any HTTPS
source listed before them has been fetched.

`Client` is as for `retrieve_token/3` (the id is the expected audience
of a signed userinfo response); `Params` is
`#{issuer, access_token, token_type, expected_subject}`. Answers
`{ok, Claims}` with the claims as Beamtalk values (String keys).
""".
-spec userinfo(provider(), Client :: map(), Params :: map()) ->
    {ok, map()} | {error, term()}.
userinfo({beamtalk_oauth_provider, _} = Provider, Client, Params) when
    is_map(Client), is_map(Params)
->
    ensure_started(),
    maybe
        {ok, [ClientId]} ?= required(Client, [client_id]),
        {ok, [Issuer, AccessToken, Type, Subject]} ?=
            required(Params, [issuer, access_token, token_type, expected_subject]),
        ok ?= check_issuer(Provider, Issuer),
        Context = client_context(Provider, ClientId, maps:get(client_secret, Client, nil)),
        Access = #oidcc_token_access{token = AccessToken, type = Type},
        Opts = (claim_source_check(Provider, call_opts(Provider)))#{
            expected_subject => Subject
        },
        ok ?= check_userinfo_endpoint(Provider),
        {ok, Claims} ?= guard(fun() -> oidcc_userinfo:retrieve(Access, Context, Opts) end),
        {ok, to_beamtalk(Claims)}
    end;
userinfo(_Provider, _Client, _Params) ->
    {error, invalid_provider}.

%% `Opts` with the adapter told to run `check_claim_sources/2` on a
%% successful response from `Provider`'s userinfo endpoint (or its mTLS
%% alias), before `oidcc` reads it and fetches any distributed claims.
claim_source_check(
    {beamtalk_oauth_provider, #{config := Config}},
    #{request_opts := #{http_adapter := {Mod, Cfg}} = RequestOpts} = Opts
) ->
    #oidcc_provider_configuration{
        userinfo_endpoint = Endpoint, mtls_endpoint_aliases = Aliases
    } = Config,
    Urls = [
        iolist_to_binary(U)
     || U <- [Endpoint, maps:get(<<"userinfo_endpoint">>, aliases(Aliases), undefined)],
        is_binary(U) orelse is_list(U)
    ],
    Check = fun
        (get, Url, {ok, {{_, Status, _}, _Headers, Body}}, Unsafe) when
            Status =:= 200; Status =:= 201
        ->
            case lists:member(iolist_to_binary(Url), Urls) of
                true -> check_claim_sources(userinfo_claims(Body), Unsafe);
                false -> ok
            end;
        (_Method, _Url, _Answer, _Unsafe) ->
            ok
    end,
    Opts#{request_opts := RequestOpts#{http_adapter := {Mod, Cfg#{response_check => Check}}}}.

aliases(Map) when is_map(Map) -> Map;
aliases(_) -> #{}.

-doc """
`ok` when every distributed-claim source endpoint in a userinfo claims
map is HTTPS (or, with `AllowUnsafe`, plain HTTP on a loopback host), as
`check_https/2` decides; `{error, {insecure_endpoint, claim_source, Url}}`
for the first that is not.

The sources checked are the ones `oidcc` would fetch: claims with both
`_claim_names` and `_claim_sources`, and in `_claim_sources` each source
with an `endpoint` and no aggregated `JWT`. A source with an endpoint
that is not text fails. `Url` in the error is the endpoint without its
user info, query or fragment, which can carry credentials.
""".
-spec check_claim_sources(Claims :: term(), AllowUnsafe :: boolean()) ->
    ok | {error, {insecure_endpoint, claim_source, binary()}}.
check_claim_sources(#{<<"_claim_names">> := _, <<"_claim_sources">> := Sources}, Unsafe) when
    is_map(Sources)
->
    check_sources(maps:values(Sources), Unsafe);
check_claim_sources(_Claims, _Unsafe) ->
    ok.

check_sources([], _Unsafe) ->
    ok;
check_sources([#{<<"JWT">> := _Aggregated} | Rest], Unsafe) ->
    check_sources(Rest, Unsafe);
check_sources([#{<<"endpoint">> := Endpoint} | Rest], Unsafe) ->
    case check_https(#{claim_source => Endpoint}, Unsafe) of
        ok -> check_sources(Rest, Unsafe);
        {error, _} -> {error, {insecure_endpoint, claim_source, display_url(Endpoint)}}
    end;
check_sources([_Other | Rest], Unsafe) ->
    check_sources(Rest, Unsafe).

%% `Url` as `scheme://host[:port]/path`, for an error: the user info,
%% query and fragment of a provider-supplied URL can carry credentials.
display_url(Url) when is_binary(Url) ->
    case uri_string:parse(Url) of
        #{} = Parts ->
            Kept = maps:with([scheme, host, port, path], Parts),
            case uri_string:recompose(Kept) of
                Bin when is_binary(Bin) -> Bin;
                _ -> <<"[invalid URL]">>
            end;
        _ ->
            <<"[invalid URL]">>
    end;
display_url(_NotText) ->
    <<"[invalid URL]">>.

%% The claims of a userinfo response body, read without validation (only
%% to find `_claim_sources`): a JSON object, else the payload of a signed
%% compact JWT. The content type is not consulted, so no type `oidcc`
%% reads differently can hide the sources. Anything else (an encrypted
%% JWT, a malformed body) is `#{}`; `oidcc` judges the body itself.
userinfo_claims(Body) ->
    try
        json:decode(Body)
    catch
        _:_ -> jws_payload(Body)
    end.

jws_payload(Body) ->
    try
        [_Header, Payload, _Signature] = binary:split(Body, <<".">>, [global]),
        json:decode(base64:decode(Payload, #{mode => urlsafe, padding => false}))
    catch
        _:_ -> #{}
    end.

%% The text values of `Keys` in `Map`, or `{error, {missing_param, Key}}`
%% for the first that is absent or not text (nil included).
required(Map, Keys) ->
    lists:foldr(
        fun
            (_Key, {error, _} = Error) ->
                Error;
            (Key, {ok, Acc}) ->
                case text(maps:get(Key, Map, nil)) of
                    {ok, <<>>} -> {error, {missing_param, Key}};
                    {ok, Bin} -> {ok, [Bin | Acc]};
                    error -> {error, {missing_param, Key}}
                end
        end,
        {ok, []},
        Keys
    ).

-doc """
An `#oidcc_token{}` as a map Beamtalk reads: `access_token`,
`token_type`, `expires_in`, `refresh_token`, `scope` (space-separated),
`id_token` (the raw JWT) and `id_token_claims`. Absent parts are `nil`.
""".
-spec token_to_map(#oidcc_token{}) -> map().
token_to_map(#oidcc_token{id = Id, access = Access, refresh = Refresh, scope = Scope}) ->
    {AccessToken, Type, ExpiresIn} =
        case Access of
            #oidcc_token_access{token = T, type = Ty, expires = E} -> {str(T), str(Ty), opt(E)};
            none -> {nil, nil, nil}
        end,
    {IdToken, Claims} =
        case Id of
            #oidcc_token_id{token = IT, claims = C} -> {str(IT), to_beamtalk(C)};
            none -> {nil, nil}
        end,
    #{
        access_token => AccessToken,
        token_type => Type,
        expires_in => ExpiresIn,
        refresh_token =>
            case Refresh of
                #oidcc_token_refresh{token = RT} -> str(RT);
                none -> nil
            end,
        scope =>
            case Scope of
                [] -> nil;
                Scopes when is_list(Scopes) -> str(oidcc_scope:scopes_to_bin(Scopes));
                _ -> nil
            end,
        id_token => IdToken,
        id_token_claims => Claims
    }.

-doc """
A decoded JSON-ish term as Beamtalk values: binaries become Strings
(when valid UTF-8), `undefined` and `null` become nil, maps and lists
convert recursively. Atoms, numbers and booleans are kept. Records and
other tuples are kept as they are.
""".
-spec to_beamtalk(term()) -> term().
to_beamtalk(B) when is_binary(B) ->
    case unicode:characters_to_binary(B) of
        B -> {beamtalk_string, B};
        _ -> B
    end;
to_beamtalk(undefined) ->
    nil;
to_beamtalk(null) ->
    nil;
to_beamtalk(L) when is_list(L) ->
    [to_beamtalk(E) || E <- L];
to_beamtalk(M) when is_map(M) ->
    maps:from_list([{to_beamtalk_key(K), to_beamtalk(V)} || {K, V} <- maps:to_list(M)]);
to_beamtalk(Other) ->
    Other.

to_beamtalk_key(K) when is_binary(K) -> to_beamtalk(K);
to_beamtalk_key(K) -> K.

%% The configuration record as a map of field name to value.
config_map(Config) ->
    maps:from_list(
        lists:zip(
            record_info(fields, oidcc_provider_configuration),
            tl(tuple_to_list(Config))
        )
    ).

request_opts(Opts) ->
    AdapterCfg0 = #{
        client => maps:get(client, Opts),
        allow_unsafe_http =>
            maps:get(allow_unsafe_http, Opts, false) =:= true andalso unsafe_http_enabled()
    },
    AdapterCfg =
        case maps:find(max_body_bytes, Opts) of
            {ok, Max} -> AdapterCfg0#{max_body_bytes => Max};
            error -> AdapterCfg0
        end,
    RequestOpts = #{http_adapter => {beamtalk_oauth_http_adapter, AdapterCfg}},
    case maps:find(timeout, Opts) of
        {ok, T} when is_integer(T), T > 0 -> RequestOpts#{timeout => T};
        _ -> RequestOpts
    end.

secret(nil) -> unauthenticated;
secret(undefined) -> unauthenticated;
secret(unauthenticated) -> unauthenticated;
secret(S) ->
    case text(S) of
        {ok, <<>>} -> unauthenticated;
        {ok, B} -> B;
        error -> erlang:error(invalid_client_secret)
    end.

%% Beamtalk Strings nested in a term, unwrapped to raw binaries for oidcc.
untag({beamtalk_string, B}) when is_binary(B) -> B;
untag(L) when is_list(L) -> [untag(E) || E <- L];
untag(M) when is_map(M) -> maps:from_list([{untag_key(K), untag(V)} || {K, V} <- maps:to_list(M)]);
untag(nil) -> null;
untag(Other) -> Other.

%% Discovery-document member names are binaries; a Symbol key would never
%% match one, so it is taken by name.
untag_key(K) when is_atom(K) -> atom_to_binary(K);
untag_key(K) -> untag(K).

str(B) when is_binary(B) -> {beamtalk_string, B};
str(L) when is_list(L) -> {beamtalk_string, iolist_to_binary(L)}.

opt_str(Absent) when Absent =:= undefined; Absent =:= null -> nil;
opt_str(V) -> str(V).

opt(undefined) -> nil;
opt(V) -> V.

bin({beamtalk_string, B}) -> B;
bin(B) when is_binary(B) -> B.

%% `{ok, Bin}` for a String or binary, `error` for anything else (nil
%% included, which `bin/1` must never turn into `<<"nil">>`).
text({beamtalk_string, B}) when is_binary(B) -> {ok, B};
text(B) when is_binary(B) -> {ok, B};
text(_) -> error.
