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

Errors are `oidcc`'s own reasons, plus `{insecure_endpoint, Field, Url}`
from the HTTPS-only check and `{http_client, Reason}` from the adapter.
`OAuthError fromOidcc:` maps all of them.
""".

-include_lib("oidcc/include/oidcc_provider_configuration.hrl").
-include_lib("oidcc/include/oidcc_token.hrl").

-export([
    ensure_started/0,
    discover/2,
    client_context/3,
    call_opts/1,
    check_https/2,
    retrieve_token/3,
    token_to_map/1,
    to_beamtalk/1
]).

-export_type([provider/0]).

-doc "A discovered provider, opaque to Beamtalk.".
-opaque provider() :: {beamtalk_oauth_provider, #{
    config := oidcc_provider_configuration:t(),
    jwks := jose_jwk:key(),
    request_opts := oidcc_http_util:request_opts()
}}.

%% `oidcc` checks ID-token `iat`/`exp`/`nbf` with no tolerance by default;
%% laptop clocks drift (ADR 0001, Open Question 8).
-define(MAX_CLOCK_SKEW, 60).

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
  fixture provider is plain HTTP;
* `max_body_bytes` — the response cap, default 1 MiB;
* `timeout` — per-request timeout in milliseconds.

Unless `allow_unsafe_http` is set, the issuer must be HTTPS before any
request is made, and every endpoint the document names must be HTTPS.

Answers `{ok, #{issuer, context, revocation_endpoint, metadata}}`, where
`context` is the opaque provider and `metadata` the configuration record
as a map, or `{error, Reason}`.
""".
-spec discover(Issuer :: term(), Opts :: map()) -> {ok, map()} | {error, term()}.
discover(Issuer0, Opts) when is_map(Opts) ->
    ensure_started(),
    Issuer = bin(Issuer0),
    Unsafe = maps:get(allow_unsafe_http, Opts, false) =:= true,
    RequestOpts = request_opts(Opts),
    Overrides = untag(maps:get(document_overrides, Opts, #{})),
    Quirks = #{document_overrides => Overrides, allow_unsafe_http => Unsafe},
    LoadOpts = #{request_opts => RequestOpts, quirks => Quirks},
    maybe
        ok ?= check_url(issuer, Issuer, Unsafe),
        {ok, {Config, _ConfigExpiry}} ?=
            oidcc_provider_configuration:load_configuration(Issuer, LoadOpts),
        ok ?= check_https(config_map(Config), Unsafe),
        {ok, {Jwks, _JwksExpiry}} ?=
            oidcc_provider_configuration:load_jwks(
                Config#oidcc_provider_configuration.jwks_uri, LoadOpts
            ),
        Provider =
            {beamtalk_oauth_provider, #{
                config => Config, jwks => Jwks, request_opts => RequestOpts
            }},
        {ok, #{
            issuer => str(Config#oidcc_provider_configuration.issuer),
            context => Provider,
            revocation_endpoint => opt_str(Config#oidcc_provider_configuration.revocation_endpoint),
            metadata => to_beamtalk(config_map(Config))
        }}
    end.

-doc """
An `oidcc` client context for `Provider` and a client id. `Secret` is the
client secret, or `nil` (or an empty string) for a public client, which
`oidcc` calls `unauthenticated`.
""".
-spec client_context(provider(), ClientId :: term(), Secret :: term()) ->
    oidcc_client_context:t().
client_context({beamtalk_oauth_provider, #{config := Config, jwks := Jwks}}, ClientId, Secret) ->
    case secret(Secret) of
        unauthenticated ->
            oidcc_client_context:from_manual(Config, Jwks, bin(ClientId), unauthenticated);
        S ->
            oidcc_client_context:from_manual(Config, Jwks, bin(ClientId), S)
    end.

-doc """
The options every `oidcc` call for `Provider` starts from: the adapter in
`request_opts`, and a `refresh_jwks` callback that reloads the JWKS
through the same adapter when a token names an unknown `kid`.
""".
-spec call_opts(provider()) -> map().
call_opts({beamtalk_oauth_provider, #{config := Config, request_opts := RequestOpts}}) ->
    JwksUri = Config#oidcc_provider_configuration.jwks_uri,
    Refresh = fun(_Jwks, _Kid) ->
        case
            oidcc_provider_configuration:load_jwks(JwksUri, #{request_opts => RequestOpts})
        of
            {ok, {Jwks, _Expiry}} -> {ok, Jwks};
            {error, Reason} -> {error, Reason}
        end
    end,
    #{request_opts => RequestOpts, refresh_jwks => Refresh}.

-doc """
`ok` when every URL in `Endpoints` (a map of field name to URL, or to a
map of URLs, as in `mtls_endpoint_aliases`) is HTTPS, or `AllowUnsafe` is
true; `{error, {insecure_endpoint, Field, Url}}` for the first that is not.
Absent fields (`undefined`, `null`, `nil`) are skipped.
""".
-spec check_https(Endpoints :: map(), AllowUnsafe :: boolean()) ->
    ok | {error, {insecure_endpoint, atom() | binary(), binary()}}.
check_https(_Endpoints, true) ->
    ok;
check_https(Endpoints, _AllowUnsafe) ->
    Fields = [F || F <- ?ENDPOINT_FIELDS ++ [mtls_endpoint_aliases], maps:is_key(F, Endpoints)],
    check_fields(Fields, Endpoints).

check_fields([], _Endpoints) ->
    ok;
check_fields([Field | Rest], Endpoints) ->
    case check_value(Field, maps:get(Field, Endpoints)) of
        ok -> check_fields(Rest, Endpoints);
        Error -> Error
    end.

check_value(_Field, Absent) when Absent =:= undefined; Absent =:= null; Absent =:= nil ->
    ok;
check_value(Field, Aliases) when is_map(Aliases) ->
    check_fields(maps:keys(Aliases), Aliases, Field);
check_value(Field, Url) ->
    check_url(Field, bin(Url), false).

check_fields([], _Aliases, _Parent) ->
    ok;
check_fields([Key | Rest], Aliases, Parent) ->
    case check_value(Parent, maps:get(Key, Aliases)) of
        ok -> check_fields(Rest, Aliases, Parent);
        Error -> Error
    end.

check_url(_Field, _Url, true) ->
    ok;
check_url(Field, Url, false) ->
    case uri_string:parse(Url) of
        #{scheme := Scheme, host := Host} when Host =/= <<>> ->
            case string:lowercase(Scheme) of
                <<"https">> -> ok;
                _ -> {error, {insecure_endpoint, Field, Url}}
            end;
        _ ->
            {error, {insecure_endpoint, Field, Url}}
    end.

-doc """
Exchange an authorization code at `Provider`'s token endpoint, with the
ID token validated by `oidcc` and PKCE always required.

`Client` is `#{client_id, client_secret}` (secret `nil` for a public
client); `Params` is `#{code, redirect_uri, nonce, pkce_verifier}`.
Answers `{ok, token_to_map(Token)}` or `{error, Reason}`.
""".
-spec retrieve_token(provider(), Client :: map(), Params :: map()) ->
    {ok, map()} | {error, term()}.
retrieve_token(Provider, #{client_id := ClientId} = Client, #{code := Code} = Params) ->
    ensure_started(),
    Context = client_context(Provider, ClientId, maps:get(client_secret, Client, nil)),
    Opts = (call_opts(Provider))#{
        redirect_uri => bin(maps:get(redirect_uri, Params)),
        nonce => bin(maps:get(nonce, Params)),
        pkce_verifier => bin(maps:get(pkce_verifier, Params)),
        require_pkce => true
    },
    case oidcc_token:retrieve(bin(Code), Context, Opts) of
        {ok, Token} -> {ok, token_to_map(Token)};
        {error, Reason} -> {error, Reason}
    end.

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
    AdapterCfg0 = #{client => maps:get(client, Opts)},
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
    case bin(S) of
        <<>> -> unauthenticated;
        B -> B
    end.

%% Beamtalk Strings nested in a term, unwrapped to raw binaries for oidcc.
untag({beamtalk_string, B}) when is_binary(B) -> B;
untag(L) when is_list(L) -> [untag(E) || E <- L];
untag(M) when is_map(M) -> maps:from_list([{untag(K), untag(V)} || {K, V} <- maps:to_list(M)]);
untag(nil) -> null;
untag(Other) -> Other.

str(B) when is_binary(B) -> {beamtalk_string, B};
str(L) when is_list(L) -> {beamtalk_string, iolist_to_binary(L)}.

opt_str(Absent) when Absent =:= undefined; Absent =:= null -> nil;
opt_str(V) -> str(V).

opt(undefined) -> nil;
opt(V) -> V.

bin({beamtalk_string, B}) -> B;
bin(B) when is_binary(B) -> B;
bin(L) when is_list(L) -> unicode:characters_to_binary(L);
bin(A) when is_atom(A) -> atom_to_binary(A).
