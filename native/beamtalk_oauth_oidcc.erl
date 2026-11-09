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
    load_opts/1,
    provider_info/4,
    client_context/3,
    call_opts/1,
    check_https/2,
    check_endpoints/2,
    retrieve_token/3,
    token_to_map/1,
    to_beamtalk/1
]).

-export_type([provider/0]).

-doc "A discovered provider, opaque to Beamtalk.".
-opaque provider() :: {beamtalk_oauth_provider, #{
    config := oidcc_provider_configuration:t(),
    jwks := jose_jwk:key(),
    request_opts := oidcc_http_util:request_opts(),
    worker => pid()
}}.

%% `oidcc` checks ID-token `iat`/`exp`/`nbf` with no tolerance by default;
%% laptop clocks drift (ADR 0001, Open Question 8).
-define(MAX_CLOCK_SKEW, 60).

%% How long token validation waits for a `ProviderWorker`'s JWKS reload
%% before loading the keys itself.
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
  fixture provider is plain HTTP;
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
    Unsafe = maps:get(allow_unsafe_http, Opts, false) =:= true,
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

`Worker` is the `oidcc_provider_configuration_worker` the configuration
came from, or `undefined`. With a worker, the context's `refresh_jwks`
callback asks the worker to reload, so the new keys are kept for every
later caller (see `call_opts/1`).
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
            true -> Context0#{worker => Worker};
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
asks the worker to reload instead, so the worker keeps the new keys for
every later caller; if the worker has gone, it falls back to reloading
directly.
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
            #{worker := Worker} -> fun(_Jwks, Kid) -> worker_jwks(Worker, Kid, Direct) end;
            _ -> fun(_Jwks, _Kid) -> Direct() end
        end,
    #{request_opts => RequestOpts, refresh_jwks => Refresh}.

%% Ask the worker to reload its JWKS for `Kid' (it skips the reload when it
%% already has that key) and answer its keys. A worker that has stopped,
%% has no keys or does not answer within ?WORKER_JWKS_TIMEOUT falls back
%% to `Direct'.
%%
%% The cast is what `oidcc_provider_configuration_worker:
%% refresh_jwks_for_unknown_kid/2' sends; that function then waits with
%% the default 5 s call timeout, too long inside a Beamtalk actor call.
%% The worker handles the cast before the `get_jwks' call.
worker_jwks(Worker, Kid, Direct) ->
    gen_server:cast(Worker, {refresh_jwks_for_unknown_kid, Kid}),
    try gen_server:call(Worker, get_jwks, ?WORKER_JWKS_TIMEOUT) of
        undefined -> Direct();
        Jwks -> {ok, Jwks}
    catch
        exit:_ -> Direct()
    end.

-doc """
`ok` when every URL in `Endpoints` (a map of field name to URL, or to a
map of URLs, as in `mtls_endpoint_aliases`) is HTTPS;
`{error, {insecure_endpoint, Field, Url}}` for the first that is not.
With `AllowUnsafe`, plain HTTP is also accepted on a loopback host
(`127.0.0.1`, `::1`, `localhost`), never elsewhere. Absent fields
(`undefined`, `null`, `nil`) are skipped. The HTTP adapter checks each
request URL as the field `request_url`.
""".
-spec check_https(Endpoints :: map(), AllowUnsafe :: boolean()) ->
    ok | {error, {insecure_endpoint, atom() | binary(), term()}}.
check_https(Endpoints, AllowUnsafe) when is_map(Endpoints) ->
    Fields = [
        F
     || F <- ?ENDPOINT_FIELDS ++ [mtls_endpoint_aliases, request_url], maps:is_key(F, Endpoints)
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
Exchange an authorization code at `Provider`'s token endpoint, with the
ID token validated by `oidcc` and PKCE always required.

`Client` is `#{client_id, client_secret}` (secret `nil` for a public
client); `Params` is `#{code, redirect_uri, nonce, pkce_verifier}`.
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
        {ok, [Code, Redirect, Nonce, Verifier]} ?=
            required(Params, [code, redirect_uri, nonce, pkce_verifier]),
        Context = client_context(Provider, ClientId, maps:get(client_secret, Client, nil)),
        Opts = (call_opts(Provider))#{
            redirect_uri => Redirect,
            nonce => Nonce,
            pkce_verifier => Verifier,
            require_pkce => true
        },
        {ok, Token} ?= oidcc_token:retrieve(Code, Context, Opts),
        {ok, token_to_map(Token)}
    end;
retrieve_token(_Provider, _Client, _Params) ->
    %% No function_clause: its stacktrace would carry the secret.
    {error, invalid_provider}.

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
        allow_unsafe_http => maps:get(allow_unsafe_http, Opts, false) =:= true
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
