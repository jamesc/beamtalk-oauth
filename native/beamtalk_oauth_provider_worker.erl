%% Copyright 2026 James Casey
%% SPDX-License-Identifier: Apache-2.0

-module(beamtalk_oauth_provider_worker).

-moduledoc """
Backing gen_server for the `ProviderWorker` native actor (language ADR
0056).

It starts, and links to, an `oidcc_provider_configuration_worker` that
loads the provider configuration and JWKS and keeps both refreshed. The
worker loads through `beamtalk_oauth_oidcc:load_opts/1`, whose
`request_opts` carry the HTTP adapter, so its own refreshes never use
`httpc`.

The two processes live and die together: the link is not trapped, so if
the `oidcc` worker crashes this process exits with it, and if this
process is shut down by its supervisor the `oidcc` worker gets the same
exit signal. `stop` stops the `oidcc` worker in `terminate/2`.

Config (the `spawnWith:` map, Symbol keys arriving as atoms):

* `issuer` (required) — the issuer to discover;
* `client` — the `HTTPClient` class object, looked up by name when
  absent;
* `preset` — a `ProviderPresets` Dictionary (`documentOverrides` and the
  endpoints discovery omits), default `#{}`;
* `options` — `#{allowUnsafeHttp, maxBodyBytes, timeout}` as for
  `OAuthServer fromDiscovery:preset:options:`, plus `backoffMin`,
  `backoffMax` (ms) and `backoffType` for failed loads (default
  `random_exponential`, 1 s to 30 s: the worker keeps retrying instead of
  stopping).

The state holds no secrets (no client credentials ever reach it), and
`format_status/1` shows only the issuer and the `oidcc` worker's pid.
""".

-behaviour(gen_server).

-include_lib("oidcc/include/oidcc_provider_configuration.hrl").

-export([start_link/1, check/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, format_status/1]).

%% Inner calls to the oidcc worker stay below the 5 s Beamtalk actor-call
%% timeout, so a slow first load answers an error instead of the caller
%% timing out.
-define(CALL_TIMEOUT, 4500).

-define(KNOWN_OPTIONS, [
    allowUnsafeHttp, maxBodyBytes, timeout, backoffMin, backoffMax, backoffType
]).

-define(BACKOFF_TYPES, [stop, exponential, random, random_exponential]).

-doc "Start the worker (the native-actor facade calls this with the `spawnWith:` map).".
-spec start_link(map()) -> gen_server:start_ret().
start_link(Config) ->
    gen_server:start_link(?MODULE, Config, []).

-doc """
Check a `spawnWith:` config without starting anything: `nil` when it is
good, else the reason: `{insecure_endpoint, issuer, Url}` or
`{config, Text}`. `ProviderWorker issuer:preset:options:` calls it first,
so a bad config answers `Result error:` instead of failing the spawn.

A plain term, not `{ok, _}`/`{error, _}`: the FFI boundary turns an error
reason into an exception, and the caller needs the reason itself.
""".
-spec check(term()) -> nil | {insecure_endpoint, issuer, term()} | {config, term()}.
check(Config) ->
    case validate(Config) of
        {ok, _Issuer} -> nil;
        {error, {config, Text}} -> {config, {beamtalk_string, Text}};
        {error, {insecure_endpoint, Field, Url}} -> {insecure_endpoint, Field, {beamtalk_string, Url}}
    end.

%% `{ok, Issuer}' for a good config, else `{error, Reason}'.
validate(Config) when is_map(Config) ->
    maybe
        {ok, Issuer} ?= issuer(Config),
        {ok, Options} ?= options(Config),
        ok ?= preset(Config),
        Unsafe = maps:get(allowUnsafeHttp, Options, false) =:= true,
        ok ?= beamtalk_oauth_oidcc:check_https(#{issuer => Issuer}, Unsafe),
        {ok, Issuer}
    end;
validate(_Config) ->
    {error, {config, <<"ProviderWorker config must be a Dictionary">>}}.

init(Config) ->
    beamtalk_oauth_oidcc:ensure_started(),
    case validate(Config) of
        {ok, Issuer} ->
            {ok, Options} = options(Config),
            Unsafe = maps:get(allowUnsafeHttp, Options, false) =:= true,
            Preset = maps:get(preset, Config, #{}),
            LoadOpts = beamtalk_oauth_oidcc:load_opts(
                shim_opts(http_client(Config), Preset, Options)
            ),
            WorkerOpts = #{
                issuer => Issuer,
                provider_configuration_opts => LoadOpts,
                backoff_min => maps:get(backoffMin, Options, 1000),
                backoff_max => maps:get(backoffMax, Options, 30000),
                backoff_type => maps:get(backoffType, Options, random_exponential)
            },
            case oidcc_provider_configuration_worker:start_link(WorkerOpts) of
                {ok, Worker} ->
                    {ok, #{
                        issuer => Issuer,
                        preset => Preset,
                        unsafe => Unsafe,
                        request_opts => maps:get(request_opts, LoadOpts),
                        worker => Worker
                    }};
                {error, Reason} ->
                    {stop, Reason}
            end;
        {error, Reason} ->
            {stop, Reason}
    end.

%% Strip propagated context (ADR 0069 Phase 2b).
handle_call({Selector, Args, PropCtx}, From, State) when is_map(PropCtx) ->
    beamtalk_actor:restore_propagated_ctx(PropCtx),
    handle_call({Selector, Args}, From, State);
handle_call({server, []}, _From, State) ->
    Reply =
        try
            {ok, server(State)}
        catch
            Class:Reason:Stack -> {error, {Class, Reason, Stack}}
        end,
    {reply, Reply, State};
handle_call({refresh, []}, _From, #{worker := Worker} = State) ->
    Answer =
        try
            ok = oidcc_provider_configuration_worker:refresh_configuration(Worker),
            ok = oidcc_provider_configuration_worker:refresh_jwks(Worker),
            nil
        catch
            exit:{timeout, _} -> nil
        end,
    {reply, {ok, Answer}, State};
handle_call({issuer, []}, _From, #{issuer := Issuer} = State) ->
    {reply, {ok, {beamtalk_string, Issuer}}, State};
handle_call({oidccWorker, []}, _From, #{worker := Worker} = State) ->
    {reply, {ok, Worker}, State};
handle_call({Selector, _Args}, _From, State) ->
    {reply, {error, {does_not_understand, Selector}}, State};
handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #{worker := Worker}) ->
    _ = catch gen_server:stop(Worker, normal, ?CALL_TIMEOUT),
    ok;
terminate(_Reason, _State) ->
    ok.

-doc """
`sys:get_status/1` and crash reports: the issuer and the `oidcc` worker's
pid only. The preset and request options (the adapter config) are left
out; none of them is secret, but nothing here needs them.
""".
format_status(#{state := #{issuer := Issuer, worker := Worker}} = Status) ->
    Status#{state => #{issuer => Issuer, worker => Worker}};
format_status(Status) ->
    Status.

%% `Result ok:` an `OAuthServer` (built by `OAuthServer fromShim:preset:`,
%% as `fromDiscovery:` builds one) or `Result error:` an `OAuthError`.
server(#{preset := Preset} = State) ->
    case server_info(State) of
        {ok, Info} ->
            beamtalk_result:'ok:'(send_class('OAuthServer', 'fromShim:preset:', [Info, Preset]));
        {error, Reason} ->
            beamtalk_result:'makeError:'(send_class('OAuthError', 'fromOidcc:', [Reason]))
    end.

%% A class-side send to one of this package's classes. Native code has no
%% supported send API yet (BT-4556); the HTTP adapter uses the same call.
send_class(ClassName, Selector, Args) ->
    case beamtalk_class_registry:resolve_class_object(ClassName) of
        undefined -> erlang:error({class_not_loaded, ClassName});
        Class -> beamtalk_message_dispatch:send(Class, Selector, Args)
    end.

%% The worker's current configuration and JWKS as `OAuthServer fromShim:`
%% reads them. Errors when the first load has not
%% finished (or keeps failing) and when an endpoint is not HTTPS.
server_info(#{worker := Worker, unsafe := Unsafe, request_opts := RequestOpts}) ->
    maybe
        {ok, Config} ?= fetch(Worker, get_provider_configuration),
        {ok, Jwks} ?= fetch(Worker, get_jwks),
        ok ?= beamtalk_oauth_oidcc:check_endpoints(Config, Unsafe),
        {ok, beamtalk_oauth_oidcc:provider_info(Config, Jwks, RequestOpts, Worker)}
    end.

fetch(Worker, Call) ->
    try gen_server:call(Worker, Call, ?CALL_TIMEOUT) of
        undefined -> {error, provider_unavailable};
        Value -> {ok, Value}
    catch
        exit:{timeout, _} -> {error, {provider_unavailable, timeout}}
    end.

issuer(Config) ->
    case maps:get(issuer, Config, nil) of
        {beamtalk_string, B} when is_binary(B), B =/= <<>> -> {ok, B};
        B when is_binary(B), B =/= <<>> -> {ok, B};
        _ -> {error, {config, <<"ProviderWorker needs an #issuer String">>}}
    end.

preset(Config) ->
    case maps:get(preset, Config, #{}) of
        P when is_map(P) -> ok;
        _ -> {error, {config, <<"ProviderWorker #preset must be a Dictionary">>}}
    end.

options(Config) ->
    case maps:get(options, Config, #{}) of
        Opts when is_map(Opts) ->
            case [K || K <- maps:keys(Opts), not lists:member(K, ?KNOWN_OPTIONS)] of
                [] -> check_backoff(Opts);
                Unknown -> {error, {config, unknown_options_text(Unknown)}}
            end;
        _ ->
            {error, {config, <<"ProviderWorker #options must be a Dictionary">>}}
    end.

check_backoff(Opts) ->
    Type = maps:get(backoffType, Opts, random_exponential),
    Min = maps:get(backoffMin, Opts, 1000),
    Max = maps:get(backoffMax, Opts, 30000),
    case
        lists:member(Type, ?BACKOFF_TYPES) andalso is_integer(Min) andalso Min > 0 andalso
            is_integer(Max) andalso Max >= Min
    of
        true -> {ok, Opts};
        false -> {error, {config, <<"ProviderWorker backoff options are invalid">>}}
    end.

unknown_options_text(Unknown) ->
    Names = lists:join(<<", ">>, [atom_to_binary(K) || K <- Unknown, is_atom(K)]),
    iolist_to_binary([<<"ProviderWorker: unknown options ">>, Names]).

%% The `HTTPClient' class object the adapter sends requests to: the
%% config's `client' (Beamtalk constructors pass it), else looked up by
%% name, which is how a supervisor's `withArgs:' map reaches here.
http_client(Config) ->
    case maps:find(client, Config) of
        {ok, Client} -> Client;
        error -> beamtalk_class_registry:resolve_class_object('HTTPClient')
    end.

%% The `discover/2' options for this client, preset and options.
shim_opts(Client, Preset, Options) ->
    Base = #{
        client => Client,
        document_overrides => maps:get(documentOverrides, Preset, #{}),
        allow_unsafe_http => maps:get(allowUnsafeHttp, Options, false) =:= true
    },
    Base1 =
        case maps:find(maxBodyBytes, Options) of
            {ok, Max} -> Base#{max_body_bytes => Max};
            error -> Base
        end,
    case maps:find(timeout, Options) of
        {ok, T} -> Base1#{timeout => T};
        error -> Base1
    end.
