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
`httpc`. Each of its requests times out after 10 s unless the `timeout`
option says otherwise.

The two processes live and die together: the link is not trapped, so if
the `oidcc` worker crashes this process exits with it, and if this
process is shut down by its supervisor the `oidcc` worker gets the same
exit signal. `stop` stops the `oidcc` worker in `terminate/2`.

This process never waits on a load. The `oidcc` worker loads inside its
own callbacks and answers nothing until a load finishes, so this process
keeps the last configuration and JWKS it read (`cache`), and the `server`
reply built from them (`reply`), and answers `server` from that with no
call to the `oidcc` worker. Once `cacheTtl` (default 60 s) has passed
since the last read, a `server` call also starts a re-read in a helper
process, so the cache follows the worker's own scheduled reloads within
one TTL (and one `server` call). Only before the first successful read
does `server` wait (up to 4.5 s, in a helper) for the first load. (The
`oidcc` worker is not registered under a name, so its ETS read path is
not used.)

`refresh` comes through here and is rate-limited to one per `backoffMin`,
so callers cannot pile reloads (each with its own oidcc backoff retry
chain) onto a provider that is down. Unknown-`kid` reloads (from
`beamtalk_oauth_oidcc:call_opts/1`) are limited to one per
`minJwksReloadInterval` (default 30 s). Within it no load starts: a
caller gets the keys the reload under way reads, once it ends, or else
the cached keys at once, so a token naming a key they lack fails
validation without a fetch. A reload refreshes the cache. When it
leaves the keys unchanged and still without the `kid` (the load failed,
or the provider has no such key), the caller is told to load the keys
itself (`undefined`), so a failed reload falls back to a direct load.
The waits run in helper processes, answered with `gen_server:reply/2`.

Config (the `spawnWith:` map, Symbol keys arriving as atoms):

* `issuer` (required) — the issuer to discover;
* `client` — the `HTTPClient` class object, looked up by name when
  absent;
* `preset` — a `ProviderPresets` Dictionary (`documentOverrides` and the
  endpoints discovery omits), default `#{}`;
* `options` — `#{allowUnsafeHttp, maxBodyBytes, timeout}` as for
  `OAuthServer fromDiscovery:preset:options:`, plus `backoffMin`,
  `backoffMax` (ms) and `backoffType` for failed loads (default
  `random_exponential`, 1 s to 30 s), `cacheTtl` (ms, default 60 s) and
  `minJwksReloadInterval` (ms, default 30 s). oidcc's `stop` backoff is refused:
  the worker keeps retrying instead of exiting. `allowUnsafeHttp` also
  needs the test-only application flag (see
  `beamtalk_oauth_oidcc:unsafe_http_enabled/0`).

The state holds no secrets (no client credentials ever reach either
process), and `format_status/1` shows only the issuer and the `oidcc`
worker's pid. The `oidcc` worker has no `format_status/1`: its status and
crash reports show its load options (the adapter config and document
overrides) and the public configuration and keys, none of them secret.

Every request either process makes goes through the HTTP adapter, which
refuses non-HTTPS URLs; `oidcc` alone would fetch a plain-HTTP `jwks_uri`.
""".

-behaviour(gen_server).

-export([start_link/1, check/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, format_status/1]).

%% Every wait for the oidcc worker that a Beamtalk caller sits behind ends
%% within this budget, below the 5 s Beamtalk actor-call timeout.
-define(CALL_TIMEOUT, 4500).

%% How long an unknown-kid reload may wait for the oidcc worker; the shim
%% gives up at 3 s (`beamtalk_oauth_oidcc' ?WORKER_JWKS_TIMEOUT).
-define(KID_RELOAD_TIMEOUT, 2500).

%% Per-request timeout for the oidcc worker's loads, unless `timeout' is
%% given.
-define(LOAD_REQUEST_TIMEOUT, 10000).

%% How long a background cache read waits: a full configuration plus JWKS
%% load at the request timeout, with room to spare.
-define(CACHE_READ_TIMEOUT, 30000).

%% How long `server' answers from the cache before re-reading the oidcc
%% worker, unless `cacheTtl' is given.
-define(CACHE_TTL, 60000).

%% The least time between two unknown-kid JWKS reloads, unless
%% `minJwksReloadInterval' is given.
-define(MIN_JWKS_RELOAD_INTERVAL, 30000).

-define(KNOWN_OPTIONS, [
    allowUnsafeHttp,
    maxBodyBytes,
    timeout,
    backoffMin,
    backoffMax,
    backoffType,
    cacheTtl,
    minJwksReloadInterval
]).

%% No `stop`: the oidcc worker would exit on one failed refresh, and the
%% link would take this process (and an unsupervised caller) with it.
-define(BACKOFF_TYPES, [exponential, random, random_exponential]).

-doc "Start the worker (the native-actor facade calls this with the `spawnWith:` map).".
-spec start_link(map()) -> gen_server:start_ret().
start_link(Config) ->
    gen_server:start_link(?MODULE, Config, []).

-doc """
Check a `spawnWith:` config without starting anything: `nil` when it is
good, else the reason: `{insecure_endpoint, issuer, Url}` or
`{config, Text}`. `ProviderWorker startWith:` calls it first, so a bad
config answers `Result error:` instead of failing the spawn.

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
        ok ?= check_unsafe(Options),
        ok ?= beamtalk_oauth_oidcc:check_https(#{issuer => Issuer}, unsafe(Options)),
        {ok, Issuer}
    end;
validate(_Config) ->
    {error, {config, <<"ProviderWorker config must be a Dictionary">>}}.

init(Config) ->
    beamtalk_oauth_oidcc:ensure_started(),
    case validate(Config) of
        {ok, Issuer} ->
            {ok, Options} = options(Config),
            Preset = maps:get(preset, Config, #{}),
            LoadOpts = beamtalk_oauth_oidcc:load_opts(
                shim_opts(http_client(Config), Preset, Options)
            ),
            BackoffMin = maps:get(backoffMin, Options, 1000),
            WorkerOpts = #{
                issuer => Issuer,
                provider_configuration_opts => LoadOpts,
                backoff_min => BackoffMin,
                backoff_max => maps:get(backoffMax, Options, 30000),
                backoff_type => maps:get(backoffType, Options, random_exponential)
            },
            case oidcc_provider_configuration_worker:start_link(WorkerOpts) of
                {ok, Worker} ->
                    {ok, #{
                        issuer => Issuer,
                        preset => Preset,
                        unsafe => unsafe(Options),
                        request_opts => maps:get(request_opts, LoadOpts),
                        worker => Worker,
                        cache => undefined,
                        reply => undefined,
                        reading => false,
                        next_read => undefined,
                        cache_ttl => maps:get(cacheTtl, Options, ?CACHE_TTL),
                        last_reload => undefined,
                        reload_interval => BackoffMin,
                        last_kid_reload => undefined,
                        kid_waiters => none,
                        kid_reload_interval =>
                            maps:get(minJwksReloadInterval, Options, ?MIN_JWKS_RELOAD_INTERVAL)
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
handle_call({server, []}, From, #{cache := undefined} = State) ->
    %% Nothing read yet: wait for the first load in a helper, so other
    %% callers are not queued behind this one.
    Self = self(),
    read_async(State, ?CALL_TIMEOUT, fun(Read) ->
        gen_server:reply(From, server_reply(Read, State, Self))
    end),
    {noreply, State};
handle_call({server, []}, _From, State0) ->
    {Reply, State} = cached_reply(State0),
    {reply, Reply, read_when_stale(State)};
handle_call({refresh, []}, From, #{worker := Worker} = State0) ->
    State = reload(State0, last_reload, reload_interval, fun() ->
        %% A JWKS reload before any configuration has loaded crashes the
        %% oidcc worker (it reads `jwks_uri' from the missing
        %% configuration), so only the configuration is reloaded then; its
        %% first load chains the JWKS.
        gen_server:cast(Worker, refresh_configuration),
        case State0 of
            #{cache := {_, _}} -> gen_server:cast(Worker, refresh_jwks);
            _ -> ok
        end
    end),
    %% The oidcc worker handles messages in order, so this read is answered
    %% once the reloads have run (or failed into oidcc's backoff retries).
    read_async(State, ?CALL_TIMEOUT, fun(_Read) -> gen_server:reply(From, {ok, nil}) end),
    {noreply, State};
handle_call({beamtalk_oauth_unknown_kid, Kid}, From, #{worker := Worker} = State0) ->
    %% From `beamtalk_oauth_oidcc:call_opts/1': a token names a key we do not
    %% have. The oidcc worker reloads only when its keys lack `Kid'.
    case due(State0, last_kid_reload, kid_reload_interval) of
        false when is_list(map_get(kid_waiters, State0)) ->
            %% A reload is under way: answered with its keys when it ends.
            {noreply, State0#{kid_waiters := [From | map_get(kid_waiters, State0)]}};
        false ->
            %% Within the interval: no load. The caller validates with the
            %% newest keys read, and fails if they lack `Kid'.
            {reply, cached_jwks(State0), State0};
        {true, Now} ->
            Self = self(),
            spawn(fun() ->
                try
                    Deadline = erlang:monotonic_time(millisecond) + ?KID_RELOAD_TIMEOUT,
                    %% The keys before the reload. The oidcc worker handles
                    %% messages in order: the cast after this call, the
                    %% reads below after the reload.
                    Before = fetch(Worker, get_jwks, Deadline),
                    gen_server:cast(Worker, {refresh_jwks_for_unknown_kid, Kid}),
                    Read = read(Worker, Deadline),
                    Self ! {beamtalk_oauth_read, false, Read},
                    gen_server:reply(From, kid_reply(Read, Before, Kid))
                after
                    Self ! beamtalk_oauth_kid_reloaded
                end
            end),
            {noreply, State0#{last_kid_reload => Now, kid_waiters => []}}
    end;
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

%% A helper's read of the oidcc worker: keep it when both parts are there.
%% A new configuration or JWKS drops the built `server' reply.
handle_info({beamtalk_oauth_read, Background, Read}, #{cache := Cache} = State0) ->
    State1 =
        case Read of
            {ok, Cache} -> fresh(State0);
            {ok, Loaded} -> fresh(State0#{cache => Loaded, reply => undefined});
            _ -> State0
        end,
    State =
        case Background of
            true -> State1#{reading => false};
            false -> State1
        end,
    {noreply, State};
%% An unknown-kid reload ended (its read handled just before): callers that
%% came in meanwhile get the keys now cached.
handle_info(beamtalk_oauth_kid_reloaded, #{kid_waiters := Waiters} = State) ->
    Reply = cached_jwks(State),
    lists:foreach(fun(From) -> gen_server:reply(From, Reply) end, Waiters),
    {noreply, State#{kid_waiters := none}};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #{worker := Worker}) ->
    _ = catch gen_server:stop(Worker, normal, ?CALL_TIMEOUT),
    ok;
terminate(_Reason, _State) ->
    ok.

-doc """
`sys:get_status/1` and crash reports: the issuer and the `oidcc` worker's
pid only. The preset, request options (the adapter config) and cached
configuration are left out; none of them is secret, but nothing here
needs them.
""".
format_status(#{state := #{issuer := Issuer, worker := Worker}} = Status) ->
    Status#{state => #{issuer => Issuer, worker => Worker}};
format_status(Status) ->
    Status.

%% The `server' reply for a read of the oidcc worker: `Result ok:' an
%% `OAuthServer' (built by `OAuthServer fromShim:preset:', as
%% `fromDiscovery:' builds one) or `Result error:' an `OAuthError'.
server_reply(Read, State, Self) ->
    try
        case Read of
            {ok, Loaded} -> {ok, build(Loaded, State, Self)};
            {partial, Config} -> {ok, error_result(partial_reason(Config, State))};
            {error, Failed} -> {ok, error_result(Failed)}
        end
    catch
        %% No stacktrace: its frames would carry the configuration.
        Class:Reason -> {error, {Class, Reason}}
    end.

%% Why a configuration without keys gives no server: an insecure endpoint
%% (the likely cause), else the keys are not loaded yet.
partial_reason(Config, #{unsafe := Unsafe}) ->
    case beamtalk_oauth_oidcc:check_endpoints(Config, Unsafe) of
        ok -> provider_unavailable;
        {error, Reason} -> Reason
    end.

build({Config, Jwks}, #{preset := Preset, unsafe := Unsafe, request_opts := RequestOpts}, Self) ->
    case beamtalk_oauth_oidcc:check_endpoints(Config, Unsafe) of
        ok ->
            Info = beamtalk_oauth_oidcc:provider_info(Config, Jwks, RequestOpts, #{
                provider_worker => Self
            }),
            beamtalk_result:'ok:'(send_class('OAuthServer', 'fromShim:preset:', [Info, Preset]));
        {error, Reason} ->
            error_result(Reason)
    end.

error_result(Reason) ->
    beamtalk_result:'makeError:'(send_class('OAuthError', 'fromOidcc:', [Reason])).

%% A class-side send to one of this package's classes. Native code has no
%% supported send API yet (BT-4556); the HTTP adapter uses the same call.
send_class(ClassName, Selector, Args) ->
    case beamtalk_class_registry:resolve_class_object(ClassName) of
        undefined -> erlang:error({class_not_loaded, ClassName});
        Class -> beamtalk_message_dispatch:send(Class, Selector, Args)
    end.

%% The `server' reply for the cache, built once per cache contents (the
%% `OAuthServer' is an immutable value).
cached_reply(#{reply := Reply} = State) when Reply =/= undefined ->
    {Reply, State};
cached_reply(#{cache := Loaded} = State) ->
    case server_reply({ok, Loaded}, State, self()) of
        {ok, _} = Reply -> {Reply, State#{reply => Reply}};
        Failed -> {Failed, State}
    end.

%% What an unknown-kid caller gets within the reload interval: the cached
%% JWKS, or `busy' (go on with your own keys) when none is cached.
cached_jwks(#{cache := {_Config, Jwks}}) -> Jwks;
cached_jwks(_State) -> busy.

%% The unknown-kid answer after a reload: the keys, when they name `Kid' or
%% changed; `undefined' (load directly) when they are unchanged and still
%% lack `Kid' (the reload failed, or the provider has no such key) or none
%% are loaded; `busy' when the oidcc worker did not answer in time.
kid_reply({ok, {_Config, Jwks}}, Before, Kid) ->
    case beamtalk_oauth_oidcc:has_kid(Jwks, Kid) orelse Before =/= {ok, Jwks} of
        true -> Jwks;
        false -> undefined
    end;
kid_reply({error, {provider_unavailable, timeout}}, _Before, _Kid) ->
    busy;
kid_reply(_NothingLoaded, _Before, _Kid) ->
    undefined.

%% The cache was just read: the next background read is one TTL away.
fresh(#{cache_ttl := Ttl} = State) ->
    State#{next_read => erlang:monotonic_time(millisecond) + Ttl}.

%% `{true, Now}' when no reload is recorded under `LastKey', or the last
%% one was at least the `IntervalKey' ms ago; else `false'.
due(State, LastKey, IntervalKey) ->
    #{LastKey := Last, IntervalKey := Interval} = State,
    Now = erlang:monotonic_time(millisecond),
    case Last =:= undefined orelse Now - Last >= Interval of
        true -> {true, Now};
        false -> false
    end.

%% Run `Start' (casts asking the oidcc worker to reload) when a reload is
%% `due/3'; else the caller gets the current state instead.
reload(State, LastKey, IntervalKey, Start) ->
    case due(State, LastKey, IntervalKey) of
        {true, Now} ->
            Start(),
            State#{LastKey => Now};
        false ->
            State
    end.

%% Re-read the oidcc worker, without waiting for it, once the TTL has
%% passed: one background read at a time, and at most one per TTL even
%% when reads fail.
read_when_stale(#{reading := true} = State) ->
    State;
read_when_stale(#{next_read := Next} = State) when is_integer(Next) ->
    case erlang:monotonic_time(millisecond) >= Next of
        true -> read_in_background(fresh(State));
        false -> State
    end;
read_when_stale(State) ->
    read_in_background(fresh(State)).

read_in_background(#{worker := Worker} = State) ->
    Self = self(),
    spawn(fun() ->
        Deadline = erlang:monotonic_time(millisecond) + ?CACHE_READ_TIMEOUT,
        Self ! {beamtalk_oauth_read, true, read(Worker, Deadline)}
    end),
    State#{reading => true}.

%% Read the oidcc worker from a helper within `Timeout', hand the result to
%% this process's cache, then call `Then' with it (in the helper).
read_async(#{worker := Worker}, Timeout, Then) ->
    Self = self(),
    spawn(fun() ->
        Read = read(Worker, erlang:monotonic_time(millisecond) + Timeout),
        Self ! {beamtalk_oauth_read, false, Read},
        Then(Read)
    end),
    ok.

%% `{ok, {Config, Jwks}}' from the oidcc worker by `Deadline';
%% `{partial, Config}' when the configuration loaded but no JWKS has (its
%% load failed, say because the adapter refused a plain-HTTP `jwks_uri');
%% else `{error, provider_unavailable | {provider_unavailable, timeout}}'.
read(Worker, Deadline) ->
    maybe
        {ok, Config} ?= fetch(Worker, get_provider_configuration, Deadline),
        case fetch(Worker, get_jwks, Deadline) of
            {ok, Jwks} -> {ok, {Config, Jwks}};
            {error, provider_unavailable} -> {partial, Config};
            Error -> Error
        end
    end.

fetch(Worker, Call, Deadline) ->
    Timeout = max(0, Deadline - erlang:monotonic_time(millisecond)),
    try gen_server:call(Worker, Call, Timeout) of
        undefined -> {error, provider_unavailable};
        Value -> {ok, Value}
    catch
        exit:{timeout, _} -> {error, {provider_unavailable, timeout}};
        exit:_ -> {error, provider_unavailable}
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

unsafe(Options) ->
    maps:get(allowUnsafeHttp, Options, false) =:= true.

check_unsafe(Options) ->
    case unsafe(Options) andalso not beamtalk_oauth_oidcc:unsafe_http_enabled() of
        true -> {error, {config, <<"#allowUnsafeHttp is for tests only and is not enabled">>}};
        false -> ok
    end.

check_backoff(Opts) ->
    Type = maps:get(backoffType, Opts, random_exponential),
    Min = maps:get(backoffMin, Opts, 1000),
    Max = maps:get(backoffMax, Opts, 30000),
    case
        lists:member(Type, ?BACKOFF_TYPES) andalso is_integer(Min) andalso Min > 0 andalso
            is_integer(Max) andalso Max >= Min
    of
        true -> check_intervals(Opts);
        false -> {error, {config, <<"ProviderWorker backoff options are invalid">>}}
    end.

check_intervals(Opts) ->
    Bad = [
        K
     || K <- [cacheTtl, minJwksReloadInterval],
        not is_non_neg_integer(maps:get(K, Opts, 0))
    ],
    case Bad of
        [] ->
            {ok, Opts};
        [K | _] ->
            {error,
                {config,
                    iolist_to_binary([
                        <<"ProviderWorker #">>, atom_to_binary(K), <<" must be an Integer >= 0">>
                    ])}}
    end.

is_non_neg_integer(N) -> is_integer(N) andalso N >= 0.

unknown_options_text(Unknown) ->
    Names = lists:join(<<", ">>, [atom_to_binary(K) || K <- Unknown, is_atom(K)]),
    iolist_to_binary([<<"ProviderWorker: unknown options ">>, Names]).

%% The `HTTPClient' class object the adapter sends requests to: the
%% config's `client' (Beamtalk constructors pass it), else looked up by
%% name.
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
        allow_unsafe_http => unsafe(Options),
        timeout => maps:get(timeout, Options, ?LOAD_REQUEST_TIMEOUT)
    },
    case maps:find(maxBodyBytes, Options) of
        {ok, Max} -> Base#{max_body_bytes => Max};
        error -> Base
    end.
