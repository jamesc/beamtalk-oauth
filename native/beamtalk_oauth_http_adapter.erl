%% Copyright 2026 James Casey
%% SPDX-License-Identifier: Apache-2.0

-module(beamtalk_oauth_http_adapter).

-moduledoc """
`oidcc_http_adapter` over Beamtalk's `HTTPClient` (Mint), so every call
`oidcc` makes shares the package's TLS, no-redirect and body-cap behaviour
instead of using `httpc`.

Adapter config: `#{client => HTTPClient class object, max_body_bytes =>
non_neg_integer() | unlimited, allow_unsafe_http => boolean()}`. The class object is passed in from
Beamtalk and messaged through `beamtalk_message_dispatch:send/3`, so this
module does not depend on how class methods are compiled. (That module is
internal to the Beamtalk runtime; BT-4556 tracks a supported API.)

Beamtalk Strings cross as `{beamtalk_string, Bin}`, and a `Result` arrives
as a map. Requests are tagged on the way out; responses are converted
back to the `httpc` shape `oidcc` expects: lowercase charlist header names
and a binary body.

Every failure but a `response_check` refusal and a `deadline` (below) answers
`{error, {http_client, Reason}}`, where `Reason` is
the `HTTPClient` error's message (a binary) or a fixed atom. It never
carries the request: no URL query, headers or body, which hold codes,
secrets and tokens.

With `capture => true` in the config, the body of each successful `POST`
response is also kept in the calling process's dictionary under
`beamtalk_oauth_captured_body` (see `take_captured/0`). The shim uses
this for refresh: `oidcc_token:refresh/3` discards a response that has
no ID token, and the shim must still read it.

With `response_check => Fun` in the config, each response is passed to
`Fun(Method, Url, {ok, Response}, AllowUnsafe)` before `oidcc` sees it;
an `{error, Reason}` from it is answered as is (not wrapped in
`http_client`). The shim uses this to HTTPS-check the distributed-claim
endpoints a userinfo response names before `oidcc` fetches them
(`beamtalk_oauth_oidcc:check_claim_sources/2`).

With `deadline => At` in the config (absolute, in
`erlang:monotonic_time(millisecond)`), the operation's deadline set by
`beamtalk_oauth_oidcc:call_opts/1`, each request times out at what is
left of it, or at `oidcc`'s timeout if that is sooner. Once nothing is
left no request starts. A spent deadline, or a request that failed
without a response once the deadline had passed, answers
`{error, deadline_exceeded}` (not wrapped in `http_client`).

A `200` answer to a `GET` of a discovery document is handed to
`beamtalk_oauth_oidcc:mark_discovery/3`, which marks a document that
leaves out `revocation_endpoint_auth_methods_supported` (so the marker
survives `oidcc` applying the RFC 8414 default).

With `load_observer => Pid` in the config, `Pid` is sent
`{beamtalk_oauth_load, configuration | jwks, started}` before each
request and `{beamtalk_oauth_load, configuration | jwks, ok | failed}`
after it: `configuration` for a discovery document, else `jwks`, and `ok`
for a `200` or `201` whose body is a JSON object. `ProviderWorker` sets
it on its `oidcc` worker's loads only, to learn which of them is running
or failed (and so has an `oidcc` backoff retry pending).

Every URL must be HTTPS (`{error, {http_client, insecure_url}}`
otherwise), whatever `oidcc` accepted: `oidcc` itself takes a plain-HTTP
`jwks_uri`, and an `oidcc_provider_configuration_worker` fetches it
before Beamtalk code sees the configuration. `allow_unsafe_http` (tests
only) also admits plain HTTP on a loopback host, as
`beamtalk_oauth_oidcc:check_https/2` does. Each refusal emits the
telemetry event `[beamtalk_oauth, http_adapter, refused]` (metadata
`#{reason => insecure_url}`, or `#{reason => insecure_claim_source}` for a
`response_check` refusal), so a refused background load is visible.
""".

-behaviour(oidcc_http_adapter).

-export([request/5, take_captured/0]).

-define(CAPTURE_KEY, beamtalk_oauth_captured_body).

-doc """
The last captured `POST` response body, removed from the process
dictionary, or `none`.
""".
-spec take_captured() -> binary() | none.
take_captured() ->
    case erase(?CAPTURE_KEY) of
        undefined -> none;
        Body -> Body
    end.

-define(DEFAULT_MAX_BODY, 1048576).

%% Emitted for every refused request or response, with
%% `#{reason => insecure_url | insecure_claim_source}' as metadata (never
%% the URL).
-define(REFUSED_EVENT, [beamtalk_oauth, http_adapter, refused]).
%% oidcc's own default; used when oidcc passes `infinity`, which
%% `HTTPClient` does not accept.
-define(DEFAULT_TIMEOUT, 60000).

-doc """
Perform one `oidcc` request through `HTTPClient request:url:options:`.

`#maxBodyBytes` defaults to 1 MiB and the timeout comes from `oidcc`'s
`HttpOptions`. A streaming request body, malformed headers and `ssl`
options are refused (`{error, {http_client, streaming_request_body |
malformed_headers | unsupported_ssl_options | insecure_url}}`); any crash answers
`{error, {http_client, {raised, Class}}}`.
""".
-spec request(Method, Request, HttpOptions, RequestOptions, Config) ->
    {ok, {{string(), non_neg_integer(), string()}, [{string(), string()}], binary()}}
    | {error, term()}
when
    Method :: oidcc_http_adapter:method(),
    Request :: oidcc_http_adapter:request(),
    HttpOptions :: oidcc_http_adapter:http_options(),
    RequestOptions :: oidcc_http_adapter:request_options(),
    Config :: #{
        client := term(),
        max_body_bytes => non_neg_integer() | unlimited,
        allow_unsafe_http => boolean(),
        capture => boolean(),
        deadline => integer(),
        response_check => fun((atom(), term(), {ok, term()}, boolean()) -> ok | {error, term()})
    }.
request(Method, Request, HttpOptions, _RequestOptions, #{client := Client} = Config) ->
    %% Everything runs inside the try: a crash anywhere here (a header
    %% value that is not iodata, a response of an unexpected shape) must
    %% not escape with the request in its stacktrace or arguments, where
    %% oidcc's telemetry span would re-emit it. It becomes a fixed reason.
    case time_left(Config) of
        0 ->
            %% The operation's deadline is spent: no request starts.
            {error, deadline_exceeded};
        Left ->
            observe(Request, started, Config),
            Answer =
                try
                    do_request(Method, Request, clamp(HttpOptions, Left), Client, Config)
                catch
                    Class:_Reason -> {error, {http_client, {raised, Class}}}
                end,
            observe(Request, outcome(Answer), Config),
            past_deadline(Answer, Config)
    end.

%% Milliseconds left of the config's `deadline' (absolute, monotonic ms),
%% at least 0; `infinity' when it has none.
time_left(#{deadline := Deadline}) when is_integer(Deadline) ->
    max(0, Deadline - erlang:monotonic_time(millisecond));
time_left(_Config) ->
    infinity.

%% `HttpOptions' with the request timeout cut to `Left' ms when that is
%% sooner.
clamp(HttpOptions, infinity) ->
    HttpOptions;
clamp(HttpOptions, Left) ->
    Timeout = min(Left, timeout(proplists:get_value(timeout, HttpOptions, ?DEFAULT_TIMEOUT))),
    [{timeout, Timeout} | proplists:delete(timeout, HttpOptions)].

%% A request that failed (no response) once the deadline had passed was
%% cut short by it: `{error, deadline_exceeded}'.
past_deadline({error, {http_client, _}} = Answer, Config) ->
    case time_left(Config) of
        0 -> {error, deadline_exceeded};
        _ -> Answer
    end;
past_deadline(Answer, _Config) ->
    Answer.

%% Tell the config's `load_observer', if any, about the request:
%% `{beamtalk_oauth_load, configuration | jwks, started | ok | failed}',
%% by whether the URL is a discovery document.
observe(Request, Event, #{load_observer := Observer}) when is_pid(Observer) ->
    Kind =
        try beamtalk_oauth_oidcc:is_discovery_url(element(1, Request)) of
            true -> configuration;
            false -> jwks
        catch
            _:_ -> jwks
        end,
    Observer ! {beamtalk_oauth_load, Kind, Event},
    ok;
observe(_Request, _Event, _Config) ->
    ok.

%% `ok' for an answer `oidcc' can load from: a 200 or 201 (the statuses it
%% takes as success) whose body is a JSON object. Anything else (an error
%% status, a maintenance page served as a 200) fails the load.
outcome({ok, {{_, Status, _}, _Headers, Body}}) when Status =:= 200; Status =:= 201 ->
    try json:decode(Body) of
        Doc when is_map(Doc) -> ok;
        _ -> failed
    catch
        _:_ -> failed
    end;
outcome(_Answer) ->
    failed.

do_request(Method, Request, HttpOptions, Client, Config) ->
    maybe
        ok ?= check_http_options(HttpOptions),
        {Url, Headers, Body} ?= split_request(Request),
        {ok, HeaderPairs} ?= headers(Headers),
        ok ?= check_url(Url, unsafe(Config)),
        Opts0 = #{
            headers => HeaderPairs,
            timeout => timeout(proplists:get_value(timeout, HttpOptions, ?DEFAULT_TIMEOUT)),
            maxBodyBytes => maps:get(max_body_bytes, Config, ?DEFAULT_MAX_BODY)
        },
        Opts =
            case Body of
                none -> Opts0;
                _ -> Opts0#{body => str(Body)}
            end,
        Answer = from_result(
            beamtalk_message_dispatch:send(Client, 'request:url:options:', [Method, str(Url), Opts])
        ),
        capture(Method, Answer, Config),
        ok ?= check_response(Method, Url, Answer, Config),
        mark_discovery(Method, Url, Answer)
    else
        {response_refused, Reason} -> {error, Reason};
        {error, Reason} -> {error, {http_client, Reason}}
    end.

%% The config's `response_check`, if any, on a response that arrived:
%% `ok`, or `{response_refused, Reason}`, answered as `{error, Reason}`.
check_response(Method, Url, {ok, _} = Answer, #{response_check := Check} = Config) when
    is_function(Check, 4)
->
    case Check(Method, Url, Answer, unsafe(Config)) of
        ok -> ok;
        {error, Reason} ->
            telemetry:execute(?REFUSED_EVENT, #{count => 1}, #{reason => insecure_claim_source}),
            {response_refused, Reason}
    end;
check_response(_Method, _Url, _Answer, _Config) ->
    ok.

capture(post, {ok, {_Status, _Headers, Body}}, #{capture := true}) ->
    put(?CAPTURE_KEY, Body),
    ok;
capture(_Method, _Answer, _Config) ->
    ok.

%% A discovery document is passed through the shim, which records whether
%% the provider named its revocation auth methods before `oidcc` fills in
%% the RFC 8414 default (`beamtalk_oauth_oidcc:mark_discovery/3`).
%% Only a 200 is a document: an error body at that URL is left as served.
mark_discovery(Method, Url, {ok, {{_, 200, _} = Status, Headers, Body}}) ->
    {ok, {Status, Headers, beamtalk_oauth_oidcc:mark_discovery(Method, Url, Body)}};
mark_discovery(_Method, _Url, Answer) ->
    Answer.

%% The opt-in counts only while the test-only application flag is set.
unsafe(Config) ->
    maps:get(allow_unsafe_http, Config, false) =:= true andalso
        beamtalk_oauth_oidcc:unsafe_http_enabled().

%% HTTPS only (plain HTTP on loopback with the test-only opt-in). The
%% reason never carries the URL.
check_url(Url, Unsafe) ->
    case beamtalk_oauth_oidcc:check_https(#{request_url => iolist_to_binary(Url)}, Unsafe) of
        ok -> ok;
        {error, _} ->
            telemetry:execute(?REFUSED_EVENT, #{count => 1}, #{reason => insecure_url}),
            {error, insecure_url}
    end.

%% `HTTPClient` has no per-request TLS options, so `ssl` options (custom
%% CAs, client certificates for `tls_client_auth`) would be silently
%% dropped. Refuse them instead.
check_http_options(HttpOptions) ->
    case proplists:is_defined(ssl, HttpOptions) of
        true -> {error, unsupported_ssl_options};
        false -> ok
    end.

%% Request headers as `[Name, Value]` String pairs; anything that is not
%% a `{Name, Value}` pair is refused rather than dropped.
headers(Headers) when is_list(Headers) ->
    case lists:all(fun(H) -> is_tuple(H) andalso tuple_size(H) =:= 2 end, Headers) of
        true -> {ok, [[str(K), str(V)] || {K, V} <- Headers]};
        false -> {error, malformed_headers}
    end;
headers(_) ->
    {error, malformed_headers}.

split_request({Url, Headers}) ->
    {Url, Headers, none};
split_request({Url, Headers, ContentType, Body}) when is_binary(Body); is_list(Body) ->
    {Url, [{"content-type", ContentType} | Headers], iolist_to_binary(Body)};
split_request({_Url, _Headers, _ContentType, _StreamingBody}) ->
    {error, streaming_request_body};
split_request(_Other) ->
    {error, malformed_request}.

timeout(T) when is_integer(T), T >= 0 -> T;
timeout(_) -> ?DEFAULT_TIMEOUT.

from_result(#{'$beamtalk_class' := 'Result', isOk := true, okValue := Response}) ->
    #{status := Status, headers := Headers, body := Body} = Response,
    {ok, {
        {"HTTP/1.1", Status, ""},
        [{string:lowercase(chars(K)), chars(V)} || [K, V] <- Headers],
        bin(Body)
    }};
from_result(#{'$beamtalk_class' := 'Result', isOk := false, errReason := Reason}) ->
    {error, {http_client, message(Reason)}};
from_result(_Other) ->
    {error, {http_client, unexpected_result}}.

%% The error's message text. `HTTPClient` builds it from a fixed hint and
%% the transport reason (`Request failed (econnrefused)`), never from the
%% request.
message(Reason) ->
    try beamtalk_message_dispatch:send(Reason, message, []) of
        {beamtalk_string, Text} -> Text;
        Text when is_binary(Text) -> Text;
        _ -> unknown
    catch
        _:_ -> unknown
    end.

str(V) -> {beamtalk_string, iolist_to_binary(V)}.

bin({beamtalk_string, B}) -> B;
bin(B) when is_binary(B) -> B.

chars(V) -> binary_to_list(bin(V)).
