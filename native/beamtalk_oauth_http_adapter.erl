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

Every failure answers `{error, {http_client, Reason}}`, where `Reason` is
the `HTTPClient` error's message (a binary) or a fixed atom. It never
carries the request: no URL query, headers or body, which hold codes,
secrets and tokens.

With `capture => true` in the config, the body of each successful `POST`
response is also kept in the calling process's dictionary under
`beamtalk_oauth_captured_body` (see `take_captured/0`). The shim uses
this for refresh: `oidcc_token:refresh/3` discards a response that has
no ID token, and the shim must still read it.

Every URL must be HTTPS (`{error, {http_client, insecure_url}}`
otherwise), whatever `oidcc` accepted: `oidcc` itself takes a plain-HTTP
`jwks_uri`, and an `oidcc_provider_configuration_worker` fetches it
before Beamtalk code sees the configuration. `allow_unsafe_http` (tests
only) also admits plain HTTP on a loopback host, as
`beamtalk_oauth_oidcc:check_https/2` does. Each refusal emits the
telemetry event `[beamtalk_oauth, http_adapter, refused]` (metadata
`#{reason => insecure_url}`), so a refused background load is visible.
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

%% Emitted for every refused request, with `#{reason => insecure_url}' as
%% metadata (never the URL).
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
    | {error, {http_client, term()}}
when
    Method :: oidcc_http_adapter:method(),
    Request :: oidcc_http_adapter:request(),
    HttpOptions :: oidcc_http_adapter:http_options(),
    RequestOptions :: oidcc_http_adapter:request_options(),
    Config :: #{
        client := term(),
        max_body_bytes => non_neg_integer() | unlimited,
        allow_unsafe_http => boolean()
    }.
request(Method, Request, HttpOptions, _RequestOptions, #{client := Client} = Config) ->
    %% Everything runs inside the try: a crash anywhere here (a header
    %% value that is not iodata, a response of an unexpected shape) must
    %% not escape with the request in its stacktrace or arguments, where
    %% oidcc's telemetry span would re-emit it. It becomes a fixed reason.
    try
        do_request(Method, Request, HttpOptions, Client, Config)
    catch
        Class:_Reason -> {error, {http_client, {raised, Class}}}
    end.

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
        Answer
    else
        {error, Reason} -> {error, {http_client, Reason}}
    end.

capture(post, {ok, {_Status, _Headers, Body}}, #{capture := true}) ->
    put(?CAPTURE_KEY, Body),
    ok;
capture(_Method, _Answer, _Config) ->
    ok.

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
