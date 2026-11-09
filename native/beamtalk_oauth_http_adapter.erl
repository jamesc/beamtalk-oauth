%% Copyright 2026 James Casey
%% SPDX-License-Identifier: Apache-2.0

-module(beamtalk_oauth_http_adapter).

-moduledoc """
`oidcc_http_adapter` over Beamtalk's `HTTPClient` (Mint), so every call
`oidcc` makes shares the package's TLS, no-redirect and body-cap behaviour
instead of using `httpc`.

Adapter config: `#{client => HTTPClient class object, max_body_bytes =>
non_neg_integer() | unlimited}`. The class object is passed in from
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
""".

-behaviour(oidcc_http_adapter).

-export([request/5]).

-define(DEFAULT_MAX_BODY, 1048576).
%% oidcc's own default; used when oidcc passes `infinity`, which
%% `HTTPClient` does not accept.
-define(DEFAULT_TIMEOUT, 60000).

-doc """
Perform one `oidcc` request through `HTTPClient request:url:options:`.

`#maxBodyBytes` defaults to 1 MiB and the timeout comes from `oidcc`'s
`HttpOptions`. A streaming request body is refused with
`{error, {http_client, streaming_request_body}}`.
""".
-spec request(Method, Request, HttpOptions, RequestOptions, Config) ->
    {ok, {{string(), non_neg_integer(), string()}, [{string(), string()}], binary()}}
    | {error, {http_client, term()}}
when
    Method :: oidcc_http_adapter:method(),
    Request :: oidcc_http_adapter:request(),
    HttpOptions :: oidcc_http_adapter:http_options(),
    RequestOptions :: oidcc_http_adapter:request_options(),
    Config :: #{client := term(), max_body_bytes => non_neg_integer() | unlimited}.
request(Method, Request, HttpOptions, _RequestOptions, #{client := Client} = Config) ->
    case split_request(Request) of
        {error, Reason} ->
            {error, {http_client, Reason}};
        {Url, Headers, Body} ->
            Opts0 = #{
                headers => [[str(K), str(V)] || {K, V} <- Headers],
                timeout => timeout(proplists:get_value(timeout, HttpOptions, ?DEFAULT_TIMEOUT)),
                maxBodyBytes => maps:get(max_body_bytes, Config, ?DEFAULT_MAX_BODY)
            },
            Opts =
                case Body of
                    none -> Opts0;
                    _ -> Opts0#{body => str(Body)}
                end,
            send(Client, Method, str(Url), Opts)
    end.

%% A raise inside `HTTPClient` (a type error on a bad option, a crash in
%% the transport) must not escape with the request in its stacktrace or
%% arguments, so it becomes a fixed reason.
send(Client, Method, Url, Opts) ->
    try beamtalk_message_dispatch:send(Client, 'request:url:options:', [Method, Url, Opts]) of
        Result -> from_result(Result)
    catch
        Class:_Reason -> {error, {http_client, {raised, Class}}}
    end.

split_request({Url, Headers}) ->
    {Url, Headers, none};
split_request({Url, Headers, ContentType, Body}) when is_binary(Body); is_list(Body) ->
    {Url, [{"content-type", ContentType} | Headers], iolist_to_binary(Body)};
split_request({_Url, _Headers, _ContentType, _StreamingBody}) ->
    {error, streaming_request_body}.

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
