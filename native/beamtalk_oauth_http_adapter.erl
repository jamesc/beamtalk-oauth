%% Copyright 2026 oauth authors
%% SPDX-License-Identifier: Apache-2.0

-module(beamtalk_oauth_http_adapter).

-moduledoc """
`oidcc_http_adapter` over Beamtalk's `HTTPClient` (Mint), so every call
oidcc makes shares the package's TLS, redirect, body-cap and proxy
behaviour instead of using `httpc`.

Adapter config: `#{client => HTTPClient class object, max_body_bytes =>
integer() | unlimited}`. The class object is passed in from Beamtalk and
messaged through `beamtalk_message_dispatch:send/3`, so this module does
not depend on how class methods are compiled.

Beamtalk Strings cross as `{beamtalk_string, Bin}`; responses are
converted back to the `httpc` shape oidcc expects: lowercase charlist
header names and a binary body.
""".

-behaviour(oidcc_http_adapter).

-export([request/5]).

-define(DEFAULT_MAX_BODY, 1048576).

-doc "Perform one oidcc request through `HTTPClient request:url:options:`.".
-spec request(Method, Request, HttpOptions, RequestOptions, Config) ->
    {ok, {{string(), non_neg_integer(), string()}, [{string(), string()}], binary()}}
    | {error, term()}
when
    Method :: oidcc_http_adapter:method(),
    Request :: oidcc_http_adapter:request(),
    HttpOptions :: list(),
    RequestOptions :: list(),
    Config :: #{client := term(), max_body_bytes => integer() | unlimited}.
request(Method, Request, HttpOptions, _RequestOptions, #{client := Client} = Config) ->
    {Url, Headers, Body} = split_request(Request),
    Opts0 = #{
        headers => [[str(K), str(V)] || {K, V} <- Headers],
        timeout => proplists:get_value(timeout, HttpOptions, 30000),
        maxBodyBytes => maps:get(max_body_bytes, Config, ?DEFAULT_MAX_BODY)
    },
    Opts =
        case Body of
            none -> Opts0;
            _ -> Opts0#{body => str(Body)}
        end,
    Result = beamtalk_message_dispatch:send(
        Client, 'request:url:options:', [Method, str(Url), Opts]
    ),
    from_result(Result).

split_request({Url, Headers}) ->
    {Url, Headers, none};
split_request({Url, Headers, ContentType, Body}) when is_binary(Body); is_list(Body) ->
    {Url, [{"content-type", ContentType} | Headers], iolist_to_binary(Body)};
split_request({_Url, _Headers, _ContentType, _StreamingBody}) ->
    erlang:error({unsupported_request_body, streaming}).

from_result(#{'$beamtalk_class' := 'Result', isOk := true, okValue := Response}) ->
    #{status := Status, headers := Headers, body := Body} = Response,
    {ok, {
        {"HTTP/1.1", Status, ""},
        [{string:lowercase(chars(K)), chars(V)} || [K, V] <- Headers],
        bin(Body)
    }};
from_result(#{'$beamtalk_class' := 'Result', isOk := false, errReason := Reason}) ->
    {error, {http_client, Reason}}.

str(V) -> {beamtalk_string, iolist_to_binary(V)}.

bin({beamtalk_string, B}) -> B;
bin(B) when is_binary(B) -> B.

chars(V) -> binary_to_list(bin(V)).
