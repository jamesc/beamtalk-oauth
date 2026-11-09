%% Copyright 2026 oauth authors
%% SPDX-License-Identifier: Apache-2.0

-module(beamtalk_oauth_oidcc).

-moduledoc """
Phase 0 wire-check shim between Beamtalk and oidcc.
""".

-include_lib("oidcc/include/oidcc_provider_configuration.hrl").
-include_lib("oidcc/include/oidcc_token.hrl").

-export([probe/0, discover/2, adapter_get/2, fixture_token_response/0, fixture_retrieve/3, fixture_retrieve/4,
    gitlab_context/2, live_authorize_url/5, live_exchange/6]).

-doc "Proves oidcc and jose are loadable and startable from Beamtalk.".
probe() ->
    {ok, _} = application:ensure_all_started(oidcc),
    {ok, Vsn} = application:get_key(oidcc, vsn),
    list_to_binary(Vsn).

-doc "Runs oidcc discovery for Issuer with every request over HTTPClient.".
discover(Issuer, Client) ->
    {ok, _} = application:ensure_all_started(oidcc),
    Opts = #{request_opts => #{http_adapter => adapter(Client)}},
    case oidcc_provider_configuration:load_configuration(bin(Issuer), Opts) of
        {ok, {Config, _Expiry}} ->
            JwksUri = element(#oidcc_provider_configuration.jwks_uri, Config),
            {ok, {Jwks, _}} = oidcc_provider_configuration:load_jwks(JwksUri, Opts),
            {jose_jwk, _, _, _} = Jwks,
            {ok, #{
                issuer => Config#oidcc_provider_configuration.issuer,
                token_endpoint => Config#oidcc_provider_configuration.token_endpoint,
                jwks_uri => JwksUri
            }};
        {error, Reason} ->
            {error, Reason}
    end.

-doc """
Fixture provider, step 1: mints an EC key and a token response whose
ID token is signed with it. Answers `{Body, State}`: Beamtalk serves
`Body` from the token endpoint and hands `State` back to
`fixture_retrieve/3`.
""".
fixture_token_response() ->
    {ok, _} = application:ensure_all_started(oidcc),
    Key = jose_jwk:generate_key({ec, <<"P-256">>}),
    Now = erlang:system_time(second),
    Claims = #{
        <<"iss">> => <<"https://issuer.test">>,
        <<"sub">> => <<"user-1">>,
        <<"aud">> => <<"client-1">>,
        <<"iat">> => Now,
        <<"exp">> => Now + 300,
        <<"nonce">> => <<"nonce-1">>
    },
    {_, IdToken} = jose_jws:compact(jose_jwt:sign(Key, #{<<"alg">> => <<"ES256">>}, Claims)),
    Body = iolist_to_binary(
        json:encode(#{
            <<"access_token">> => <<"at-1">>,
            <<"token_type">> => <<"Bearer">>,
            <<"expires_in">> => 3600,
            <<"refresh_token">> => <<"rt-1">>,
            <<"scope">> => <<"openid">>,
            <<"id_token">> => IdToken
        })
    ),
    {{beamtalk_string, Body}, jose_jwk:to_public(Key)}.

-doc """
Fixture provider, step 2: exchanges a code at `TokenUrl` through the
adapter, with PKCE required and the ID token validated by oidcc.
""".
fixture_retrieve(TokenUrl, PublicKey, Client) ->
    fixture_retrieve(TokenUrl, PublicKey, Client, <<"nonce-1">>).

-doc "As `fixture_retrieve/3`, expecting `Nonce` in the ID token.".
fixture_retrieve(TokenUrl, PublicKey, Client, Nonce) ->
    try
        do_fixture_retrieve(TokenUrl, PublicKey, Client, bin(Nonce))
    catch
        error:{badmatch, Bad}:St -> {error, {badmatch, Bad, hd(St)}}
    end.

do_fixture_retrieve(TokenUrl, PublicKey, Client, Nonce) ->
    {ok, Config0} = oidcc_provider_configuration:decode_configuration(#{
        <<"issuer">> => <<"https://issuer.test">>,
        <<"authorization_endpoint">> => <<"https://issuer.test/authorize">>,
        <<"token_endpoint">> => <<"https://issuer.test/token">>,
        <<"jwks_uri">> => <<"https://issuer.test/jwks">>,
        <<"response_types_supported">> => [<<"code">>],
        <<"scopes_supported">> => [<<"openid">>],
        <<"subject_types_supported">> => [<<"public">>],
        <<"id_token_signing_alg_values_supported">> => [<<"ES256">>],
        <<"token_endpoint_auth_methods_supported">> => [<<"client_secret_basic">>],
        <<"code_challenge_methods_supported">> => [<<"S256">>]
    }),
    Config = Config0#oidcc_provider_configuration{token_endpoint = bin(TokenUrl)},
    Context = oidcc_client_context:from_manual(
        Config, PublicKey, <<"client-1">>, <<"secret-1">>
    ),
    Result = oidcc_token:retrieve(<<"code-1">>, Context, #{
        redirect_uri => <<"http://127.0.0.1/callback">>,
        nonce => Nonce,
        pkce_verifier => <<"verifier-verifier-verifier-verifier-verifier-1">>,
        require_pkce => true,
        request_opts => #{http_adapter => adapter(Client)}
    }),
    case Result of
        {ok, #oidcc_token{id = Id, access = Access, refresh = Refresh}} ->
            {ok, #{
                sub => maps:get(<<"sub">>, Id#oidcc_token_id.claims),
                access_token => Access#oidcc_token_access.token,
                refresh_token => Refresh#oidcc_token_refresh.token
            }};
        {error, Reason} ->
            {error, Reason}
    end.

-doc """
Live check: a public-client context for gitlab.com. GitLab advertises
only secret-based token auth, so the override adds `none`.
""".
gitlab_context(ClientId, Client) ->
    {ok, _} = application:ensure_all_started(oidcc),
    Opts = #{
        request_opts => #{http_adapter => adapter(Client)},
        quirks => #{
            document_overrides => #{
                <<"token_endpoint_auth_methods_supported">> =>
                    [<<"none">>, <<"client_secret_basic">>, <<"client_secret_post">>]
            }
        }
    },
    {ok, {Config, _}} = oidcc_provider_configuration:load_configuration(
        <<"https://gitlab.com">>, Opts
    ),
    {ok, {Jwks, _}} = oidcc_provider_configuration:load_jwks(
        Config#oidcc_provider_configuration.jwks_uri, Opts
    ),
    oidcc_client_context:from_manual(Config, Jwks, bin(ClientId), unauthenticated).

-doc "Live check: the authorization URL, PKCE S256 required.".
live_authorize_url(Context, Redirect, State, Nonce, Verifier) ->
    {ok, Url} = oidcc_authorization:create_redirect_url(Context, #{
        redirect_uri => bin(Redirect),
        scopes => [openid],
        state => bin(State),
        nonce => bin(Nonce),
        pkce_verifier => bin(Verifier),
        require_pkce => true
    }),
    {beamtalk_string, iolist_to_binary(Url)}.

-doc "Live check: exchange the code (ID token validated), then userinfo.".
live_exchange(Context, Code, Redirect, Nonce, Verifier, Client) ->
    Request = #{http_adapter => adapter(Client)},
    case
        oidcc_token:retrieve(bin(Code), Context, #{
            redirect_uri => bin(Redirect),
            nonce => bin(Nonce),
            pkce_verifier => bin(Verifier),
            require_pkce => true,
            request_opts => Request
        })
    of
        {ok, #oidcc_token{id = #oidcc_token_id{claims = Claims}} = Token} ->
            Info = oidcc_userinfo:retrieve(Token, Context, #{request_opts => Request}),
            {ok, #{
                id_token_sub => maps:get(<<"sub">>, Claims),
                id_token_claims => maps:keys(Claims),
                userinfo => Info
            }};
        {error, Reason} ->
            {error, Reason}
    end.

-doc "Calls the adapter directly, returning the raw httpc-shaped response.".
adapter_get(Url, Client) ->
    beamtalk_oauth_http_adapter:request(
        get, {binary_to_list(bin(Url)), []}, [{timeout, 10000}], [], #{client => Client}
    ).

adapter(Client) -> {beamtalk_oauth_http_adapter, #{client => Client}}.

bin({beamtalk_string, B}) -> B;
bin(B) when is_binary(B) -> B.
