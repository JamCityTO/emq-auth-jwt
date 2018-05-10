%%--------------------------------------------------------------------
%% Copyright (c) 2013-2018 EMQ Enterprise, Inc. (http://emqtt.io)
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%--------------------------------------------------------------------

-module(emq_auth_jwt).

-include_lib("emqttd/include/emqttd.hrl").

-behaviour(emqttd_auth_mod).

%% emqttd_auth callbacks
-export([init/1, check/3, description/0]).

%%--------------------------------------------------------------------
%% emqttd_auth_mod Callbacks
%%--------------------------------------------------------------------

init(Env) ->
    {ok, Env}.

check(_Client, undefined, _Env) ->
    {error, token_undefined};
check(#mqtt_client{peername = {IP, _}}, Token, Env) ->

    %% Match the client's IP with a few CIDR IP ranges to determine if it's a public client
    IsClientPublic = esockd_cidr:match(IP, {{10,0,0,0}, {10,0,0,255}, 24})
      or esockd_cidr:match(IP, {{10,0,1,0}, {10,0,1,255}, 24})
      or esockd_cidr:match(IP, {{10,0,2,0}, {10,0,2,255}, 24}),

    %% Only apply auth checks if the client is public, let internal traffic passthrough
    case IsClientPublic of
      false -> ok;
      true -> case catch jwerl:header(Token) of
        {'EXIT', _} -> {error,  token_undefined};
        Headers -> verify_token(Headers, Token, Env)
      end
    end.

verify_token(#{alg := <<"HS", _/binary>>}, _Token, #{secret := undefined}) ->
    {error, hmac_secret_undefined};
verify_token(#{alg := <<"HS", _/binary>>}, Token, #{secret := Secret}) ->
    verify_token(Token, Secret);
verify_token(#{alg := <<"RS", _/binary>>}, _Token, #{pubkey := undefined}) ->
    {error, rsa_pubkey_undefined};
verify_token(#{alg := <<"RS", _/binary>>}, Token, #{pubkey := PubKey}) ->
    verify_token(Token, PubKey);
verify_token(#{alg := <<"ES", _/binary>>}, _Token, #{pubkey := undefined}) ->
    {error, ecdsa_pubkey_undefined};
verify_token(#{alg := <<"ES", _/binary>>}, Token, #{pubkey := PubKey}) ->
    verify_token(Token, PubKey);
verify_token(Header, _Token, _Env) ->
    lager:error("Unsupported token: ~p", [Header]),
    {error, token_unsupported}.

verify_token(Token, SecretOrKey) ->
    case catch jwerl:verify(Token, SecretOrKey, true) of
        {ok, _Claims}  -> ok;
        {error, Reason} ->
            lager:error("JWT decode error:~p", [Reason]),
            {error, token_error};
        {'EXIT', Error} ->
            lager:error("JWT decode error:~p", [Error]),
            {error, token_error}
    end.

description() ->
    "Authentication with JWT".
