%%
%% @doc Serialize an Erlang term to signed encrypted binary and
%% deserialize it back ensuring it's not been forged.
%%

-module(termit).
-author('Vladimir Dronnikov <dronnikov@gmail.com>').

-export([
    encode/2, decode/3,
    encode_base64/2, decode_base64/3
  ]).

%%
%% -----------------------------------------------------------------------------
%% @doc Serialize Term, encrypt and sign the result with Secret.
%% Return binary().
%% -----------------------------------------------------------------------------
%%

-spec encode(Term :: any(), Secret :: binary()) -> Cipher :: binary().

encode(Term, Secret) ->
  Bin = term_to_binary(Term),
  Enc = encrypt(Bin, Secret),
  {MegaSecs, Secs, _} = erlang:now(),
  Time = list_to_binary(integer_to_list(MegaSecs * 1000000 + Secs)),
  Sig = sign(<<Time/binary, Enc/binary>>, Secret),
  <<Sig/binary, Time/binary, Enc/binary>>.

%%
%% -----------------------------------------------------------------------------
%% @doc Given a result of encode/2, i.e. a signed encrypted binary,
%% check the signature, uncrypt and deserialize into original term.
%% Check it timestamp encoded into the data is not older than Ttl.
%% Return {ok, Term} or {error, Reason}.
%% -----------------------------------------------------------------------------
%%

-spec decode(
    Cipher :: binary(),
    Secret :: binary(),
    Ttl :: non_neg_integer()
  ) -> {ok, Term :: any()} | {error, Reason :: atom()}.

%% @todo how do we know time is 10 octets?

decode(<<Sig:32/binary, Time:10/binary, Enc/binary>>, Secret, Ttl) ->
  case sign(<<Time/binary, Enc/binary>>, Secret) of
      % signature ok?
      Sig ->
        Bin = uncrypt(Enc, Secret),
        % deserialize
        try binary_to_term(Bin, [safe]) of
            Term ->
              % not yet expired?
              {MegaSecs, Secs, _} = erlang:now(),
              Now = MegaSecs * 1000000 + Secs,
              Expires = list_to_integer(binary_to_list(Time)) + Ttl,
              case Expires > Now of
                  true ->
                    {ok, Term};
                  false ->
                    {error, expired}
                end
          catch _:_ ->
              {error, badarg}
          end;
      _ ->
        {error, forged}
    end;

%% N.B. unmatched binaries are forged
decode(Bin, _, _) when is_binary(Bin) ->
  {error, forged}.

%%
%% -----------------------------------------------------------------------------
%% @doc Get 32-byte SHA1 sum of Data salted with Secret.
%% -----------------------------------------------------------------------------
%%

-spec sign(binary(), binary()) -> binary().

sign(Data, Secret) ->
  crypto:sha256([Data, Secret]).

%%
%% -----------------------------------------------------------------------------
%% @doc Encrypt Bin using Secret.
%% -----------------------------------------------------------------------------
%%

-spec encrypt(binary(), binary()) -> binary().

encrypt(Bin, Secret) ->
  <<Key:16/binary, IV:16/binary>> = crypto:sha256(Secret),
  crypto:aes_cfb_128_encrypt(Key, IV, Bin).

%%
%% -----------------------------------------------------------------------------
%% @doc Uncrypt Bin using Secret.
%% -----------------------------------------------------------------------------
%%

-spec uncrypt(binary(), binary()) -> binary().

uncrypt(Bin, Secret) ->
  <<Key:16/binary, IV:16/binary>> = crypto:sha256(Secret),
  crypto:aes_cfb_128_decrypt(Key, IV, Bin).

%%
%% -----------------------------------------------------------------------------
%% Conversion helpers
%% -----------------------------------------------------------------------------
%%

encode_base64(Term, Secret) ->
  base64:encode(encode(Term, Secret)).

decode_base64(undefined, _, _) ->
  {error, forged};

decode_base64(Bin, Secret, Ttl) when is_binary(Bin) ->
  decode(base64:decode(Bin), Secret, Ttl).

%%
%% -----------------------------------------------------------------------------
%% Some unit tests
%% -----------------------------------------------------------------------------
%%

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

encrypt_test() ->
  Secret = <<"Make It Elegant">>,
  Bin = <<"Transire Benefaciendo">>,
  ?assertEqual(Bin, uncrypt(encrypt(Bin, Secret), Secret)),
  ?assert(Bin =/= uncrypt(encrypt(Bin, Secret), <<Secret/binary, "1">>)),
  ?assert(Bin =/= uncrypt(encrypt(Bin, <<Secret/binary, "1">>), Secret)).

smoke_test() ->
  Term = {a, b, c, [d, "e", <<"foo">>]},
  Secret = <<"TopSecRet">>,
  Enc = encode(Term, Secret),
  % decode encoded term with valid time to live
  ?assertEqual({ok, Term}, decode(Enc, Secret, 1)),
  % expired data
  ?assertEqual({error, expired}, decode(encode(Term, Secret), Secret, 0)),
  % forged data
  ?assertEqual({error, forged}, decode(<<"1">>, Secret, 1)),
  ?assertEqual({error, forged}, decode(<<Enc/binary, "1">>, Secret, 1)).

encode_test(_Config) ->
  Term = {a, b, c, [d, "e", <<"foo">>]},
  Secret = <<"TopSecRet">>,
  undefined = decode_base64(undefined, a, b),
  {ok, Term} = decode_base64(encode_base64(Term, Secret), Secret, 1),
  {error, expired} = decode_base64(encode_base64(Term, Secret), Secret, 0).

-endif.
