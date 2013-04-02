%%
%% @doc Serialize an Erlang term to signed encrypted binary and
%% deserialize it back ensuring it's not been forged or expired.
%%

-module(termit).
-author('Vladimir Dronnikov <dronnikov@gmail.com>').

-export([
    encode/3, decode/3,
    encode_base64/3, decode_base64/3
  ]).

%%
%% -----------------------------------------------------------------------------
%% @doc Serialize Term, encrypt and sign the result with Secret.
%% Return binary().
%% -----------------------------------------------------------------------------
%%

-spec encode(
    Term :: any(),
    Secret :: binary(),
    Ttl :: non_neg_integer()) ->
  Cipher :: binary().

encode(Term, Secret, Ttl) ->
  ExpiresAt = timestamp(Ttl),
  ExpiresAtBin = list_to_binary(integer_to_list(ExpiresAt)),
  Key = key(Secret, Ttl),
  Enc = encrypt(term_to_binary(Term), Key),
  Sig = sign(<< ExpiresAtBin/binary, Key/binary, Enc/binary >>, Secret),
  << Sig/binary, ExpiresAt:32/integer, Enc/binary >>.

%%
%% -----------------------------------------------------------------------------
%% @doc Given a result of encode/3, i.e. a signed encrypted binary,
%% check the signature, uncrypt and deserialize into original term.
%% Check it timestamp encoded into the data is not older than Ttl.
%% -----------------------------------------------------------------------------
%%

-spec decode(
    Cipher :: binary(),
    Secret :: binary(),
    Ttl :: non_neg_integer()) ->
  {ok, Term :: any()} |
  {error, expired} |
  {error, forged} |
  {error, badarg}.

decode(<< Sig:32/binary, ExpiresAt:32/integer, Enc/binary >>, Secret, Ttl) ->
  ExpiresAtBin = list_to_binary(integer_to_list(ExpiresAt)),
  Key = key(Secret, Ttl),
  % @todo constant time comparison
  case sign(<< ExpiresAtBin/binary, Key/binary, Enc/binary >>, Secret) of
    % signature ok?
    Sig ->
      Bin = uncrypt(Enc, Key),
      % deserialize
      try binary_to_term(Bin, [safe]) of
        Term ->
          % not yet expired?
          case ExpiresAt > timestamp(0) of
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
%% @doc Get current OS time plus Delta in seconds as unsigned integer.
%% -----------------------------------------------------------------------------
%%

-spec timestamp(
    Delta :: integer()) ->
  non_neg_integer().

timestamp(Delta) when is_integer(Delta) ->
  {MegaSecs, Secs, _} = os:timestamp(),
  MegaSecs * 1000000 + Secs + Delta.


%%
%% -----------------------------------------------------------------------------
%% @doc Get 16-octet binary from given arbitrary Secret and integer TTL.
%% -----------------------------------------------------------------------------
%%

-spec key(
    Secret :: binary(),
    Ttl :: non_neg_integer()) ->
  MAC16 :: binary().

key(Secret, Ttl) ->
  crypto:md5_mac(Secret, integer_to_list(Ttl)).

%%
%% -----------------------------------------------------------------------------
%% @doc Get 32-octet hash of Data salted with Secret.
%% -----------------------------------------------------------------------------
%%

-spec sign(
    Data :: binary(),
    Secret :: binary()) ->
  Signature32 :: binary().

sign(Data, Secret) ->
  crypto:sha256([Data, Secret]).

%%
%% -----------------------------------------------------------------------------
%% @doc Encrypt Bin using Secret.
%% -----------------------------------------------------------------------------
%%

-spec encrypt(
    Data :: binary(),
    Key :: binary()) ->
  Cipher :: binary().

encrypt(Data, Key) ->
  IV = crypto:rand_bytes(16),
  << IV/binary, (crypto:aes_cfb_128_encrypt(Key, IV, Data))/binary >>.

%%
%% -----------------------------------------------------------------------------
%% @doc Uncrypt Bin using Secret.
%% -----------------------------------------------------------------------------
%%

-spec uncrypt(
    Cipher :: binary(),
    Key :: binary()) ->
  Uncrypted :: binary().

uncrypt(<< IV:16/binary, Data/binary >>, Key) ->
  crypto:aes_cfb_128_decrypt(Key, IV, Data).

%%
%% -----------------------------------------------------------------------------
%% Conversion helpers
%% -----------------------------------------------------------------------------
%%

encode_base64(Term, Secret, Ttl) ->
  base64:encode(encode(Term, Secret, Ttl)).

decode_base64(undefined, _, _) ->
  {error, forged};

decode_base64(Bin, Secret, Ttl) when is_binary(Bin) ->
  try base64:decode(Bin) of
    Decoded ->
      decode(Decoded, Secret, Ttl)
  catch _:_ ->
    {error, forged}
  end.

%%
%% -----------------------------------------------------------------------------
%% Some unit tests
%% -----------------------------------------------------------------------------
%%

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

encrypt_test() ->
  Secret = crypto:md5_mac(<<"Make It Elegant">>, []),
  << Secret15:15/binary, _/binary >> = Secret,
  Bin = <<"Transire Benefaciendo">>,
  ?assertEqual(Bin, uncrypt(encrypt(Bin, Secret), Secret)),
  ?assertNotEqual(Bin, uncrypt(encrypt(Bin, Secret), <<Secret15/binary, "1">>)),
  ?assertNotEqual(Bin, uncrypt(encrypt(Bin, Secret), <<"0", Secret15/binary>>)),
  ?assertNotEqual(Bin, uncrypt(encrypt(Bin, <<Secret15/binary, "1">>), Secret)),
  ?assertNotEqual(Bin, uncrypt(encrypt(Bin, <<"0", Secret15/binary>>), Secret)).

smoke_test() ->
  Term = {a, b, c, [d, "e", <<"foo">>]},
  Secret = <<"TopSecRet">>,
  Enc = encode(Term, Secret, 1),
  % decode encoded term with valid time to live
  ?assertEqual({ok, Term}, decode(Enc, Secret, 1)),
  % forged data
  ?assertEqual({error, forged}, decode(Enc, Secret, 2)),
  ?assertEqual({error, forged}, decode(<<"1">>, Secret, 1)),
  ?assertEqual({error, forged}, decode(<<"0", Enc/binary>>, Secret, 1)),
  ?assertEqual({error, forged}, decode(<<Enc/binary, "1">>, Secret, 1)),
  % expired data
  Enc2 = encode(Term, Secret, 1),
  timer:sleep(2000),
  ?assertEqual({error, expired}, decode(Enc2, Secret, 1)).

encode64_test() ->
  Term = {a, b, c, [d, "e", <<"foo">>]},
  Secret = <<"TopSecRet">>,
  ?assertEqual({error, forged}, decode_base64(undefined, a, b)),
  ?assertEqual({ok, Term}, decode_base64(encode_base64(Term, Secret, 1), Secret, 1)).

decode64_test() ->
  ?assertEqual({error, forged}, decode_base64(<<"%3A">>, a, b)).

-endif.
