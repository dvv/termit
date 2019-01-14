%%
%% @doc Serialize an Erlang term to signed encrypted binary and
%% deserialize it back ensuring it's not been forged.
%%
%% Some code extracted from
%%   https://github.com/mochi/mochiweb/blob/master/src/mochiweb_session.erl.
%%

-module(termit).
-author('Vladimir Dronnikov <dronnikov@gmail.com>').

-export([
    check_expired/1,
    decode/2,
    decode_base64/2,
    encode/2,
    encode_base64/2,
    expires_by/2,
    expiring/2,
    issue_token/2,
    issue_token/3,
    verify_token/2
  ]).

%%
%% -----------------------------------------------------------------------------
%% @doc Serialize Term, encrypt and sign the result with Secret.
%% Return binary().
%% -----------------------------------------------------------------------------
%%

-spec encode(
    Term :: any(),
    Secret :: binary()) ->
  Cipher :: binary().

encode(Term, Secret) ->
  Key = key(Secret),
  Enc = encrypt(term_to_binary(Term, [compressed, {minor_version, 1}]),
                Key, rand_bytes(16)),
  << (sign(Enc, Key))/binary, Enc/binary >>.


%%
%% -----------------------------------------------------------------------------
%% @doc Given a result of encode/2, i.e. a signed encrypted binary,
%% check the signature, uncrypt and deserialize into original term.
%% -----------------------------------------------------------------------------
%%

-spec decode(
    Cipher :: binary(),
    Secret :: binary()) ->
  {ok, Term :: any()} |
  {error, forged} |
  {error, badarg}.

decode(<< Sig:20/binary, Enc/binary >>, Secret) ->
  Key = key(Secret),
  % NB constant time signature verification
  case equal(Sig, sign(Enc, Key)) of
    true ->
      % deserialize
      try binary_to_term(uncrypt(Enc, Key), [safe]) of
        Term -> {ok, Term}
      catch _:_ ->
        {error, badarg}
      end;
    false ->
      {error, forged}
  end;

%% N.B. unmatched binaries are forged
decode(Bin, _) when is_binary(Bin) ->
  {error, forged}.



-ifdef(crypto_compatibility).
-spec key(
    Secret :: binary()) ->
  MAC16 :: binary().

key(Secret) ->
  crypto:md5_mac(Secret, []).

-spec sign(
    Data :: binary(),
    Secret :: binary()) ->
  MAC20 :: binary().

sign(Data, Key) ->
  crypto:sha_mac(Key, Data).

-spec encrypt(
    Data :: binary(),
    Key :: binary(),
    IV :: binary()) ->
  Cipher :: binary().

encrypt(Data, Key, IV) ->
  Crypt = crypto:aes_cfb_128_encrypt(Key, IV, Data),
  << IV/binary, Crypt/binary>>.

-spec uncrypt(
    Cipher :: binary(),
    Key :: binary()) ->
  Uncrypted :: binary().

uncrypt(<< IV:16/binary, Data/binary >>, Key) ->
  crypto:aes_cfb_128_decrypt(Key, IV, Data).
-else
-spec key(
    Secret :: binary()) ->
  MAC16 :: binary().

key(Secret) ->
  crypto:hmac(md5, Secret, []).

-spec sign(
    Data :: binary(),
    Secret :: binary()) ->
  MAC20 :: binary().

sign(Data, Key) ->
  crypto:hmac(sha, Key, Data).
-spec encrypt(
    Data :: binary(),
    Key  :: binary(),
    IV  :: binary()) ->
  Cipher :: binary().

encrypt(Data, Key, IV) ->
  Crypt = crypto:block_encrypt(aes_cfb128, Key, IV, Data),
  << IV/binary, Crypt/binary>>.

-spec uncrypt(
    Cipher :: binary(),
    Key :: binary()) ->
  Uncrypted :: binary().

uncrypt(<< IV:16/binary, Data/binary >>, Key) ->
  crypto:block_decrypt(aes_cfb128, Key, IV, Data).

-endif.

%%
%% -----------------------------------------------------------------------------
%% 'Constant' time =:= operator for binaries, to mitigate timing attacks
%% -----------------------------------------------------------------------------
%%

-spec equal(
    A :: binary(),
    B :: binary()) ->
  true |
  false.

equal(A, B) ->
  equal(A, B, 0).

equal(<< A, As/binary >>, << B, Bs/binary >>, Acc) ->
  equal(As, Bs, Acc bor (A bxor B));
equal(<<>>, <<>>, 0) ->
  true;
equal(_As, _Bs, _Acc) ->
  false.

%%
%% -----------------------------------------------------------------------------
%% Conversion helpers
%% -----------------------------------------------------------------------------
%%

encode_base64(Term, Secret) ->
  termit_base64url:encode(encode(Term, Secret)).

decode_base64(undefined, _) ->
  {error, forged};
decode_base64(Bin, Secret) when is_binary(Bin) ->
  try termit_base64url:decode(Bin) of
    Decoded ->
      decode(Decoded, Secret)
  catch _:_ ->
    {error, forged}
  end.

%%
%% -----------------------------------------------------------------------------
%% Expiration helpers
%% -----------------------------------------------------------------------------
%%

-spec timestamp(
    Delta :: integer()) ->
  integer().

timestamp(Delta) when is_integer(Delta) ->
  {MegaSecs, Secs, _} = os:timestamp(),
  MegaSecs * 1000000 + Secs + Delta.

expiring(Term, Ttl) ->
  expires_by(Term, timestamp(Ttl)).

expires_by(Term, When) ->
  {expires, When, Term}.

check_expired(Term) ->
  check_expired(Term, timestamp(0)).

check_expired({expires, ExpiresAt, Data}, Now) ->
  case ExpiresAt > Now of
    true -> {ok, Data};
    false -> {error, expired}
  end;
check_expired(_, _) ->
  {error, badarg}.

%%
%% -----------------------------------------------------------------------------
%% Token helpers
%% -----------------------------------------------------------------------------
%%

-spec issue_token(
    Term :: any(),
    Secret :: binary(),
    Ttl :: non_neg_integer()) ->
  Token :: binary().

issue_token(Term, Secret, Ttl) ->
  encode_base64(expiring(Term, Ttl), Secret).

-spec issue_token(
    Term :: any(),
    Secret :: binary()) ->
 Token :: binary().

issue_token(Term, Secret) ->
  encode_base64(Term, Secret).


-spec verify_token(
    Token :: binary(),
    Secret :: binary()) ->
  {ok, Term :: any()} |
  {error, forged} |  % token forged
  {error, badarg} |  % token not created with issue_token/3
  {error, expired}.  % token no longer valid

verify_token(Token, Secret) ->
  case decode_base64(Token, Secret) of
    {ok, {expires, _ExpiresAt, _Data}=Decoded} -> check_expired(Decoded);
    {ok, Decoded} -> {ok, Decoded};
    Error -> Error
  end.


%% @doc Return N random bytes. This falls back to the pseudo random version of rand_uniform
%% if strong_rand_bytes fails.
-spec rand_bytes( Length :: pos_integer() ) -> binary().
rand_bytes(N) when N > 0 ->
    try
        crypto:strong_rand_bytes(N)
    catch
        error:low_entropy ->
            list_to_binary([ crypto:rand_uniform(0,256) || _X <- lists:seq(1, N) ])
    end.

%%
%% -----------------------------------------------------------------------------
%% Some unit tests
%% -----------------------------------------------------------------------------
%%

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

encrypt_test() ->
  IV = crypto:rand_bytes(16),
  Secret = crypto:hmac(md5, <<"Make It Elegant">>, []),
  << Secret15:15/binary, _/binary >> = Secret,
  Bin = <<"Transire Benefaciendo">>,
  ?assertEqual(Bin, uncrypt(encrypt(Bin, Secret, IV), Secret)),
  ?assertNotEqual(Bin,
      uncrypt(encrypt(Bin, Secret, IV), <<Secret15/binary, "1">>)),
  ?assertNotEqual(Bin,
      uncrypt(encrypt(Bin, Secret, IV), <<"0", Secret15/binary>>)),
  ?assertNotEqual(Bin,
      uncrypt(encrypt(Bin, <<Secret15/binary, "1">>, IV), Secret)),
  ?assertNotEqual(Bin,
      uncrypt(encrypt(Bin, <<"0", Secret15/binary>>, IV), Secret)).

smoke_test() ->
  Term = {a, b, c, [d, "e", <<"foo">>]},
  Secret = <<"TopSecRet">>,
  Enc = encode(Term, Secret),
  ?assertEqual({ok, Term}, decode(Enc, Secret)),
  % forged data
  ?assertEqual({error, forged}, decode(<<"1">>, Secret)),
  ?assertEqual({error, forged}, decode(<<"0", Enc/binary>>, Secret)),
  ?assertEqual({error, forged}, decode(<<Enc/binary, "1">>, Secret)).

expiry_test() ->
  Term = {a, b, c, [d, "e", <<"foo">>]},
  Secret = <<"TopSecRet">>,
  % check_expired returns error when term is not expiring
  ?assertEqual({error, badarg}, check_expired(Term)),
  % encode an expiring term
  Enc = encode(expiring(Term, 10), Secret),
  % decode it back
  {ok, Dec} = decode(Enc, Secret),
  % ensure term is not expired
  ?assertEqual({ok, Term}, check_expired(Dec)),
  % wait until it expires
  ?assertEqual({error, expired}, check_expired(Dec, timestamp(11))).

encode64_test() ->
  Term = {a, b, c, [d, "e", <<"foo">>]},
  Secret = <<"TopSecRet">>,
  ?assertEqual({error, forged}, decode_base64(undefined, a)),
  ?assertEqual({ok, Term}, decode_base64(encode_base64(Term, Secret), Secret)).

decode64_test() ->
  ?assertEqual({error, forged}, decode_base64(<<"%3A">>, a)).

token_test() ->
  Term = {a, b, c, [d, "e", <<"foo">>]},
  Secret = <<"TopSecRet">>,
  ?assertEqual({ok, Term},
      verify_token(issue_token(Term, Secret, 10), Secret)),
  ?assertEqual({error, forged},
      verify_token(issue_token(Term, Secret, 10), << Secret/binary, "1" >>)),
  ?assertEqual({ok, Term},
      verify_token(encode_base64(Term, Secret), Secret)),
  ?assertEqual({ok, Term},
      verify_token(issue_token(Term, Secret), Secret)).

-endif.
