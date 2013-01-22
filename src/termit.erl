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
  Time = list_to_binary(integer_to_list(timestamp())),
  TimeSize = byte_size(Time),
  Sig = sign(<<Time/binary, Enc/binary>>, Secret),
  <<Sig/binary, TimeSize, Time/binary, Enc/binary>>.

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

decode(<<Sig:32/binary, TimeSize, Time:TimeSize/binary, Enc/binary>>, Secret, Ttl) ->
  case sign(<<Time/binary, Enc/binary>>, Secret) of
      % signature ok?
      Sig ->
        Bin = uncrypt(Enc, Secret),
        % deserialize
        try binary_to_term(Bin, [safe]) of
            Term ->
              % not yet expired?
              Now = timestamp(),
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
%% @doc Get current OS time as unsigned integer.
%% -----------------------------------------------------------------------------
%%

-spec timestamp() -> non_neg_integer().

timestamp() ->
  {MegaSecs, Secs, _} = os:timestamp(),
  MegaSecs * 1000000 + Secs.

%%
%% -----------------------------------------------------------------------------
%% @doc Get 32-octet hash of Data salted with Secret.
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
  ?assertNotEqual(Bin, uncrypt(encrypt(Bin, Secret), <<Secret/binary, "1">>)),
  ?assertNotEqual(Bin, uncrypt(encrypt(Bin, Secret), <<"0", Secret/binary>>)),
  ?assertNotEqual(Bin, uncrypt(encrypt(Bin, <<Secret/binary, "1">>), Secret)),
  ?assertNotEqual(Bin, uncrypt(encrypt(Bin, <<"0", Secret/binary>>), Secret)).

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
  ?assertEqual({error, forged}, decode(<<"0", Enc/binary>>, Secret, 1)),
  ?assertEqual({error, forged}, decode(<<Enc/binary, "1">>, Secret, 1)).

encode64_test() ->
  Term = {a, b, c, [d, "e", <<"foo">>]},
  Secret = <<"TopSecRet">>,
  ?assertEqual({error, forged}, decode_base64(undefined, a, b)),
  ?assertEqual({ok, Term}, decode_base64(encode_base64(Term, Secret), Secret, 1)),
  ?assertEqual({error, expired}, decode_base64(encode_base64(Term, Secret), Secret, 0)).

-endif.
