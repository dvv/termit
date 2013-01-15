-module(termit_SUITE).
-author('Vladimir Dronnikov <dronnikov@gmail.com>').

%% interface
-export([all/0]).

%% tests
-export([encode_test/1]).

-include_lib("common_test/include/ct.hrl").

all() ->
  [encode_test].

encode_test(_Config) ->
  Term = {a, b, c, [d, "e", <<"foo">>]},
  Secret = <<"TopSecRet">>,
  {error, forged} = termit:decode_base64(undefined, a, b),
  {ok, Term} = termit:decode_base64(
      termit:encode_base64(Term, Secret), Secret, 1),
  {error, expired} = termit:decode_base64(
      termit:encode_base64(Term, Secret), Secret, 0).
