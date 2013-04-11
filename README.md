Termit
==============

Library for serializing Erlang terms to signed encrypted binaries and reliably deserializing them back.

Usage
--------------

A typical use case is to provide means to keep secrets put in public domain, e.g. secure cookies.

```erlang
% generate a token
Term = {this, is, an, [erlang, <<"term">>]}.
Cookie = termit:encode_base64(Term, <<"cekpet">>).

% token is ok
{ok, Term} = termit:decode_base64(Cookie, <<"cekpet">>).

% check whether token is not forged
{error, forged} = termit:decode_base64(<<Cookie/binary, "1">>, <<"cekpet">>).
{error, forged} = termit:decode_base64(Cookie, <<"secret">>).
{error, forged} = termit:decode_base64(undefined, <<"cekpet">>).

% generate expiring token
Term = {this, is, another, [erlang, <<"term">>]}.
% time-to-live is 10 seconds =:= secret valid no more than 10 seconds
Cookie = termit:encode_base64(termit:expiring(Term, 10), <<"cekpet">>).

% secret is ok within 10 seconds interval
{ok, Decoded} = termit:decode_base64(Cookie, <<"cekpet">>).
{ok, Term} = termit:check_expired(Decoded).

% after 10 seconds elapsed
{ok, Decoded} = termit:decode_base64(Cookie, <<"cekpet">>).
{error, expired} = termit:check_expired(Decoded).

% shortcuts for expiring security tokens, e.g. OAuth2 bearer tokens
Token = termit:issue_token([{user, <<"dvv">>}, {scope, <<"admin.*">>}], <<"ThanksBob!">>, 24 * 60 * 60).
{ok, Data} = termit:verify_token(Token, <<"ThanksBob!">>).
{error, forged} = termit:verify_token(Token, <<"ThanksBob?">>).
```

Thanks
--------------

[Bob Ippolito](https://github.com/etrepum) for invaluable assistance in improving the library usability.

[License](termit/blob/master/LICENSE.txt)
-------

Copyright (c) 2013 Vladimir Dronnikov <dronnikov@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
