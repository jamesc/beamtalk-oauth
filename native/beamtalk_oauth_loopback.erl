%% Copyright 2026 oauth authors
%% SPDX-License-Identifier: Apache-2.0

-module(beamtalk_oauth_loopback).

-moduledoc """
Caller-side wait for `LoopbackReceiver awaitCallback:`.

Beamtalk has no `receive` expression, and an actor call times out at
5 s, while a user can take minutes to approve a login. So the waiting
process registers itself with the receiver's gate actor and then blocks
here, in its own mailbox, for the gate's message.
""".

-export([await/2]).

-doc """
Wait up to `Timeout` ms for `{beamtalk_oauth_callback, Ref, Query}` and
answer `{ok, Query}`, or `{error, timeout}`. A timeout of 0 only takes a
message that is already in the mailbox, which is how a late message is
flushed after the gate stops.
""".
await(Ref, Timeout) when is_reference(Ref), is_integer(Timeout), Timeout >= 0 ->
    receive
        {beamtalk_oauth_callback, Ref, Query} -> {ok, Query}
    after Timeout -> {error, timeout}
    end.
