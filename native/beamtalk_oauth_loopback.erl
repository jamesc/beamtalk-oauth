%% Copyright 2026 James Casey
%% SPDX-License-Identifier: Apache-2.0

-module(beamtalk_oauth_loopback).

-moduledoc """
Caller-side wait for `LoopbackReceiver awaitCallback:`.

Beamtalk has no `receive` expression, and an actor call times out at
5 s, while a user can take minutes to approve a login. So the waiting
process registers itself with the receiver's gate actor and then blocks
here, in its own mailbox, for the gate's message.
""".

-export([await/3, mailbox_size/0]).

-doc """
Wait up to `Timeout` ms for `{beamtalk_oauth_callback, Ref, Query}` from
the gate `Gate` and answer `{callback, Query}`. Answers `timeout` when
nothing arrives in time, and `stopped` as soon as the gate exits
(the receiver was stopped elsewhere, or crashed). A timeout of 0 only takes
a message already in the mailbox, which is how a late message is flushed
after the gate stops.

Plain terms, not `{ok, _}`/`{error, _}`: the FFI boundary turns an error
reason into an exception, and the caller needs the reason itself.
""".
-spec await(reference(), pid(), non_neg_integer()) ->
    {callback, map()} | timeout | stopped.
await(Ref, Gate, Timeout) when
    is_reference(Ref), is_pid(Gate), is_integer(Timeout), Timeout >= 0
->
    MRef = erlang:monitor(process, Gate),
    Answer =
        receive
            {beamtalk_oauth_callback, Ref, Query} -> {callback, Query};
            {'DOWN', MRef, process, Gate, _} -> down
        after Timeout -> timeout
        end,
    erlang:demonitor(MRef, [flush]),
    case Answer of
        %% The gate sends before it can exit, so a delivered query is
        %% already in the mailbox when its DOWN arrives.
        down ->
            receive
                {beamtalk_oauth_callback, Ref, Late} -> {callback, Late}
            after 0 -> stopped
            end;
        _ ->
            Answer
    end.

-doc "Messages in the calling process's mailbox; for tests.".
-spec mailbox_size() -> non_neg_integer().
mailbox_size() ->
    {message_queue_len, N} = erlang:process_info(self(), message_queue_len),
    N.
