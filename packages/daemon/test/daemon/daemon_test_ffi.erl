-module(daemon_test_ffi).
-export([env/1, capture_start/0, capture_stop/0, set_clock_shift/2, clock_shift/1]).

%% An environment variable as a Gleam `Result(String, Nil)`.
env(Name) ->
    case os:getenv(binary_to_list(Name)) of
        false -> {error, nil};
        Value -> {ok, unicode:characters_to_binary(Value)}
    end.

%% Redirects everything written to standard error into a buffer, so a test
%% can read what the whole daemon logged. The original handler is remembered
%% and put back by `capture_stop`.
capture_start() ->
    Original = whereis(standard_error),
    Collector = spawn(fun() -> collect(<<>>) end),
    unregister(standard_error),
    register(standard_error, Collector),
    persistent_term:put({?MODULE, original}, Original),
    nil.

%% Restores standard error and returns what was captured.
capture_stop() ->
    Original = persistent_term:get({?MODULE, original}),
    Collector = whereis(standard_error),
    unregister(standard_error),
    register(standard_error, Original),
    Collector ! {done, self()},
    receive {captured, Bytes} -> Bytes after 5000 -> <<>> end.

collect(Acc) ->
    receive
        {io_request, From, ReplyAs, Request} ->
            Text = request_text(Request),
            From ! {io_reply, ReplyAs, ok},
            collect(<<Acc/binary, Text/binary>>);
        {done, Caller} ->
            Caller ! {captured, Acc}
    end.

request_text({put_chars, _Encoding, Chars}) -> to_binary(Chars);
request_text({put_chars, _Encoding, M, F, A}) -> to_binary(apply(M, F, A));
request_text(_) -> <<>>.

to_binary(Chars) ->
    case unicode:characters_to_binary(Chars) of
        Bin when is_binary(Bin) -> Bin;
        _ -> <<>>
    end.

%% A named shift, in seconds, for `support.shiftable_clock`. A persistent
%% term because the clock is read from every process of a daemon's tree.
set_clock_shift(Name, Seconds) ->
    persistent_term:put({?MODULE, clock_shift, Name}, Seconds),
    nil.

clock_shift(Name) ->
    persistent_term:get({?MODULE, clock_shift, Name}, 0).
