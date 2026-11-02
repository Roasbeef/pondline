-module(daemon_test_ffi).
-export([env/1, capture_start/0, capture_stop/0, capture_peek/0, set_clock_shift/2, clock_shift/1,
         seal_or_crash/5, sealing_key/0, arm_crash/2, crash_if_armed/1]).

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
        {peek, Caller} ->
            Caller ! {captured, Acc},
            collect(Acc);
        {done, Caller} ->
            Caller ! {captured, Acc}
    end.

%% What has been captured so far, without stopping the capture.
capture_peek() ->
    whereis(standard_error) ! {peek, self()},
    receive {captured, Bytes} -> Bytes after 5000 -> <<>> end.

%% The real ChaCha20-Poly1305 seal, except that a plaintext holding
%% `Marker` reaches OpenSSL with a key one byte short. The NIF then raises
%% `badarg`, and the exception's stack frame carries the call's arguments,
%% the key and the plaintext among them, which is what a crypto failure
%% mid-send looks like (`primitives_ffi` guards its own calls for the same
%% reason).
seal_or_crash(Key, Nonce, Aad, Plaintext, Marker) ->
    case binary:match(Plaintext, Marker) of
        nomatch -> primitives_ffi:aead_seal(Key, Nonce, Aad, Plaintext);
        _ ->
            Short = binary:part(Key, 0, byte_size(Key) - 1),
            persistent_term:put({?MODULE, sealing_key}, Short),
            {ok, crypto:crypto_one_time_aead(
                chacha20_poly1305, Short, Nonce, Plaintext, Aad, true)}
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

%% The key `seal_or_crash` handed OpenSSL when it crashed, so a test can
%% search the output for it too.
sealing_key() ->
    persistent_term:get({?MODULE, sealing_key}, <<>>).

%% Arms one crash for `Role`: the next `crash_if_armed(Role)` raises from a
%% BIF with `Secret` as an argument, as a crash with key material in reach
%% does, and disarms it.
arm_crash(Role, Secret) ->
    persistent_term:put({?MODULE, armed, Role}, Secret),
    nil.

crash_if_armed(Role) ->
    case persistent_term:get({?MODULE, armed, Role}, none) of
        none -> nil;
        Secret ->
            persistent_term:erase({?MODULE, armed, Role}),
            _ = binary:part(Secret, 1000000, 1),
            nil
    end.
