-module(mailbox_ffi).
-export([unix_seconds/0, monotonic_ms/0, create_private_file/2, write_private_file/2, write_stdout/1, getenv/1, find_executable/1]).

%% Whole seconds since the Unix epoch. `erlang:system_time/1` takes the unit
%% as an atom, which Gleam cannot build without creating one.
unix_seconds() -> erlang:system_time(second).

%% A monotonic reading in milliseconds, for measuring durations only.
monotonic_ms() -> erlang:monotonic_time(millisecond).

%% Creates `Path` exclusively, restricts it to its owner, and only then
%% writes `Bytes`, so the secret is never in a file other users can read.
%% An existing file is refused. The error is the POSIX reason's name.
create_private_file(Path, Bytes) ->
    case file:open(Path, [write, exclusive, binary, raw]) of
        {ok, Fd} ->
            Result = write_private(Fd, Path, Bytes),
            _ = file:close(Fd),
            case Result of
                {ok, nil} -> {ok, nil};
                {error, _} ->
                    _ = file:delete(binary_to_list(Path)),
                    Result
            end;
        {error, Reason} ->
            reason(Reason)
    end.

%% Atomically writes `Bytes` to `Path` with mode 0600 by staging into an
%% exclusive 0600 sibling file and renaming into place.
write_private_file(Path, Bytes) ->
    Pid = list_to_binary(os:getpid()),
    Suffix = integer_to_binary(erlang:unique_integer([positive])),
    Tmp = <<Path/binary, ".tmp.", Pid/binary, ".", Suffix/binary>>,
    case create_private_file(Tmp, Bytes) of
        {ok, nil} ->
            case file:rename(binary_to_list(Tmp), binary_to_list(Path)) of
                ok -> {ok, nil};
                {error, Reason} ->
                    _ = file:delete(binary_to_list(Tmp)),
                    reason(Reason)
            end;
        Error ->
            Error
    end.

write_private(Fd, Path, Bytes) ->
    case file:change_mode(Path, 8#600) of
        ok ->
            case file:write(Fd, Bytes) of
                ok -> {ok, nil};
                {error, Reason} -> reason(Reason)
            end;
        {error, Reason} ->
            reason(Reason)
    end.

%% Writes raw bytes synchronously to `standard_io` under `latin1` encoding so OS
%% write failures (`ebadf`/`epipe`) return synchronously and seatbelt needs no `/dev/stdout` open.
write_stdout(<<>>) ->
    {ok, nil};
write_stdout(Bytes) ->
    case io:getopts(standard_io) of
        Opts when is_list(Opts) ->
            Old = proplists:get_value(encoding, Opts, unicode),
            case io:setopts(standard_io, [binary, {encoding, latin1}]) of
                ok ->
                    Result = file:write(standard_io, Bytes),
                    _ = io:setopts(standard_io, [{encoding, Old}]),
                    write_result(Result);
                {error, Reason} ->
                    reason(Reason)
            end;
        {error, enotsup} ->
            write_result(file:write(standard_io, Bytes));
        {error, Reason} ->
            reason(Reason)
    end.

write_result(ok) -> {ok, nil};
write_result({error, Reason}) -> reason(Reason).

%% The value of an environment variable. The name and value are binaries
%% on the Gleam side; an unset variable is an error.
getenv(Name) ->
    case os:getenv(binary_to_list(Name)) of
        false -> {error, nil};
        Value -> {ok, unicode:characters_to_binary(Value)}
    end.

%% Finds an executable on PATH, returning its resolved path.
find_executable(Name) ->
    case os:find_executable(binary_to_list(Name)) of
        false -> {error, nil};
        Path -> {ok, unicode:characters_to_binary(Path)}
    end.

reason(Reason) when is_atom(Reason) ->
    {error, atom_to_binary(Reason, utf8)};
reason(_) ->
    {error, <<"unknown">>}.
