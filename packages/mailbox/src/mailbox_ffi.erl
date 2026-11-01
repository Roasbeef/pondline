-module(mailbox_ffi).
-export([unix_seconds/0, monotonic_ms/0, create_private_file/2, getenv/1]).

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
            Result;
        {error, Reason} ->
            reason(Reason)
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

%% The value of an environment variable. The name and value are binaries
%% on the Gleam side; an unset variable is an error.
getenv(Name) ->
    case os:getenv(binary_to_list(Name)) of
        false -> {error, nil};
        Value -> {ok, unicode:characters_to_binary(Value)}
    end.

reason(Reason) when is_atom(Reason) ->
    {error, atom_to_binary(Reason, utf8)};
reason(_) ->
    {error, <<"unknown">>}.
