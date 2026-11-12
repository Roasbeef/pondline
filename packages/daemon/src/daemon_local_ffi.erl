-module(daemon_local_ffi).
-export([
    listen/1, accept/1, connect/2, recv_line/4, send/2, close/1,
    monotonic_ms/0, create_private_file/2, write_private_file/2,
    make_private_dir/1, file_mode/1, write_stdout/1, read_stdin/1,
    getenv/1, find_executable/1, halt/1
]).

%% Binds a Unix domain socket at `Path`. A stale socket file is removed
%% first, and the socket is restricted to its owner right after the bind.
%% The state directory is itself private, so no other user can reach the
%% path in the gap between the two calls. The error is the POSIX reason.
listen(Path) ->
    Name = binary_to_list(Path),
    _ = file:delete(Name),
    Options = [
        {ifaddr, {local, Name}}, binary, {packet, raw},
        {active, false}, {reuseaddr, true}
    ],
    case gen_tcp:listen(0, Options) of
        {ok, Listener} ->
            case file:change_mode(Name, 8#600) of
                ok ->
                    {ok, Listener};
                {error, Reason} ->
                    _ = gen_tcp:close(Listener),
                    reason(Reason)
            end;
        {error, Reason} ->
            reason(Reason)
    end.

accept(Listener) ->
    case gen_tcp:accept(Listener) of
        {ok, Socket} -> {ok, Socket};
        {error, Reason} -> reason(Reason)
    end.

connect(Path, TimeoutMs) ->
    Options = [binary, {packet, raw}, {active, false}],
    case gen_tcp:connect({local, binary_to_list(Path)}, 0, Options, TimeoutMs) of
        {ok, Socket} -> {ok, Socket};
        {error, Reason} -> reason(Reason)
    end.

%% Reads up to and excluding the next newline. `Buffer` holds bytes left
%% over from an earlier read, and the second element of the result is what
%% follows the newline. A line longer than `Max` bytes is refused as soon as
%% the buffer proves it, so a peer cannot make this process hold more than
%% `Max` plus one read.
recv_line(Socket, Buffer, Max, TimeoutMs) ->
    case binary:split(Buffer, <<"\n">>) of
        [Line, Rest] when byte_size(Line) =< Max ->
            {ok, {Line, Rest}};
        [_Line, _Rest] ->
            {error, <<"too_large">>};
        [_Partial] when byte_size(Buffer) > Max ->
            {error, <<"too_large">>};
        [_Partial] ->
            case gen_tcp:recv(Socket, 0, TimeoutMs) of
                {ok, More} ->
                    recv_line(Socket, <<Buffer/binary, More/binary>>, Max, TimeoutMs);
                {error, Reason} ->
                    reason(Reason)
            end
    end.

send(Socket, Bytes) ->
    case gen_tcp:send(Socket, Bytes) of
        ok -> {ok, nil};
        {error, Reason} -> reason(Reason)
    end.

close(Socket) ->
    _ = gen_tcp:close(Socket),
    nil.

monotonic_ms() -> erlang:monotonic_time(millisecond).

%% Creates `Path` exclusively, restricts it to its owner, and only then
%% writes `Bytes`, so the secret is never in a file other users can read.
create_private_file(Path, Bytes) ->
    case file:open(Path, [write, exclusive, binary, raw]) of
        {ok, Fd} ->
            Result = write_private(Fd, Path, Bytes),
            _ = file:close(Fd),
            Result;
        {error, Reason} ->
            reason(Reason)
    end.

%% Atomically writes `Bytes` to `Path` with mode 0600 by staging into an
%% exclusive 0600 sibling file and renaming into place.
write_private_file(Path, Bytes) ->
    Suffix = integer_to_binary(erlang:unique_integer([positive])),
    Tmp = <<Path/binary, ".tmp.", Suffix/binary>>,
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

%% Creates `Path` and its parents if missing, then restricts `Path` itself
%% to its owner.
make_private_dir(Path) ->
    case filelib:ensure_dir(filename:join(binary_to_list(Path), "x")) of
        ok ->
            case file:change_mode(binary_to_list(Path), 8#700) of
                ok -> {ok, nil};
                {error, Reason} -> reason(Reason)
            end;
        {error, Reason} ->
            reason(Reason)
    end.

%% The permission bits of `Path`, such as 8#600.
file_mode(Path) ->
    case file:read_file_info(binary_to_list(Path)) of
        {ok, Info} -> {ok, element(8, Info) band 8#777};
        {error, Reason} -> reason(Reason)
    end.

%% Writes raw bytes directly to file descriptor 1 via an OTP fd port. Unlike
%% `io`, this never UTF-8 re-encodes binary payloads, and unlike opening
%% `/dev/stdout` by path, it works inside macOS seatbelt and chroot sandboxes.
write_stdout(<<>>) ->
    {ok, nil};
write_stdout(Bytes) ->
    try
        Port = erlang:open_port({fd, 0, 1}, [out, binary, stream]),
        try
            true = erlang:port_command(Port, Bytes),
            {ok, nil}
        after
            try erlang:port_close(Port) catch _:_ -> ok end
        end
    catch
        _:Reason -> reason(Reason)
    end.

%% Reads standard input to its end, giving up with `too_large` once more
%% than `Max` bytes have arrived.
read_stdin(Max) ->
    case file:open("/dev/stdin", [read, raw, binary]) of
        {ok, Fd} ->
            Result = read_all(Fd, Max, []),
            _ = file:close(Fd),
            Result;
        {error, Reason} ->
            reason(Reason)
    end.

read_all(Fd, Max, Acc) ->
    case file:read(Fd, 65536) of
        {ok, Data} ->
            Next = [Data | Acc],
            case iolist_size(Next) > Max of
                true -> {error, <<"too_large">>};
                false -> read_all(Fd, Max, Next)
            end;
        eof ->
            {ok, iolist_to_binary(lists:reverse(Acc))};
        {error, Reason} ->
            reason(Reason)
    end.

getenv(Name) ->
    case os:getenv(binary_to_list(Name)) of
        false -> {error, nil};
        Value -> {ok, unicode:characters_to_binary(Value)}
    end.

find_executable(Name) ->
    case os:find_executable(binary_to_list(Name)) of
        false -> {error, nil};
        Path -> {ok, unicode:characters_to_binary(Path)}
    end.

halt(Code) -> erlang:halt(Code).

reason(Reason) when is_atom(Reason) ->
    {error, atom_to_binary(Reason, utf8)};
reason(_) ->
    {error, <<"unknown">>}.
