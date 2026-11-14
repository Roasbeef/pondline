-module(daemon_local_ffi).
-export([
    listen/1, accept/1, connect/2, recv_line/4, send/2, close/1,
    monotonic_ms/0, create_private_file/2, write_private_file/2,
    make_private_dir/1, file_mode/1, write_stdout/1, read_stdin/1,
    getenv/1, find_executable/1, host_os/0, absolute_path/1,
    current_uid/0, run_program/3, halt/1
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

%% Writes raw bytes synchronously to `standard_io` under `latin1` encoding (1:1
%% octets, restoring the previous encoding afterwards). Unlike opening `/dev/stdout`
%% by path, this works inside macOS seatbelt sandboxes, and unlike an async fd port,
%% `file:write(standard_io, ...)` waits for the OS write and reports `ebadf`/`epipe`.
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

host_os() ->
    case os:type() of
        {unix, Name} -> {ok, atom_to_binary(Name, utf8)};
        _ -> {error, nil}
    end.

absolute_path(Path) ->
    unicode:characters_to_binary(filename:absname(unicode:characters_to_list(Path))).

current_uid() ->
    IdBin = case os:find_executable("id") of
        false -> <<"/usr/bin/id">>;
        Found -> unicode:characters_to_binary(Found)
    end,
    case run_program(IdBin, [<<"-u">>], 5000) of
        {ok, {0, Out}} ->
            Trimmed = string:trim(Out),
            try binary_to_integer(Trimmed) of
                Uid when Uid >= 0 -> {ok, Uid};
                _ -> {error, <<"bad_uid">>}
            catch
                _:_ -> {error, <<"bad_uid">>}
            end;
        {ok, {_Code, _Out}} -> {error, <<"id_failed">>};
        {error, Reason} -> {error, Reason}
    end.

run_program(Executable, Args, TimeoutMs) ->
    ExeList = unicode:characters_to_list(Executable),
    ArgLists = [unicode:characters_to_list(A) || A <- Args],
    try open_port({spawn_executable, ExeList}, [exit_status, binary, stderr_to_stdout, {args, ArgLists}]) of
        Port -> collect_port(Port, TimeoutMs, [])
    catch
        error:Reason -> reason(Reason)
    end.

collect_port(Port, TimeoutMs, Acc) ->
    receive
        {Port, {data, Chunk}} ->
            collect_port(Port, TimeoutMs, [Chunk | Acc]);
        {Port, {exit_status, Status}} ->
            Raw = iolist_to_binary(lists:reverse(Acc)),
            Text = case unicode:characters_to_binary(Raw) of
                Bin when is_binary(Bin) -> Bin;
                _ -> <<>>
            end,
            {ok, {Status, Text}}
    after TimeoutMs ->
        try port_close(Port) catch _:_ -> ok end,
        {error, <<"timeout">>}
    end.

halt(Code) -> erlang:halt(Code).

reason(Reason) when is_atom(Reason) ->
    {error, atom_to_binary(Reason, utf8)};
reason(_) ->
    {error, <<"unknown">>}.
