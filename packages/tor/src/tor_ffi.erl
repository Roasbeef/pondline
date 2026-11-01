%% The Erlang shim for the `tor` package: the sidecar port and the unix
%% sockets of outbound streams.
%%
%% Custom Erlang is a last resort, taken only where gleam_erlang and
%% gleam_otp cannot express the thing. Two things force it here: an
%% Erlang port is opened and written through BIFs with option lists that
%% have no Gleam binding, and passive-mode unix sockets need gen_tcp's
%% `{local, Path}` address. Every function catches every exception and
%% returns `{ok, X} | {error, Reason}` in the shape of a Gleam `Result`,
%% with `Reason` an atom matching a variant of the Gleam error type, so no
%% Erlang exception, and no Erlang term that was not built here, crosses
%% into Gleam.
-module(tor_ffi).

-export([open_sidecar/2, send_frame/2, close_port/1, port_os_pid/1,
         classify_message/1,
         connect_unix/2, socket_send/3, socket_recv/3, socket_set_line/2,
         socket_set_raw/1, socket_close/1]).

%% Starts the sidecar binary as a `{packet, 4}` port. The state directory
%% is the only argument, and no secret is ever passed on the command line.
%% `exit_status` makes the VM tell the owner when the process dies, and
%% `use_stdio` makes stdin and stdout the frame channel; stderr is left
%% inherited, so the sidecar's diagnostics reach the VM's stderr.
open_sidecar(Binary, StateDir) ->
    try
        Path = unicode:characters_to_list(Binary),
        Dir = unicode:characters_to_list(StateDir),
        Port = open_port({spawn_executable, Path},
                         [{packet, 4}, binary, exit_status, use_stdio,
                          {args, ["--state-dir", Dir]}]),
        {ok, Port}
    catch _:_ -> {error, nil}
    end.

%% Sends one control frame. `{packet, 4}` adds the length prefix.
send_frame(Port, Frame) ->
    try port_command(Port, Frame) of
        true -> {ok, nil}
    catch _:_ -> {error, nil}
    end.

%% Closing the port closes the sidecar's stdin, which is the signal for
%% it to exit.
close_port(Port) ->
    try port_close(Port) of
        true -> {ok, nil}
    catch _:_ -> {error, nil}
    end.

%% The operating system pid of the sidecar, for tests and diagnostics.
port_os_pid(Port) ->
    try erlang:port_info(Port, os_pid) of
        {os_pid, Pid} when is_integer(Pid) -> {ok, Pid};
        _ -> {error, nil}
    catch _:_ -> {error, nil}
    end.

%% Classifies a message in the actor's mailbox. Only the two port
%% messages we asked for (`data` and `exit_status`) are named; anything
%% else is `{error, nil}` and is ignored, so a stray message can never be
%% mistaken for a frame. The Gleam variants `PortData` and `PortExit`
%% compile to `port_data` and `port_exit`.
classify_message({Port, {data, Data}}) when is_port(Port), is_binary(Data) ->
    {ok, {port_data, Port, Data}};
classify_message({Port, {exit_status, Status}})
  when is_port(Port), is_integer(Status) ->
    {ok, {port_exit, Port, Status}};
classify_message(_) ->
    {error, nil}.

%% Connects to the sidecar's outbound socket in passive mode, so the
%% caller reads when it is ready and the kernel buffer is the backpressure.
%% The handshake reply is one line, so the socket starts in line mode
%% with a small buffer.
connect_unix(Path, Timeout) ->
    try gen_tcp:connect({local, unicode:characters_to_list(Path)}, 0,
                        [binary, {active, false}, {packet, line},
                         {buffer, 512}], Timeout) of
        {ok, Socket} -> {ok, Socket};
        {error, timeout} -> {error, timeout};
        {error, closed} -> {error, closed};
        {error, _} -> {error, socket_failed}
    catch _:_ -> {error, socket_failed}
    end.

%% Sends all of the data or reports why not. `Timeout` bounds how long a
%% full socket may block the sender, which is how a slow reader shows up.
socket_send(Socket, Data, Timeout) ->
    try
        ok = inet:setopts(Socket, [{send_timeout, Timeout},
                                   {send_timeout_close, false}]),
        case gen_tcp:send(Socket, Data) of
            ok -> {ok, nil};
            {error, timeout} -> {error, timeout};
            {error, closed} -> {error, closed};
            {error, _} -> {error, socket_failed}
        end
    catch _:_ -> {error, socket_failed}
    end.

%% Receives between one and `Max` bytes, or one line in line mode.
%% `{buffer, Max}` caps what a receive of length 0 returns, so the caller
%% never gets more than it asked for and nothing is held back.
socket_recv(Socket, Max, Timeout) ->
    try
        ok = inet:setopts(Socket, [{buffer, Max}]),
        case gen_tcp:recv(Socket, 0, Timeout) of
            {ok, Data} -> {ok, Data};
            {error, timeout} -> {error, timeout};
            {error, closed} -> {error, closed};
            {error, _} -> {error, socket_failed}
        end
    catch _:_ -> {error, socket_failed}
    end.

%% Switches the socket to line mode for the handshake reply.
socket_set_line(Socket, Max) ->
    try inet:setopts(Socket, [{packet, line}, {buffer, Max}]) of
        ok -> {ok, nil};
        _ -> {error, socket_failed}
    catch _:_ -> {error, socket_failed}
    end.

%% Switches the socket to raw bytes once the handshake is done.
socket_set_raw(Socket) ->
    try inet:setopts(Socket, [{packet, raw}]) of
        ok -> {ok, nil};
        _ -> {error, socket_failed}
    catch _:_ -> {error, socket_failed}
    end.

socket_close(Socket) ->
    try gen_tcp:close(Socket) of
        ok -> {ok, nil}
    catch _:_ -> {error, nil}
    end.
