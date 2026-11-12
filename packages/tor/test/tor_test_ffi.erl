%% Test-only helpers: environment, scratch directories, process control,
%% and loopback servers for the spike. Nothing here ships; the package's
%% `src` has its own shim.
-module(tor_test_ffi).

-export([write_script/2, getenv/1, make_scratch_dir/0, remove_dir/1, pid_alive/1, kill_nine/1,
         monotonic_ms/0, rss_kb/1, file_size/1, start_echo/0, start_sink/0,
         drain_sink/1]).

%% Writes an executable script, a stand-in sidecar that never speaks the
%% control protocol: one that stays silent, or one that exits at once.
write_script(Path, Body) ->
    P = binary_to_list(Path),
    ok = file:write_file(P, Body),
    ok = file:change_mode(P, 8#755),
    nil.

getenv(Name) ->
    case os:getenv(binary_to_list(Name)) of
        false -> {error, nil};
        Value -> {ok, list_to_binary(Value)}
    end.

%% A short path under /tmp: a unix socket path is limited to about 100
%% bytes, and the platform temp directory can already use most of that.
make_scratch_dir() ->
    %% Prefer /tmp so AF_UNIX socket paths stay short, falling back to TMPDIR
    %% when running inside a sandbox that denies literal /tmp writes.
    Leaf = "t" ++ os:getpid() ++ "-" ++ integer_to_list(erlang:unique_integer([positive])),
    Primary = "/tmp/" ++ Leaf,
    case file:make_dir(Primary) of
        ok -> list_to_binary(Primary);
        {error, _} ->
            Base = case os:getenv("TMPDIR") of false -> "build"; V -> string:trim(V, trailing, "/") end,
            Fallback = Base ++ "/" ++ Leaf,
            ok = filelib:ensure_dir(Fallback),
            ok = file:make_dir(Fallback),
            list_to_binary(Fallback)
    end.

remove_dir(Dir) ->
    _ = file:del_dir_r(binary_to_list(Dir)),
    nil.

pid_alive(Pid) ->
    Out = os:cmd("kill -0 " ++ integer_to_list(Pid) ++ " 2>/dev/null; echo $?"),
    string:trim(Out) =:= "0".

kill_nine(Pid) ->
    _ = os:cmd("kill -9 " ++ integer_to_list(Pid)),
    nil.

monotonic_ms() ->
    erlang:monotonic_time(millisecond).

rss_kb(Pid) ->
    Out = os:cmd("ps -o rss= -p " ++ integer_to_list(Pid)),
    case string:to_integer(string:trim(Out)) of
        {N, _} when is_integer(N) -> N;
        _ -> -1
    end.

file_size(Path) ->
    case file:read_file_info(binary_to_list(Path)) of
        {ok, Info} -> element(2, Info);
        _ -> -1
    end.

%% A loopback server that echoes every byte back. Returns its port.
start_echo() ->
    Parent = self(),
    Ref = make_ref(),
    spawn(fun() ->
        {ok, L} = gen_tcp:listen(0, [binary, {active, false}, {reuseaddr, true},
                                     {ip, {127, 0, 0, 1}}]),
        {ok, P} = inet:port(L),
        Parent ! {Ref, P},
        echo_accept(L)
    end),
    receive {Ref, Port} -> Port after 5000 -> 0 end.

echo_accept(L) ->
    case gen_tcp:accept(L) of
        {ok, S} ->
            Pid = spawn(fun() -> receive go -> echo_loop(S) end end),
            ok = gen_tcp:controlling_process(S, Pid),
            Pid ! go,
            echo_accept(L);
        {error, _} -> ok
    end.

echo_loop(S) ->
    case gen_tcp:recv(S, 0) of
        {ok, Data} -> _ = gen_tcp:send(S, Data), echo_loop(S);
        {error, _} -> gen_tcp:close(S)
    end.

%% A loopback server that accepts and then never reads, until told to
%% drain. Returns its port and a handle to drain it with.
start_sink() ->
    Parent = self(),
    Ref = make_ref(),
    Pid = spawn(fun() ->
        {ok, L} = gen_tcp:listen(0, [binary, {active, false}, {reuseaddr, true},
                                     {ip, {127, 0, 0, 1}}, {recbuf, 4096}]),
        {ok, P} = inet:port(L),
        Parent ! {Ref, P},
        {ok, S} = gen_tcp:accept(L),
        receive drain -> sink_drain(S) end
    end),
    receive {Ref, Port} -> {Port, Pid} after 5000 -> {0, Pid} end.

drain_sink(Pid) ->
    Pid ! drain,
    nil.

sink_drain(S) ->
    case gen_tcp:recv(S, 0, 2000) of
        {ok, _} -> sink_drain(S);
        {error, _} -> gen_tcp:close(S)
    end.
