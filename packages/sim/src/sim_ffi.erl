%% The VM-level primitives the simulation's runner needs and Gleam cannot
%% express: a quiescence probe over the schedulers, shared counters a
%% process can read without a round trip, a fault table the production
%% hooks read in their own process, the supervisor's child list, and a sink
%% that stands in for `standard_error`. `sim/internal/ffi_vm` is the only
%% caller and says why each one has no pure alternative.
-module(sim_ffi).

-export([term_digest/1, quiesce/2, quiet_logger/0, restore_logger/1, cells_new/1, cells_get/2, cells_put/3, cells_add/3,
         table_new/0, table_put/3, table_take/2, table_get/2, table_delete/1,
         table_clear/1, unique/0, os_pid/0,
         monotonic_us/0, registered_role/1, supervisor_children/1,
         install_sink/0, sink_lines/1, uninstall_sink/1, active_tasks/0]).

%% Waits until no process or port but the caller is runnable or running,
%% across three yields in a row, and then confirms it process by process.
%% The scheduler statistics do not count a process while it executes a
%% dirty NIF (every SQLite call, and the code loader's file reads), so the
%% cheap probe alone can declare quiescence while a commit is still
%% running. The confirmation reads the status of every registered process
%% (`registered`): the engines and the coordinator, the only processes
%% that hold a SQLite connection during a run, are registered, and so are
%% the code server and the loader. `every` reads every process,
%% which `erlang:processes()` makes cost half a millisecond, so the runner
%% asks for it only after it kills something, when an unregistered process
%% (a lock closing its file) may still be in a NIF. Gives up after MaxSpins
%% yields.
quiesce(MaxSpins, Scan) -> quiesce(0, 0, MaxSpins, Scan =:= every).

quiesce(_Stable, Spins, Max, _Deep) when Spins >= Max -> {error, nil};
quiesce(Stable, Spins, Max, Deep) when Stable >= 3 ->
    case all_waiting(self(), Deep) of
        true -> {ok, Spins};
        false -> erlang:yield(), quiesce(0, Spins + 1, Max, Deep)
    end;
quiesce(Stable, Spins, Max, Deep) ->
    erlang:yield(),
    case erlang:statistics(total_active_tasks_all) of
        1 -> quiesce(Stable + 1, Spins + 1, Max, Deep);
        _ -> quiesce(0, Spins + 1, Max, Deep)
    end.

all_waiting(Self, Deep) ->
    Pids = case Deep of
        true -> erlang:processes();
        false -> [whereis(Name) || Name <- erlang:registered()]
    end,
    lists:all(fun(P) ->
        P =:= Self orelse not is_pid(P) orelse
            case erlang:process_info(P, status) of
                {status, waiting} -> true;
                undefined -> true;
                _ -> false
            end
    end, Pids).

active_tasks() -> erlang:statistics(total_active_tasks_all).

cells_new(N) -> atomics:new(N, [{signed, true}]).
cells_get(Ref, I) -> atomics:get(Ref, I).
cells_put(Ref, I, V) -> atomics:put(Ref, I, V), nil.
cells_add(Ref, I, D) -> atomics:add_get(Ref, I, D).

table_new() -> ets:new(sim_faults, [set, public]).
table_put(T, K, V) -> ets:insert(T, {K, V}), nil.
table_take(T, K) ->
    case ets:take(T, K) of
        [{_, V}] -> {ok, V};
        [] -> {error, nil}
    end.
table_get(T, K) ->
    case ets:lookup(T, K) of
        [{_, V}] -> {ok, V};
        [] -> {error, nil}
    end.
table_delete(T) -> ets:delete(T), nil.
table_clear(T) -> ets:delete_all_objects(T), nil.

unique() -> erlang:unique_integer([positive]).
os_pid() -> list_to_binary(os:getpid()).

monotonic_us() -> erlang:monotonic_time(microsecond).

%% The prefix of a process's registered name before the `$` that
%% `process.new_name` appends, or the empty string for an unregistered one.
registered_role(Pid) ->
    case erlang:process_info(Pid, registered_name) of
        {registered_name, Name} ->
            [Prefix | _] = binary:split(atom_to_binary(Name), <<"$">>),
            Prefix;
        _ -> <<>>
    end.

%% The live children of a supervisor, in no particular order.
supervisor_children(Sup) ->
    try supervisor:which_children(Sup) of
        Children -> [Pid || {_, Pid, _, _} <- Children, is_pid(Pid)]
    catch _:_ -> []
    end.

%% Replaces the registered `standard_error` device with a process that
%% answers every output request and keeps the text, so a campaign's daemons
%% log to the run instead of the terminal.
install_sink() ->
    Old = whereis(standard_error),
    Sink = spawn(fun() -> sink_loop([]) end),
    case Old of
        undefined -> ok;
        _ -> unregister(standard_error)
    end,
    register(standard_error, Sink),
    {Old, Sink}.

sink_loop(Acc) ->
    receive
        {io_request, From, Ref, Request} ->
            From ! {io_reply, Ref, ok},
            sink_loop([request_text(Request) | Acc]);
        {lines, From, Ref} ->
            From ! {sink_lines, Ref, lists:reverse(Acc)},
            sink_loop([]);
        stop -> ok
    end.

request_text({put_chars, _Encoding, Chars}) -> unicode:characters_to_binary(Chars);
request_text({put_chars, Chars}) -> unicode:characters_to_binary(Chars);
request_text({put_chars, _Encoding, M, F, A}) ->
    unicode:characters_to_binary(apply(M, F, A));
request_text(_) -> <<>>.

%% Every line the sink has kept since the last call, oldest first.
sink_lines({_Old, Sink}) ->
    Ref = make_ref(),
    Sink ! {lines, self(), Ref},
    receive {sink_lines, Ref, Lines} -> Lines after 5000 -> [] end.

uninstall_sink({Old, Sink}) ->
    try unregister(standard_error) catch _:_ -> ok end,
    case Old of
        undefined -> ok;
        _ -> register(standard_error, Old)
    end,
    Sink ! stop,
    nil.

%% Silences the OTP logger (supervisor and crash reports, weft warnings)
%% and returns the level it had, so a quiet run does not print a report for
%% every process a fault kills.
quiet_logger() ->
    #{level := Level} = logger:get_primary_config(),
    logger:set_primary_config(level, none),
    Level.

restore_logger(Level) -> logger:set_primary_config(level, Level), nil.

%% The SHA-256 of a term's external format, in lowercase hex: a table
%% row's identity for the snapshot.
term_digest(Term) ->
    binary:encode_hex(crypto:hash(sha256, term_to_binary(Term)), lowercase).
