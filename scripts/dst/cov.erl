-module(cov).
-export([run/1, only/1]).
only([Out, TestMod | Covered]) -> put(only, list_to_atom(TestMod)), run([Out | Covered]).
%% run([Out, Pkg...]): cover-compile the production modules of each named
%% package (those under ../<pkg>/src), run every module under ./test through
%% eunit exactly as gleeunit does, then write per-module line coverage and
%% the functions with zero calls.
run([Out | Covered]) ->
    {ok, _} = cover:start(),
    Prod = lists:flatmap(fun(P) ->
        Mods = src_modules("../" ++ P ++ "/src"),
        Ebin = "build/dev/erlang/" ++ P ++ "/ebin/",
        [M || M <- Mods,
              {ok, M} =:= cover:compile_beam(Ebin ++ atom_to_list(M) ++ ".beam")]
    end, Covered),
    Tests = case get(only) of undefined -> modules_in("test"); O -> [O] end,
    io:format("covered ~p modules; ~p test modules~n", [length(Prod), length(Tests)]),
    T0 = erlang:monotonic_time(millisecond),
    R = eunit:test(Tests, [{scale_timeouts, 10}]),
    T1 = erlang:monotonic_time(millisecond),
    {ok, F} = file:open(Out, [write]),
    {ok, G} = file:open(Out ++ ".lines", [write]),
    io:format(F, "eunit: ~p in ~p ms~n", [R, T1 - T0]),
    {TC, TN} = lists:foldl(fun(M, {AC, AN}) ->
        {ok, Lines} = cover:analyse(M, coverage, line),
        {C, N} = lists:foldl(fun({_, {C1, N1}}, {A, B}) -> {A + C1, B + N1} end, {0, 0}, Lines),
        {ok, Fs} = cover:analyse(M, calls, function),
        Zero = [lists:flatten(io_lib:format("~s/~p", [Fn, Ar])) || {{_, Fn, Ar}, 0} <- Fs,
                 hd(atom_to_list(Fn)) =/= $-],
        Pct = case C + N of 0 -> 100.0; T -> 100 * C / T end,
        io:format(F, "~-40s ~6.1f% ~5w/~5w zero(~w): ~s~n",
                  [atom_to_list(M), Pct, C, C + N, length(Zero), string:join(Zero, " ")]),
        Miss = [L || {{_, L}, {0, 1}} <- Lines],
        io:format(G, "~s ~w~n", [atom_to_list(M), Miss]),
        {AC + C, AN + N}
    end, {0, 0}, lists:sort(Prod)),
    io:format(F, "TOTAL ~6.1f% ~w/~w~n", [100 * TC / max(1, TC + TN), TC, TC + TN]),
    file:close(F),
    halt(0).

src_modules(Dir) -> modules_in(Dir).

modules_in(Dir) ->
    Files = filelib:wildcard("**/*.{erl,gleam}", Dir),
    [list_to_atom(mod_name(F)) || F <- Files].

mod_name(F) ->
    case filename:extension(F) of
        ".gleam" -> lists:flatten(string:replace(filename:rootname(F), "/", "@", all));
        ".erl" -> filename:rootname(filename:basename(F))
    end.
