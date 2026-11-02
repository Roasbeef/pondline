%% Erlang shim for the telemetry package. The Gleam-side contract, and why
%% each function is foreign, is in `telemetry/internal/ffi_logger.gleam`.
%%
%% Most of this file is the handler's formatter, `format/2`, and most of
%% that is one rule: an event Pondline did not render is rebuilt from its
%% shape and never printed as given. OTP's own formatter prints a crashed
%% process's mailbox and dictionary, a stack frame's arguments (a NIF or BIF
%% that raises puts its whole argument list in the frame, which for
%% `crypto` is the key and the plaintext), a `gen_server`'s state and last
%% message, and the data inside every reason. Any of those can be a
%% payload, a key or a capability, so none of them is read here.
%%
%% What a foreign line keeps:
%%
%%   - the report's kind (`crash_report`, `supervisor_report`, ...);
%%   - a process's registered name, its label's tag, or its initial call
%%     as `module:function/arity`;
%%   - a reason's tag: an atom as itself, a tuple as its first atom, a
%%     Gleam panic as its kind, module, function and line;
%%   - up to three stack frames as `module:function/arity:line`;
%%   - a format string with each argument replaced by its shape, and the
%%     literal prefix of a `weft` warning.
%%
%% Atoms, module and function names, line numbers and format strings come
%% from code, never from input: no untrusted byte becomes an atom
%% (`docs/gleam-style.md` Part IV §2). That is what makes them safe to keep.
%%
%% Every value is written through `telemetry@logfmt:quote/1`, the same
%% escaping our own lines use, so a foreign value cannot split a line.
-module(telemetry_ffi).

-export([install/1, enabled/1, emit/2, constructor_name/1, getenv/1,
         format/2]).

%% ------------------------------------------------------------ installing

%% Puts our formatter on a `default` handler that writes to standard error.
%% `logger` cannot change a running handler's device, so a handler that is
%% not already ours is removed and added again; one that is keeps running
%% and only has its formatter and filters replaced, so a second install
%% (a second test) loses no line.
install(Level) ->
    Formatter = {?MODULE, #{}},
    Filters = filters(Level),
    Result =
        case logger:get_handler_config(default) of
            {ok, #{module := logger_std_h, config := #{type := standard_error}}} ->
                ok = logger:update_handler_config(default, formatter, Formatter),
                ok = logger:update_handler_config(default, filters, Filters),
                logger:update_handler_config(default, filter_default, log);
            _ ->
                _ = logger:remove_handler(default),
                logger:add_handler(default, logger_std_h, #{
                    level => all,
                    config => #{type => standard_error},
                    formatter => Formatter,
                    filters => Filters,
                    filter_default => log
                })
        end,
    case Result of
        ok ->
            ok = logger:set_primary_config(level, Level),
            {ok, nil};
        _ ->
            {error, nil}
    end.

%% A remote group leader's events belong to that node, as in OTP's own
%% default. Progress reports say a child or an application started, which
%% is `debug` in Pondline's policy, so below `debug` they are dropped.
filters(debug) ->
    [{remote_gl, {fun logger_filters:remote_gl/2, stop}}];
filters(_) ->
    [{remote_gl, {fun logger_filters:remote_gl/2, stop}},
     {progress, {fun logger_filters:progress/2, stop}}].

enabled(Level) ->
    logger:allow(Level, 'telemetry@log').

%% The line travels as a report under one key, so nothing between here and
%% the formatter can reinterpret it as a format string.
emit(Level, Line) ->
    logger:log(Level, #{pondline => Line}, #{domain => [pondline]}),
    nil.

constructor_name(Value) when is_atom(Value) ->
    atom_to_binary(Value, utf8);
constructor_name(Value)
  when is_tuple(Value), tuple_size(Value) > 0, is_atom(element(1, Value)) ->
    atom_to_binary(element(1, Value), utf8);
constructor_name(Value) ->
    bracket(shape(Value)).

getenv(Name) ->
    case os:getenv(binary_to_list(Name)) of
        false -> {error, nil};
        Value -> {ok, unicode:characters_to_binary(Value)}
    end.

%% ------------------------------------------------------------ formatting

%% `logger`'s formatter callback. Every line starts `time=... level=...`.
%% If a formatter raises, `logger_h_common:try_format` prints the event's raw
%% message through OTP's own formatter, which is the leak this module exists
%% to close. So nothing here may raise: a body that cannot be built keeps its
%% timestamp and degrades to a fixed line, and anything else falls to a fixed
%% line of its own.
format(Event, _Config) ->
    try line(Event)
    catch _:_ -> <<"level=error component=otp event=unformattable\n">>
    end.

line(#{level := Level, msg := Msg} = Event) ->
    Meta = maps:get(meta, Event, #{}),
    Body =
        try body(Msg, Meta)
        catch _:_ -> pairs([{component, otp}, {event, unformattable}])
        end,
    [<<"time=">>, timestamp(Meta), <<" level=">>, atom_to_binary(Level, utf8),
     $\s, Body, $\n].

timestamp(Meta) ->
    Micros = maps:get(time, Meta, logger:timestamp()),
    unicode:characters_to_binary(calendar:system_time_to_rfc3339(
        Micros div 1000, [{unit, millisecond}, {offset, "Z"}])).

%% Our own line was rendered by `telemetry@line:render/3` from typed fields
%% and is printed as it is. Everything else is foreign.
body({report, #{pondline := Line}}, _Meta) when is_binary(Line) ->
    Line;
body({report, Report}, Meta) when is_map(Report) ->
    pairs([{component, otp} | report(Report, Meta)]);
body({string, Text}, Meta) ->
    pairs([{component, otp} | text(Text, Meta)]);
body({report, _Keywords}, Meta) ->
    pairs([{component, otp}, {event, foreign_report} | origin(Meta)]);
body({Format, Args}, Meta) when is_list(Args) ->
    pairs([{component, otp} | formatted(Format, Args, Meta)]);
body(_Other, Meta) ->
    pairs([{component, otp}, {event, foreign} | origin(Meta)]).

%% ------------------------------------------------------------ reports

%% `proc_lib`'s crash report: `[Crasher, Neighbours]`. The crasher's
%% `messages`, `dictionary` and the arguments in its stack are what OTP
%% would print and this does not; the neighbours are dropped whole.
report(#{label := {proc_lib, crash}, report := [Crasher | _]}, Meta) ->
    [{event, crash_report} | pid(Meta)] ++ crasher(Crasher);

%% A supervisor started a child: `debug` only, by the install filter.
report(#{label := {supervisor, progress}, report := Props}, _Meta) ->
    [{event, child_started},
     {supervisor, supervisor_name(prop(supervisor, Props))}
     | child(prop(started, Props))];

%% A child terminated, failed to start or failed to stop. The offender's
%% start arguments (`mfargs`) are rendered as an arity only.
report(#{label := {supervisor, Context}, report := Props}, _Meta)
  when is_atom(Context) ->
    [{event, supervisor_report},
     {supervisor, supervisor_name(prop(supervisor, Props))},
     {context, Context}]
    ++ child(prop(offender, Props))
    ++ reason(prop(reason, Props));

%% `gen_server`, `gen_statem` and `gen_event` terminations. The report
%% carries the last message, the state and the client's stack; only the
%% name and the reason's tag survive.
report(#{label := {Behaviour, terminate}} = Report, _Meta)
  when Behaviour =:= gen_server; Behaviour =:= gen_statem;
       Behaviour =:= gen_event ->
    [{event, server_terminated}, {behaviour, Behaviour},
     {process, process_name(maps:get(name, Report, undefined))}]
    ++ reason(maps:get(reason, Report, undefined));
report(#{label := {application_controller, progress}, report := Props}, _) ->
    [{event, application_started},
     {application, tag(prop(application, Props))}];
report(#{label := {application_controller, exit}, report := Props}, _) ->
    [{event, application_exited},
     {application, tag(prop(application, Props))}]
    ++ reason(prop(exited, Props));
report(#{label := Label}, Meta) ->
    [{event, foreign_report}, {label, tag(Label)} | origin(Meta)];
report(_Report, Meta) ->
    [{event, foreign_report} | origin(Meta)].

crasher(Props) ->
    Name =
        case prop(registered_name, Props) of
            Atom when is_atom(Atom), Atom =/= undefined -> [{process, Atom}];
            _ -> label(prop(process_label, Props))
        end,
    Name
    ++ [{initial_call, call(prop(initial_call, Props))}]
    ++ error_info(prop(error_info, Props)).

%% A `proc_lib:set_label/1` label is any term; only its tag is kept.
label(undefined) -> [];
label(Label) -> [{process, tag(Label)}].

error_info({Class, Reason, Stack}) when is_atom(Class) ->
    [{class, Class} | reason(Reason)] ++ frames(Stack);
error_info(_) ->
    [].

%% ------------------------------------------------------------ reasons

%% A reason's tag and, when it has one, where it was raised. A Gleam panic
%% keeps its kind and location; its `message` and `value` are dropped,
%% because `let assert` puts the unmatched value there. An exit reason
%% `{Reason, Stack}` is unwrapped once.
reason(#{gleam_error := Kind} = Error) when is_atom(Kind) ->
    [{reason, Kind}]
    ++ [{module, M} || M <- [maps:get(module, Error, undefined)], is_binary(M)]
    ++ [{function, F} || F <- [maps:get(function, Error, undefined)], is_binary(F)]
    ++ [{line, L} || L <- [maps:get(line, Error, undefined)], is_integer(L)];
reason({Inner, Stack}) when is_list(Stack), Stack =/= [] ->
    case lists:all(fun is_frame/1, Stack) of
        true -> reason(Inner) ++ frames(Stack);
        false -> [{reason, tag({Inner, Stack})}]
    end;
reason(Reason) ->
    [{reason, tag(Reason)}].

is_frame({M, F, A, L}) when is_atom(M), is_atom(F), is_list(L) ->
    is_integer(A) orelse is_list(A);
is_frame(_) ->
    false.

%% The top three frames as `module:function/arity:line`. A frame raised by
%% a BIF or NIF holds the call's argument list where its arity would be;
%% only the list's length is kept.
frames(Stack) when is_list(Stack) ->
    case [frame(F) || F <- lists:sublist(Stack, 3), is_frame(F)] of
        [] -> [];
        Frames -> [{at, iolist_to_binary(lists:join(<<",">>, Frames))}]
    end;
frames(_) ->
    [].

frame({M, F, A, Location}) ->
    Arity = case is_list(A) of true -> length(A); false -> A end,
    Line =
        case lists:keyfind(line, 1, Location) of
            {line, N} when is_integer(N) -> [$:, integer_to_binary(N)];
            _ -> []
        end,
    iolist_to_binary([atom_to_binary(M, utf8), $:, atom_to_binary(F, utf8), $/,
                      integer_to_binary(Arity), Line]).

%% ------------------------------------------------------------ names

supervisor_name({local, Name}) when is_atom(Name) -> Name;
supervisor_name({global, Name}) when is_atom(Name) -> Name;
supervisor_name({Pid, Module}) when is_pid(Pid), is_atom(Module) -> Module;
supervisor_name(Other) -> tag(Other).

process_name({local, Name}) when is_atom(Name) -> Name;
process_name(Name) when is_atom(Name) -> Name;
process_name(Pid) when is_pid(Pid) -> Pid;
process_name(Other) -> tag(Other).

%% A child's identifier (an atom, or an index from a Gleam static
%% supervisor) and its start function as an arity.
child(Props) when is_list(Props) ->
    Id =
        case prop(id, Props) of
            I when is_atom(I); is_integer(I) -> [{child, I}];
            Other -> [{child, tag(Other)}]
        end,
    Id ++ [{start, call(prop(mfargs, Props))}];
child(_) ->
    [].

%% A start function as `module:function/arity`. A `factory_supervisor`
%% child reports `undefined` where the arguments belong, so the arity is
%% given only when there is one.
call({M, F, Args}) when is_atom(M), is_atom(F) ->
    Arity =
        case Args of
            _ when is_list(Args) -> [$/, integer_to_binary(length(Args))];
            _ when is_integer(Args) -> [$/, integer_to_binary(Args)];
            _ -> []
        end,
    iolist_to_binary([atom_to_binary(M, utf8), $:, atom_to_binary(F, utf8),
                      Arity]);
call(Other) ->
    tag(Other).

%% ------------------------------------------------------------ text

%% A foreign string is runtime text whose source is unknown, so only its
%% size is printed, except a `weft` warning, whose prefix is a literal.
text(Text, Meta) ->
    Binary = unicode:characters_to_binary(Text),
    case weft(Binary) of
        none -> [{event, foreign_text}, {bytes, byte_size(Binary)} | origin(Meta)];
        Pairs -> Pairs
    end.

%% A format and its arguments. The emulator's own "Error in process" line
%% carries an exit reason; `weft` warns through `"~s"`; `gleam_otp`'s actor
%% names a discarded message; anything else keeps its format string with
%% every argument replaced by its shape.
formatted(_Format, [Pid, Reason], #{error_logger := #{emulator := true}})
  when is_pid(Pid) ->
    [{event, process_crashed}, {pid, Pid} | reason(Reason)];
formatted("~s", [Text], Meta) ->
    text(Text, Meta);
formatted("Actor discarding unexpected message: ~s", [Text], _Meta) ->
    discarded(gleam_otp, unicode:characters_to_binary(Text));
formatted(Format, Args, Meta) ->
    [{event, foreign}, {text, template(Format, Args)} | origin(Meta)].

weft(<<"weft/actor discarding unexpected message: ", Rest/binary>>) ->
    discarded('weft/actor', Rest);
weft(<<"weft/state_machine discarding unexpected message: ", Rest/binary>>) ->
    discarded('weft/state_machine', Rest);
weft(<<"weft", _/binary>> = Text) ->
    [Prefix | _] = binary:split(Text, <<": ">>),
    [{event, weft_warning}, {text, Prefix}];
weft(_) ->
    none.

%% An unexpected message, named by the constructor that opens its
%% `string.inspect` rendering, `Ok(...)` as `Ok`. Anything else, a string
%% or a tuple, is not named.
discarded(Source, Inspected) ->
    Name =
        case re:run(Inspected, <<"^[A-Z][A-Za-z0-9_]*">>, [{capture, first, binary}]) of
            {match, [Constructor]} -> [{message, Constructor}];
            nomatch -> []
        end,
    [{event, discarded_message}, {source, Source} | Name].

template(Format, Args) ->
    try io_lib:scan_format(chars(Format), Args) of
        Parts -> unicode:characters_to_binary([part(P) || P <- Parts])
    catch
        _:_ -> <<"<unformattable>">>
    end.

chars(Format) when is_binary(Format) -> unicode:characters_to_list(Format);
chars(Format) when is_atom(Format) -> atom_to_list(Format);
chars(Format) -> Format.

%% A literal character stays; a directive becomes its argument's shape,
%% or the atom itself, and `~n` a space so the line stays one line.
part(Char) when is_integer(Char) -> Char;
part(#{control_char := $n}) -> $\s;
part(#{args := [Atom | _]}) when is_atom(Atom) -> atom_to_binary(Atom, utf8);
part(#{args := [Arg | _]}) -> bracket(shape(Arg));
part(_) -> <<>>.

origin(#{mfa := {M, F, A}}) when is_atom(M), is_atom(F), is_integer(A) ->
    [{origin, iolist_to_binary([atom_to_binary(M, utf8), $:,
                                atom_to_binary(F, utf8), $/,
                                integer_to_binary(A)])}];
origin(_) ->
    [].

pid(#{pid := Pid}) when is_pid(Pid) -> [{pid, Pid}];
pid(_) -> [].

%% ------------------------------------------------------------ shapes

%% What a term is, never what it holds.
tag(Atom) when is_atom(Atom) -> Atom;
tag(Tuple) when is_tuple(Tuple), tuple_size(Tuple) > 0,
                is_atom(element(1, Tuple)) -> element(1, Tuple);
tag(Other) -> bracket(shape(Other)).

shape(T) when is_binary(T) -> binary;
shape(T) when is_bitstring(T) -> bitstring;
shape(T) when is_integer(T) -> integer;
shape(T) when is_float(T) -> float;
shape(T) when is_atom(T) -> atom;
shape(T) when is_list(T) -> list;
shape(T) when is_map(T) -> map;
shape(T) when is_tuple(T) -> tuple;
shape(T) when is_pid(T) -> pid;
shape(T) when is_port(T) -> port;
shape(T) when is_reference(T) -> reference;
shape(T) when is_function(T) -> 'fun';
shape(_) -> term.

bracket(Shape) -> <<"<", (atom_to_binary(Shape, utf8))/binary, ">">>.

prop(Key, Props) when is_list(Props) ->
    case lists:keyfind(Key, 1, Props) of
        {Key, Value} -> Value;
        false -> undefined
    end;
prop(_Key, _Props) ->
    undefined.

%% ------------------------------------------------------------ rendering

pairs(Pairs) ->
    lists:join($\s, [[atom_to_binary(K, utf8), $=, value(V)] || {K, V} <- Pairs]).

value(V) when is_atom(V) -> 'telemetry@logfmt':quote(atom_to_binary(V, utf8));
value(V) when is_integer(V) -> integer_to_binary(V);
value(V) when is_binary(V) -> 'telemetry@logfmt':quote(V);
value(V) when is_pid(V) -> 'telemetry@logfmt':quote(list_to_binary(pid_to_list(V))).
