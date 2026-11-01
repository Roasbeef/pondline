%% Test support: captures the real events OTP logs when real processes
%% crash, so the scrubber is tested against the shapes OTP actually builds
%% rather than shapes written by hand.
-module(telemetry_test_ffi).

-export([capture_start/0, capture_stop/0, log/2, format/1,
         spawn_crasher/1, raw_crasher/1, gen_server_crasher/1,
         string_event/1, bif_crash/1, send_raw/2,
         factory_child_report/1]).

%% A `logger` handler callback: forwards every event to the collector.
log(Event, #{config := #{collector := Collector}}) ->
    Collector ! {event, Event},
    ok.

%% Adds a handler that hands every event to a collector, and mutes the
%% default handler meanwhile so the planted secrets do not reach the test
%% output through OTP's own formatter.
capture_start() ->
    Collector = spawn(fun() -> collect([]) end),
    persistent_term:put({?MODULE, collector}, Collector),
    {ok, #{level := Level}} = logger:get_handler_config(default),
    persistent_term:put({?MODULE, default_level}, Level),
    ok = logger:update_handler_config(default, level, none),
    #{level := Primary} = logger:get_primary_config(),
    persistent_term:put({?MODULE, primary}, Primary),
    ok = logger:set_primary_config(level, all),
    ok = logger:add_handler(telemetry_capture, ?MODULE,
                            #{level => all, filter_default => log,
                              config => #{collector => Collector}}),
    nil.

%% Removes the handler, restores the default one and returns the events
%% captured, oldest first.
capture_stop() ->
    timer:sleep(200),
    ok = logger:remove_handler(telemetry_capture),
    ok = logger:update_handler_config(default, level,
                                      persistent_term:get({?MODULE, default_level})),
    ok = logger:set_primary_config(level, persistent_term:get({?MODULE, primary})),
    Collector = persistent_term:get({?MODULE, collector}),
    Collector ! {done, self()},
    receive {events, Events} -> Events after 5000 -> [] end.

collect(Acc) ->
    receive
        {event, Event} -> collect([Event | Acc]);
        {done, Caller} -> Caller ! {events, lists:reverse(Acc)}
    end.

%% The handler's formatter applied to one captured event, as one binary.
format(Event) ->
    unicode:characters_to_binary(telemetry_ffi:format(Event, #{})).

%% A `proc_lib` process holding `Secret` in its mailbox and dictionary that
%% then raises from a BIF with `Secret` as an argument.
spawn_crasher(Secret) ->
    proc_lib:spawn(fun() ->
        self() ! {queued, Secret},
        put(held, Secret),
        binary:part(Secret, 1000000, 1)
    end),
    nil.

%% A plain `erlang:spawn` process that exits with `Secret` in its reason,
%% which the emulator reports itself.
raw_crasher(Secret) ->
    spawn(fun() -> erlang:error({badmatch, Secret}) end),
    nil.

%% A `gen_server` whose state is `Secret` and whose last message, also
%% `Secret`, makes it stop with `Secret` in the reason.
gen_server_crasher(Secret) ->
    {ok, Pid} = gen_server:start(telemetry_test_server, Secret, []),
    try gen_server:call(Pid, {crash, Secret}) catch exit:_ -> ok end,
    nil.

%% A library logging free text, as `logging.log` in mist does.
string_event(Text) ->
    logger:error(Text),
    nil.

%% Raises from a BIF with `Secret` as an argument, in the caller.
bif_crash(Secret) ->
    binary:part(Secret, 1000000, 1).

send_raw(Pid, Message) ->
    Pid ! Message,
    nil.

%% The `child_terminated` report a `gleam_otp` factory supervisor writes
%% when a mist connection's handler fails, as it was captured from a real
%% run: the reason is the handler's inspected exception, and the offender's
%% `mfargs` has `undefined` where a list of arguments would be.
factory_child_report(Reason) ->
    #{level => error,
      meta => #{time => logger:timestamp(), pid => self(),
                domain => [otp, sasl]},
      msg => {report,
              #{label => {supervisor, child_terminated},
                report =>
                    [{supervisor, {local, 'glisten_connection_supervisor$19078'}},
                     {errorContext, child_terminated},
                     {reason, Reason},
                     {offender,
                      [{pid, self()},
                       {id, 0},
                       {mfargs, {gleam@otp@factory_supervisor,
                                 start_child_callback, undefined}},
                       {restart_type, temporary},
                       {significant, false},
                       {shutdown, 5000},
                       {child_type, worker}]}]}}}.
