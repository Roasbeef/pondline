%% A `gen_server` that holds a secret as its state and stops with it, for
%% the termination report `telemetry_test_ffi:gen_server_crasher/1` makes.
-module(telemetry_test_server).
-behaviour(gen_server).

-export([init/1, handle_call/3, handle_cast/2]).

init(Secret) -> {ok, {holding, Secret}}.

handle_call({crash, Secret}, _From, State) ->
    {stop, {refused, Secret}, State}.

handle_cast(_Message, State) -> {noreply, State}.
