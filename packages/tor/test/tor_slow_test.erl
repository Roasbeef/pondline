%% EUnit's default per-test timeout is too short for the Tor network spike,
%% which waits minutes for a bootstrap and an onion service. A generator
%% (`_test_`) may carry its own timeout, so this one wraps the Gleam body.
-module(tor_slow_test).

-include_lib("eunit/include/eunit.hrl").

network_spike_test_() ->
    {timeout, 1200, fun() -> 'tor@network_spike_test':run_spike() end}.
