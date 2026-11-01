%% EUnit's default per-test timeout is too short for hosting an onion
%% service, which waits for a Tor bootstrap. A generator (`_test_`) may
%% carry its own timeout, so this one wraps the Gleam body.
-module(mailbox_slow_test).

-include_lib("eunit/include/eunit.hrl").

onion_hosting_test_() ->
    {timeout, 900, fun() -> 'mailbox@onion_test':run_onion() end}.
