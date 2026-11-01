-module(support_ffi).
-export([millisecond/0]).

%% The atom `millisecond`, which Gleam cannot build without making an atom.
millisecond() -> millisecond.
