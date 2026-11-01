-module(support_ffi).
-export([millisecond/0, http_exchange/3, file_mode/1, getenv/1,
         make_scratch_dir/0, remove_dir/1]).

%% The atom `millisecond`, which Gleam cannot build without making an atom.
millisecond() -> millisecond.

%% Sends `Raw` to 127.0.0.1:`Port` and reads until the server closes the
%% connection, which every response promises to do. Returns the status, the
%% headers with lower-cased names, and the body. A server that neither
%% answers nor closes within `TimeoutMs` is an error.
http_exchange(Port, Raw, TimeoutMs) ->
    case gen_tcp:connect({127, 0, 0, 1}, Port, [binary, {active, false}], 5000) of
        {ok, Socket} ->
            _ = gen_tcp:send(Socket, Raw),
            Result = recv_all(Socket, <<>>, TimeoutMs),
            _ = gen_tcp:close(Socket),
            case Result of
                {ok, Bytes} -> parse_response(Bytes);
                error -> {error, nil}
            end;
        {error, _} ->
            {error, nil}
    end.

recv_all(Socket, Acc, TimeoutMs) ->
    case gen_tcp:recv(Socket, 0, TimeoutMs) of
        {ok, Data} -> recv_all(Socket, <<Acc/binary, Data/binary>>, TimeoutMs);
        {error, closed} -> {ok, Acc};
        {error, _} -> error
    end.

parse_response(Bytes) ->
    case binary:split(Bytes, <<"\r\n\r\n">>) of
        [Head, Body] ->
            [StatusLine | HeaderLines] = binary:split(Head, <<"\r\n">>, [global]),
            [_Version, Status | _] = binary:split(StatusLine, <<" ">>, [global]),
            Headers = [split_header(Line) || Line <- HeaderLines],
            {ok, {binary_to_integer(Status), Headers, Body}};
        _ ->
            {error, nil}
    end.

split_header(Line) ->
    [Name, Value] = binary:split(Line, <<":">>),
    {string:lowercase(Name), string:trim(Value)}.

%% The permission bits of a file.
file_mode(Path) ->
    {ok, Info} = file:read_file_info(Path),
    element(8, Info) band 8#777.

%% The value of an environment variable, if it is set.
getenv(Name) ->
    case os:getenv(binary_to_list(Name)) of
        false -> {error, nil};
        Value -> {ok, list_to_binary(Value)}
    end.

%% A short path under /tmp: a unix socket path is limited to about 100
%% bytes, and the platform temp directory can already use most of that.
make_scratch_dir() ->
    Dir = "/tmp/rwmb-" ++ integer_to_list(erlang:unique_integer([positive])),
    ok = file:make_dir(Dir),
    list_to_binary(Dir).

remove_dir(Dir) ->
    _ = file:del_dir_r(binary_to_list(Dir)),
    nil.
