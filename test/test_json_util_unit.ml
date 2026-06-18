let () =
  let require condition message = if not condition then failwith message in

  let s = Lpf.Json_util.string "hello" in
  require (s = "\"hello\"") "string should wrap in quotes";

  let s = Lpf.Json_util.string "say \"hello\"" in
  require (String.contains s '\\') "string should escape double quotes";

  let s = Lpf.Json_util.string "line1\nline2" in
  require (String.contains s '\\') "string should escape newline";

  let s = Lpf.Json_util.string "" in
  require (s = "\"\"") "empty string should be empty quotes";

  let i = Lpf.Json_util.int 42 in
  require (i = "42") "int should be string";

  let l = Lpf.Json_util.list Lpf.Json_util.int [ 1; 2; 3 ] in
  require (l = "[1,2,3]") "list should be comma-separated";

  let l = Lpf.Json_util.list Lpf.Json_util.int [] in
  require (l = "[]") "empty list";

  let o = Lpf.Json_util.option Lpf.Json_util.int (Some 5) in
  require (o = "5") "option some";

  let o = Lpf.Json_util.option Lpf.Json_util.int None in
  require (o = "null") "option none should be null";

  let obj =
    Lpf.Json_util.field_object [ ("key", Lpf.Json_util.string "val") ]
  in
  require (String.contains obj '"') "object should contain braces";
  require (String.contains obj ':') "object should contain colon";

  Printf.printf "json_util tests passed\n"
