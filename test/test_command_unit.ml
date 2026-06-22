let () =
  let require condition message = if not condition then failwith message in

  require (Lpf.command_of_string "check" = Some Lpf.Check) "check command";
  require (Lpf.command_of_string "plan" = Some Lpf.Plan) "plan command";
  require (Lpf.command_of_string "apply" = Some Lpf.Apply) "apply command";
  require (Lpf.command_of_string "nonexistent" = None) "unknown command is None";

  require (String.equal Lpf.version "0.2.3") "version string";
  require (String.length (Lpf.help ()) > 100) "help should be non-trivial";

  let all = Lpf.all_commands in
  require (List.length all = 19) "should be 19 commands";

  List.iter
    (fun (name, command, _summary) ->
      let n = Lpf.command_name command in
      require (name = n) "command name roundtrip";
      let s = Lpf.command_summary command in
      require (String.length s > 0) "every command should have a summary";
      let help_text = Lpf.command_help command in
      require
        (String.length help_text > 0)
        "every command should have help text")
    all;

  require
    (List.length (Lpf.man_pages ()) >= 20)
    "should have at least 20 man pages";

  require
    (List.length Lpf.command_docs >= 15)
    "should have at least 15 command docs";

  Printf.printf "command tests passed\n"
