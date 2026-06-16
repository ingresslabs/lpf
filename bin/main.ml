let print_end text =
  print_string text;
  print_newline ()

let planned command =
  print_end (Lpf.command_help command);
  exit 2

let () =
  match Array.to_list Sys.argv with
  | [ _ ] | [ _; "--help" ] | [ _; "-h" ] | [ _; "help" ] ->
      print_end (Lpf.help ())
  | [ _; "version" ] | [ _; "--version" ] ->
      print_end Lpf.version
  | [ _; "help"; name ] -> (
      match Lpf.command_of_string name with
      | Some command -> print_end (Lpf.command_help command)
      | None ->
          prerr_endline ("unknown lpf command: " ^ name);
          exit 64)
  | _ :: name :: _ -> (
      match Lpf.command_of_string name with
      | Some Lpf.Version -> print_end Lpf.version
      | Some Lpf.Help -> print_end (Lpf.help ())
      | Some command -> planned command
      | None ->
          prerr_endline ("unknown lpf command: " ^ name);
          exit 64)
  | [] -> assert false

