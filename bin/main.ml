let print_end text =
  print_string text;
  print_newline ()

let default_man_dir = "man/generated"

let rec ensure_dir dir =
  if dir = "" || dir = "." || dir = Filename.dirname dir then ()
  else if Sys.file_exists dir then (
    if not (Sys.is_directory dir) then failwith (dir ^ " exists and is not a directory"))
  else (
    ensure_dir (Filename.dirname dir);
    Unix.mkdir dir 0o755)

let write_file path content =
  let channel = open_out path in
  Fun.protect
    ~finally:(fun () -> close_out channel)
    (fun () -> output_string channel content)

let read_file path =
  let channel = open_in path in
  Fun.protect
    ~finally:(fun () -> close_in channel)
    (fun () ->
      let length = in_channel_length channel in
      really_input_string channel length)

let generated_path ~dir page = Filename.concat dir page.Lpf.filename

let generate_man_pages ~dir =
  ensure_dir dir;
  Lpf.man_pages ()
  |> List.iter (fun page -> write_file (generated_path ~dir page) (Lpf.man_page_content page));
  Printf.printf "generated %d man pages in %s\n" (List.length (Lpf.man_pages ())) dir

let check_man_pages ~dir =
  let mismatches =
    Lpf.man_pages ()
    |> List.filter_map (fun page ->
           let path = generated_path ~dir page in
           if not (Sys.file_exists path) then Some (path ^ " is missing")
           else
             let actual = read_file path in
             let expected = Lpf.man_page_content page in
             if String.equal actual expected then None else Some (path ^ " is stale"))
  in
  match mismatches with
  | [] ->
      Printf.printf "checked %d man pages in %s\n" (List.length (Lpf.man_pages ())) dir;
      0
  | _ ->
      List.iter prerr_endline mismatches;
      1

let install_man_pages ~prefix =
  Lpf.man_pages ()
  |> List.iter (fun page ->
         let dir =
           Filename.concat
             (Filename.concat (Filename.concat prefix "share") "man")
             ("man" ^ string_of_int page.Lpf.section)
         in
         ensure_dir dir;
         write_file (Filename.concat dir page.Lpf.filename) (Lpf.man_page_content page));
  Printf.printf "installed %d man pages under %s\n" (List.length (Lpf.man_pages ())) prefix

let parse_value_option ~name ~default args =
  let rec loop current = function
    | [] -> current
    | flag :: value :: rest when String.equal flag name -> loop value rest
    | _ :: rest -> loop current rest
  in
  loop default args

let handle_man args =
  match args with
  | "generate" :: rest ->
      let dir = parse_value_option ~name:"--dir" ~default:default_man_dir rest in
      generate_man_pages ~dir
  | "check" :: rest ->
      let dir = parse_value_option ~name:"--dir" ~default:default_man_dir rest in
      exit (check_man_pages ~dir)
  | "install" :: rest ->
      let prefix = parse_value_option ~name:"--prefix" ~default:"/usr/local" rest in
      install_man_pages ~prefix
  | _ ->
      prerr_endline "usage: lpf man <generate|check|install> [--dir DIR] [--prefix PREFIX]";
      exit 64

let exit_for_policy_check result =
  let output = Lpf.Policy.format_check_result result in
  if output <> "" then prerr_endline output;
  match result.Lpf.Policy.policy with
  | Some _ -> exit 0
  | None -> exit 1

let print_diagnostics diagnostics =
  diagnostics
  |> List.iter (fun diagnostic -> prerr_endline (Lpf.Policy.diagnostic_to_string diagnostic))

let handle_check args =
  match args with
  | [ path ] ->
      read_file path |> Lpf.check_policy_text ~file:path |> exit_for_policy_check
  | _ ->
      prerr_endline "usage: lpf check <policy>";
      exit 64

let handle_fmt args =
  let check_only, paths =
    List.fold_left
      (fun (check_only, paths) arg ->
        if String.equal arg "--check" then (true, paths) else (check_only, paths @ [ arg ]))
      (false, []) args
  in
  match paths with
  | [ path ] -> (
      let input = read_file path in
      match Lpf.format_policy_text ~file:path input with
      | Ok formatted ->
          if check_only then (
            if String.equal input formatted then (
              Printf.printf "%s is formatted\n" path;
              exit 0)
            else (
              prerr_endline (path ^ " is not formatted");
              exit 1))
          else print_string formatted
      | Error diagnostics ->
          print_diagnostics diagnostics;
          exit 1)
  | _ ->
      prerr_endline "usage: lpf fmt [--check] <policy>";
      exit 64

let parse_plan_args args =
  let is_option arg = String.length arg > 0 && arg.[0] = '-' in
  let rec loop paths = function
    | [] -> Ok (List.rev paths)
    | "--json" :: rest -> loop paths rest
    | arg :: _ when is_option arg -> Error arg
    | path :: rest -> loop (path :: paths) rest
  in
  loop [] args

let handle_plan args =
  match parse_plan_args args with
  | Error option ->
      prerr_endline ("unknown lpf plan option: " ^ option);
      prerr_endline "usage: lpf plan [--json] <policy>";
      exit 64
  | Ok [ path ] -> (
      let input = read_file path in
      match Lpf.plan_policy_text ~file:path input with
      | Ok (plan, diagnostics) ->
          print_diagnostics diagnostics;
          print_string (Lpf.Plan.to_json plan)
      | Error diagnostics ->
          print_diagnostics diagnostics;
          exit 1)
  | Ok _ ->
      prerr_endline "usage: lpf plan [--json] <policy>";
      exit 64

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
  | _ :: "check" :: args -> handle_check args
  | _ :: "fmt" :: args -> handle_fmt args
  | _ :: "plan" :: args -> handle_plan args
  | _ :: "man" :: args -> handle_man args
  | _ :: name :: _ -> (
      match Lpf.command_of_string name with
      | Some Lpf.Version -> print_end Lpf.version
      | Some Lpf.Help -> print_end (Lpf.help ())
      | Some command -> planned command
      | None ->
          prerr_endline ("unknown lpf command: " ^ name);
          exit 64)
  | [] -> assert false
