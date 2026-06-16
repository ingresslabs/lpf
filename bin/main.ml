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
