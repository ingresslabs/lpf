let read_file path =
  let channel = open_in path in
  Fun.protect
    ~finally:(fun () -> close_in channel)
    (fun () ->
       let length = in_channel_length channel in
       really_input_string channel length)

let write_file path content =
  let channel = open_out path in
  Fun.protect
    ~finally:(fun () -> close_out channel)
    (fun () -> output_string channel content)

let rec ensure_dir ?(strict = true) dir =
  if dir = "" || dir = "." || dir = Filename.dirname dir then ()
  else if Sys.file_exists dir then (
    if not (Sys.is_directory dir) then
      if strict then failwith (dir ^ " exists and is not a directory")
      else prerr_endline ("warning: " ^ dir ^ " exists and is not a directory"))
  else (
    ensure_dir ~strict (Filename.dirname dir);
    try Unix.mkdir dir 0o755
    with Unix.Unix_error (error, _, _) ->
      if strict then failwith ("could not create " ^ dir ^ ": " ^ Unix.error_message error)
      else prerr_endline ("warning: could not create " ^ dir ^ ": " ^ Unix.error_message error))

let read_stdin () =
  let buffer = Buffer.create 4096 in
  (try
     while true do
       Buffer.add_string buffer (input_line stdin);
       Buffer.add_char buffer '\n'
     done
   with End_of_file -> ());
  Buffer.contents buffer
