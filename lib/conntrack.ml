type invocation = {
  program : string;
  argv : string list;
}

type run_status =
  | Exited of int
  | Signaled of int
  | Stopped of int
  | Failed_to_start of string

type run_error = {
  invocation : invocation;
  status : run_status;
  stderr : string;
}

type conntrack_entry = {
  protocol : string;
  src : string;
  dst : string;
  sport : string;
  dport : string;
  state : string;
  raw : string;
}

let list_invocation () = { program = "conntrack"; argv = [ "conntrack"; "-L"; "-o"; "extended" ] }
let delete_invocation ~src ~dst = { program = "conntrack"; argv = [ "conntrack"; "-D"; "-s"; src; "-d"; dst ] }
let flush_invocation () = { program = "conntrack"; argv = [ "conntrack"; "-F" ] }

let close_noerr fd = try Unix.close fd with Unix.Unix_error _ -> ()

let with_temp_file prefix f =
  let path = Filename.temp_file prefix ".txt" in
  Fun.protect ~finally:(fun () -> if Sys.file_exists path then Sys.remove path) (fun () -> f path)

let read_file path =
  let channel = open_in path in
  Fun.protect
    ~finally:(fun () -> close_in channel)
    (fun () ->
      let length = in_channel_length channel in
      really_input_string channel length)

let status_of_unix_status = function
  | Unix.WEXITED code -> Exited code
  | Unix.WSIGNALED signal -> Signaled signal
  | Unix.WSTOPPED signal -> Stopped signal

let run invocation =
  with_temp_file "lpf-conntrack-stdout" (fun stdout_path ->
      with_temp_file "lpf-conntrack-stderr" (fun stderr_path ->
          let stdout_fd = Unix.openfile stdout_path [ Unix.O_WRONLY; Unix.O_TRUNC ] 0o600 in
          let stderr_fd = Unix.openfile stderr_path [ Unix.O_WRONLY; Unix.O_TRUNC ] 0o600 in
          match
            try
              let pid =
                Unix.create_process invocation.program
                  (Array.of_list invocation.argv) Unix.stdin stdout_fd stderr_fd
              in
              close_noerr stdout_fd;
              close_noerr stderr_fd;
              let _, status = Unix.waitpid [] pid in
              let stdout = read_file stdout_path in
              let stderr = read_file stderr_path in
              let status = status_of_unix_status status in
              Ok (status, stdout, stderr)
            with Unix.Unix_error (error, function_name, argument) ->
              close_noerr stdout_fd;
              close_noerr stderr_fd;
              Error (Unix.error_message error ^ " in " ^ function_name ^ "(" ^ argument ^ ")")
          with
          | Ok (Exited 0, stdout, _stderr) -> Ok stdout
          | Ok (status, _stdout, stderr) -> Error { invocation; status; stderr }
          | Error message ->
              Error { invocation; status = Failed_to_start message; stderr = message }))

let list_with_runner runner = runner (list_invocation ())
let list () = list_with_runner run

let delete_with_runner runner ~src ~dst = runner (delete_invocation ~src ~dst) |> Result.map ignore
let delete ~src ~dst = delete_with_runner run ~src ~dst

let flush_with_runner runner = runner (flush_invocation ()) |> Result.map ignore
let flush () = flush_with_runner run

let string_of_run_status = function
  | Exited code -> "exit " ^ string_of_int code
  | Signaled signal -> "signal " ^ string_of_int signal
  | Stopped signal -> "stopped by signal " ^ string_of_int signal
  | Failed_to_start message -> "failed to start: " ^ message

let string_of_run_error error =
  let stderr = String.trim error.stderr in
  let detail = if String.equal stderr "" then "" else ": " ^ stderr in
  "conntrack command failed (" ^ string_of_run_status error.status ^ "): "
  ^ String.concat " " error.invocation.argv ^ detail

let parse_line line =
  let fields = String.split_on_char ' ' line |> List.filter (fun s -> String.length s > 0) in
  match fields with
  | proto :: src :: dst :: rest ->
      let sport = try List.nth rest 0 with _ -> "" in
      let dport = try List.nth rest 2 with _ -> "" in
      let state = try List.nth rest 3 with _ -> "" in
      Some { protocol = proto; src; dst; sport; dport; state; raw = line }
  | _ -> None

let parse_list output =
  String.split_on_char '\n' output
  |> List.filter_map parse_line
