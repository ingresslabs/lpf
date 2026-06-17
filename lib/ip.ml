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

let rule_list_invocation () = { program = "ip"; argv = [ "ip"; "rule"; "list" ] }
let route_show_invocation () = { program = "ip"; argv = [ "ip"; "route"; "show"; "table"; "all" ] }

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
  with_temp_file "lpf-ip-stdout" (fun stdout_path ->
      with_temp_file "lpf-ip-stderr" (fun stderr_path ->
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

let rule_list_with_runner runner = runner (rule_list_invocation ())
let rule_list () = rule_list_with_runner run

let route_show_with_runner runner = runner (route_show_invocation ())
let route_show () = route_show_with_runner run

let string_of_run_status = function
  | Exited code -> "exit " ^ string_of_int code
  | Signaled signal -> "signal " ^ string_of_int signal
  | Stopped signal -> "stopped by signal " ^ string_of_int signal
  | Failed_to_start message -> "failed to start: " ^ message

let string_of_run_error error =
  let stderr = String.trim error.stderr in
  let detail = if String.equal stderr "" then "" else ": " ^ stderr in
  "ip command failed (" ^ string_of_run_status error.status ^ "): "
  ^ String.concat " " error.invocation.argv ^ detail
