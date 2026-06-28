let print_unavailable () =
  prerr_endline "lpf verify: Z3 solver not available";
  prerr_endline "";
  prerr_endline "Install Z3 and build lpf-verify:";
  prerr_endline "  brew install z3         # macOS";
  prerr_endline "  apt install libz3-dev   # Debian/Ubuntu";
  prerr_endline "  opam install z3";
  prerr_endline "  ENABLE_LPF_VERIFY=1 dune build bin/verify/main.exe";
  prerr_endline "";
  prerr_endline "Then run: lpf verify consistency policy.lpf"

let status_to_exit_code = function
  | Lpf.Process.Exited code -> code
  | Lpf.Process.Signaled signal -> 128 + signal
  | Lpf.Process.Stopped signal -> 128 + signal
  | Lpf.Process.Failed_to_start _ -> 1

let run source invocation =
  match
    Lpf.Process.run_capture ~temp_prefix:"lpf-verify-delegate" invocation
  with
  | Ok output ->
      print_string output.Lpf.Process.stdout;
      prerr_string output.Lpf.Process.stderr;
      exit (status_to_exit_code output.Lpf.Process.status)
  | Error error -> (
      match (source, error.Lpf.Process.status) with
      | `Default, Lpf.Process.Failed_to_start _ ->
          print_unavailable ();
          exit 1
      | _ ->
          prerr_endline (Lpf.Process.string_of_run_error "lpf verify" error);
          exit 1)

let handle args =
  match Sys.getenv_opt "LPF_VERIFY_BIN" with
  | Some bin when String.trim bin <> "" ->
      run `Explicit { program = bin; argv = bin :: args }
  | _ ->
      let exe = Sys.argv.(0) in
      let exe_path =
        if Filename.is_relative exe then Filename.concat (Sys.getcwd ()) exe
        else exe
      in
      let sibling = Filename.concat (Filename.dirname exe_path) "lpf-verify" in
      if Sys.file_exists sibling then
        run `Sibling { program = sibling; argv = sibling :: args }
      else run `Default { program = "lpf-verify"; argv = "lpf-verify" :: args }
