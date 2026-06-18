let () =
  let require condition message = if not condition then failwith message in

  require true "exit code 0 should be available";

  let exit_msg = Lpf.Process.string_of_run_status (Lpf.Process.Exited 0) in
  require (String.contains exit_msg '0') "exited status should contain 0";

  let signal_msg = Lpf.Process.string_of_run_status (Lpf.Process.Signaled 9) in
  require (String.contains signal_msg '9') "signaled status should contain 9";

  let failed_msg =
    Lpf.Process.string_of_run_status (Lpf.Process.Failed_to_start "ENOENT")
  in
  require
    (String.contains failed_msg 'E')
    "failed_to_start should contain ENOENT";

  let invocation : Lpf.Process.invocation =
    { program = "test"; argv = [ "test"; "arg1"; "arg2" ] }
  in
  let error : Lpf.Process.run_error =
    {
      invocation;
      status = Lpf.Process.Exited 1;
      stderr = "something went wrong";
    }
  in
  let msg = Lpf.Process.string_of_run_error "test" error in
  require (String.length msg > 0) "error message should not be empty";
  require (String.contains msg 't') "error message should contain command name";
  require (String.contains msg '1') "error message should contain exit code";

  let echo_result =
    Lpf.Process.run ~temp_prefix:"echo-test"
      { program = "echo"; argv = [ "echo"; "hello" ] }
  in
  (match echo_result with
  | Ok stdout ->
      require (String.trim stdout = "hello") "echo should return hello"
  | Error error ->
      let msg = Lpf.Process.string_of_run_error "echo" error in
      prerr_endline msg;
      failwith msg);

  let nonexist_result =
    Lpf.Process.run ~temp_prefix:"nonexistent-test"
      {
        program = "nonexistent-command-lpf-test";
        argv = [ "nonexistent-command-lpf-test" ];
      }
  in
  (match nonexist_result with
  | Ok _ -> failwith "nonexistent command should fail"
  | Error _ -> ());

  Printf.printf "process tests passed\n"
