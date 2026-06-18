let () =
  let runner invocation =
    assert (String.equal invocation.Lpf.Conntrack.program "conntrack");
    Ok "tcp 10.0.0.1 10.0.0.2 12345 80 ESTABLISHED src=10.0.0.1 dst=10.0.0.2"
  in
  let result = Lpf.Conntrack.list_with_runner runner in
  (match result with
  | Ok out -> assert (String.length out > 0)
  | _ -> assert false);

  let entries =
    Lpf.Conntrack.parse_list "tcp 10.0.0.1 10.0.0.2 12345 80 ESTABLISHED"
  in
  assert (List.length entries = 1);
  (match entries with
  | [ e ] ->
      assert (String.equal e.Lpf.Conntrack.protocol "tcp");
      assert (String.equal e.src "10.0.0.1");
      assert (String.equal e.dst "10.0.0.2")
  | _ -> assert false);

  let entries = Lpf.Conntrack.parse_list "" in
  assert (entries = []);

  let result =
    Lpf.Conntrack.delete_with_runner runner ~src:"10.0.0.1" ~dst:"10.0.0.2" ()
  in
  assert (result = Ok ());

  let result = Lpf.Conntrack.flush_with_runner (fun _ -> Ok "flushed") in
  assert (result = Ok ());

  let error =
    {
      Lpf.Conntrack.invocation =
        { Lpf.Conntrack.program = "conntrack"; argv = [ "conntrack"; "-L" ] };
      status = Lpf.Conntrack.Exited 1;
      stderr = "failed";
    }
  in
  let msg = Lpf.Conntrack.string_of_run_error error in
  assert (String.length msg > 0);

  Printf.printf "conntrack tests passed\n"
