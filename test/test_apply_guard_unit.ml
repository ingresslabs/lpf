let () =
  assert (Lpf.Apply_guard.parse_duration "10s" = Some 10);
  assert (Lpf.Apply_guard.parse_duration "5m" = Some 300);
  assert (Lpf.Apply_guard.parse_duration "2h" = Some 7200);
  assert (Lpf.Apply_guard.parse_duration "" = None);
  assert (Lpf.Apply_guard.parse_duration "x" = None);
  assert (Lpf.Apply_guard.parse_duration "10x" = None);

  let diag =
    Lpf.Apply_guard.error_diagnostic ~file:"test.lpf" "something went wrong"
  in
  assert (diag.severity = Lpf.Policy.Diag_error);
  assert (diag.message = "something went wrong");
  assert (diag.span.file = Some "test.lpf");

  let mock_runners =
    {
      Lpf.Apply_guard.list_ruleset = (fun () -> Ok "mock ruleset");
      apply = (fun _ruleset -> Ok ());
      apply_tc = (fun _rendered -> Ok ());
      apply_routing = (fun _rendered -> Ok ());
      tc_delete = (fun _device -> Ok ());
      routing_flush_table = (fun _table -> Ok ());
    }
  in

  let result =
    Lpf.Apply_guard.apply_policy_text_with_runners mock_runners ~file:"test.lpf"
      "set default deny\npass out proto tcp from any to any port 443"
  in
  (match result with
  | Ok ((), diagnostics) -> assert (diagnostics = [])
  | Error _ -> assert false);

  let mock_apply_fails =
    {
      mock_runners with
      apply =
        (fun _ ->
          Error
            {
              Lpf.Nft.invocation =
                { Lpf.Nft.program = "nft"; argv = [ "nft"; "-f"; "x" ] };
              status = Lpf.Nft.Exited 1;
              stderr = "apply failed";
            });
    }
  in
  let result =
    Lpf.Apply_guard.apply_policy_text_with_runners mock_apply_fails
      ~file:"test.lpf"
      "set default deny\npass out proto tcp from any to any port 443"
  in
  (match result with
  | Error diagnostics -> assert (List.length diagnostics > 0)
  | _ -> assert false);

  let result =
    Lpf.Apply_guard.apply_policy_text_with_runners mock_runners ~file:"test.lpf"
      ~confirm:"invalid"
      "set default deny\npass out proto tcp from any to any port 443"
  in
  (match result with
  | Error diagnostics -> assert (List.length diagnostics > 0)
  | _ -> assert false);

  Printf.printf "apply guard tests passed\n"
