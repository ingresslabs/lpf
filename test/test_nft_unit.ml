let () =
  let runner invocation =
    assert (invocation.Lpf.Nft.program = "nft");
    Ok "mock ruleset"
  in
  let result = Lpf.Nft.list_ruleset_with_runner runner in
  assert (result = Ok "mock ruleset");

  let inv = Lpf.Nft.list_ruleset_invocation () in
  assert (String.equal inv.Lpf.Nft.program "nft");
  assert (inv.Lpf.Nft.argv = [ "nft"; "list"; "ruleset" ]);

  let inv = Lpf.Nft.apply_invocation "/tmp/test.nft" in
  assert (String.equal inv.Lpf.Nft.program "nft");
  assert (List.length inv.Lpf.Nft.argv >= 2);

  let result = Lpf.Nft.apply_with_runner (fun _ -> Ok "ok") "test ruleset" in
  assert (result = Ok ());

  let result = Lpf.Nft.apply_with_runner (fun _ -> Error {
    Lpf.Nft.invocation = { Lpf.Nft.program = "nft"; argv = [ "nft"; "-f"; "x" ] };
    status = Lpf.Nft.Exited 1; stderr = "failed";
  }) "test ruleset" in
  (match result with Error _ -> () | _ -> assert false);

  let error = {
    Lpf.Nft.invocation = { Lpf.Nft.program = "nft"; argv = [ "nft"; "list"; "ruleset" ] };
    status = Lpf.Nft.Exited 1; stderr = "permission denied";
  } in
  let msg = Lpf.Nft.string_of_run_error error in
  assert (String.length msg > 0);
  assert (String.contains msg 'n');

  Printf.printf "nft tests passed\n"
