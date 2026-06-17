let () =
  let runner invocation =
    assert (String.equal invocation.Lpf.Nft.program "nft");
    Ok "ok"
  in
  let result = Lpf.Table.add_with_runner runner "threats" "10.0.0.1" in
  assert (result = Ok ());

  let result = Lpf.Table.delete_with_runner runner "threats" "10.0.0.1" in
  assert (result = Ok ());

  let calls = ref [] in
  let track_runner invocation =
    calls := invocation.Lpf.Nft.argv @ !calls;
    Ok "ok"
  in
  let result = Lpf.Table.replace_with_runner track_runner "threats" [ "10.0.0.1"; "10.0.0.2" ] in
  assert (result = Ok ());
  assert (List.length !calls >= 3);

  let fails_first _invocation = Error {
    Lpf.Nft.invocation = { Lpf.Nft.program = "nft"; argv = [ "nft" ] };
    status = Lpf.Nft.Exited 1; stderr = "fail";
  } in
  let result = Lpf.Table.add_with_runner fails_first "threats" "10.0.0.1" in
  (match result with Error _ -> () | _ -> assert false);

  Printf.printf "table tests passed\n"
