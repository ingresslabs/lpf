let () =
  let entry = {
    Lpf.History.id = "abc123";
    timestamp = "2026-06-17T12:00:00Z";
    operator = "testuser";
    policy_checksum = "md5:deadbeef";
    policy_path = "fixtures/policies/basic.lpf";
    test_result = "passed";
    rollback_available = true;
  } in

  let json = Lpf.History.to_json [ entry ] in
  assert (String.length json > 0);
  assert (String.contains json '"');

  let text = Lpf.History.to_string [ entry ] in
  assert (String.length text > 0);

  let h = Lpf.History.add entry [] in
  assert (List.length h = 1);
  assert (h |> List.hd |> fun e -> String.equal e.id "abc123");

  let entry2 = { entry with id = "def456"; rollback_available = false } in
  let h2 = Lpf.History.add entry2 (Lpf.History.add entry []) in
  assert (List.length h2 = 2);

  let json2 = Lpf.History.to_json h2 in
  assert (String.contains json2 'a');

  let json_roundtrip = Lpf.History.to_json [ entry ] in
  assert (String.contains json_roundtrip '"');

  Printf.printf "history tests passed\n"
