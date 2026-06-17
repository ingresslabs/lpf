let entry1 = {
  Lpf.History.id = "abc123";
  timestamp = "2026-06-17T12:00:00Z";
  operator = "testuser";
  policy_checksum = "md5:deadbeef";
  policy_path = "fixtures/policies/basic.lpf";
  test_result = "passed";
  rollback_available = true;
}

let entry2 = {
  Lpf.History.id = "def456";
  timestamp = "2026-06-18T08:30:00Z";
  operator = "admin";
  policy_checksum = "md5:cafebabe";
  policy_path = "/etc/lpf.conf";
  test_result = "failed";
  rollback_available = false;
}

let () =
  let json = Lpf.History.to_json [ entry1; entry2 ] in
  assert (String.length json > 0);
  assert (String.contains json '"');

  let text = Lpf.History.to_string [ entry1; entry2 ] in
  assert (String.length text > 0);

  let h = Lpf.History.add entry1 (Lpf.History.add entry2 []) in
  assert (List.length h = 2);
  assert ((List.hd h).Lpf.History.id = "abc123");

  let json2 = Lpf.History.to_json [ entry1 ] in
  assert (String.length json2 > 0);

  Printf.printf "history tests passed\n"
