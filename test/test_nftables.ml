let read_file path =
  let channel = open_in path in
  Fun.protect
    ~finally:(fun () -> close_in channel)
    (fun () ->
      let length = in_channel_length channel in
      really_input_string channel length)

let fixture path = Filename.concat "../fixtures/policies" path
let nft_fixture path = Filename.concat "../fixtures/nftables" path
let nft_observed_fixture path = Filename.concat "../fixtures/nftables-observed" path
let nft_diff_fixture path = Filename.concat "../fixtures/nftables-diff" path

let assert_nftables_golden policy_name expected_name =
  let path = fixture policy_name in
  match Lpf.render_nftables_policy_text ~file:path (read_file path) with
  | Ok (rendered, diagnostics) ->
      assert (diagnostics = []);
      let expected = read_file (nft_fixture expected_name) in
      if not (String.equal rendered expected) then
        failwith ("nftables output mismatch for " ^ policy_name)
  | Error diagnostics ->
      failwith (String.concat "\n" (List.map Lpf.Policy.diagnostic_to_string diagnostics))

let assert_nftables_golden_fixtures () =
  assert_nftables_golden "basic.lpf" "basic.nft";
  assert_nftables_golden "nat-rdr.lpf" "nat-rdr.nft";
  assert_nftables_golden "queue-route.lpf" "queue-route.nft";
  assert_nftables_golden "logging.lpf" "logging.nft";
  assert_nftables_golden "anchor-log.lpf" "anchor-log.nft"

let assert_nftables_diff policy_name observed_path expected_name =
  let path = fixture policy_name in
  let observed = read_file observed_path in
  match Lpf.diff_nftables_policy_text ~file:path ~observed (read_file path) with
  | Ok (diff, diagnostics) ->
      assert (diagnostics = []);
      let expected = read_file (nft_diff_fixture expected_name) in
      if not (String.equal diff expected) then
        failwith ("nftables diff mismatch for " ^ policy_name ^ " / " ^ expected_name)
  | Error diagnostics ->
      failwith (String.concat "\n" (List.map Lpf.Policy.diagnostic_to_string diagnostics))

let assert_nftables_diff_fixtures () =
  assert_nftables_diff "basic.lpf" (nft_fixture "basic.nft") "unchanged.diff";
  assert_nftables_diff "basic.lpf" (nft_observed_fixture "missing-owned.nft")
    "missing-owned.diff";
  assert_nftables_diff "basic.lpf" (nft_observed_fixture "extra-rule.nft")
    "extra-rule.diff";
  assert_nftables_diff "basic.lpf" (nft_observed_fixture "changed-rule.nft")
    "changed-rule.diff"

let assert_nftables_structured_diff_fixtures () =
  let path = fixture "basic.lpf" in
  let policy = read_file path in
  (match Lpf.diff_nftables_policy ~file:path ~observed:(read_file (nft_fixture "basic.nft")) policy with
   | Ok (diff, diagnostics) ->
       assert (diagnostics = []);
       assert (not diff.Lpf.Nftables.changes_required);
       assert (String.equal diff.text (read_file (nft_diff_fixture "unchanged.diff")))
   | Error diagnostics ->
       failwith (String.concat "\n" (List.map Lpf.Policy.diagnostic_to_string diagnostics)));
  match
    Lpf.diff_nftables_policy ~file:path
      ~observed:(read_file (nft_observed_fixture "changed-rule.nft"))
      policy
  with
  | Ok (diff, diagnostics) ->
      assert (diagnostics = []);
      assert diff.Lpf.Nftables.changes_required;
      assert (String.equal diff.text (read_file (nft_diff_fixture "changed-rule.diff")))
  | Error diagnostics ->
      failwith (String.concat "\n" (List.map Lpf.Policy.diagnostic_to_string diagnostics))

let assert_live_nftables_readback () =
  let seen = ref None in
  let observed = read_file (nft_fixture "basic.nft") in
  let runner invocation =
    seen := Some invocation;
    Ok observed
  in
  let live_observed =
    match Lpf.Nft.list_ruleset_with_runner runner with
    | Ok ruleset -> ruleset
    | Error error -> failwith (Lpf.Nft.string_of_run_error error)
  in
  (match !seen with
   | Some { Lpf.Nft.program; argv } ->
       assert (String.equal program "nft");
       assert (argv = [ "nft"; "list"; "ruleset" ])
   | None -> failwith "nft runner was not called");
  let path = fixture "basic.lpf" in
  match Lpf.diff_nftables_policy_text ~file:path ~observed:live_observed (read_file path) with
  | Ok (diff, diagnostics) ->
      assert (diagnostics = []);
      assert (String.equal diff (read_file (nft_diff_fixture "unchanged.diff")))
  | Error diagnostics ->
      failwith (String.concat "\n" (List.map Lpf.Policy.diagnostic_to_string diagnostics))

let () =
  assert_nftables_golden_fixtures ();
  assert_nftables_diff_fixtures ();
  assert_nftables_structured_diff_fixtures ();
  assert_live_nftables_readback ()
