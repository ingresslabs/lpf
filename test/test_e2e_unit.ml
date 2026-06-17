let require condition message = if not condition then failwith message

let read_file path =
  let channel = open_in path in
  Fun.protect
    ~finally:(fun () -> close_in channel)
    (fun () ->
       let length = in_channel_length channel in
       really_input_string channel length)

let line_count text =
  String.fold_left (fun count char -> if char = '\n' then count + 1 else count) 0 text

let () =
  let scenarios = Lpf.E2e.scenario_catalog 550 in
  require (List.length scenarios = 550) "expected 550 e2e scenarios";
  let family_count family =
    scenarios |> List.filter (fun scenario -> scenario.Lpf.E2e.family = family) |> List.length
  in
  require (family_count Lpf.E2e.Nft_accept = 50) "expected 50 nft accept scenarios";
  require (family_count Lpf.E2e.Nft_drop = 50) "expected 50 nft drop scenarios";
  require (family_count Lpf.E2e.Nft_log = 50) "expected 50 nft log scenarios";
  require (family_count Lpf.E2e.Ipv6_accept = 50) "expected 50 ipv6 accept scenarios";
  require (family_count Lpf.E2e.Ipv6_drop = 50) "expected 50 ipv6 drop scenarios";
  require (family_count Lpf.E2e.Routing = 50) "expected 50 routing scenarios";
  require (family_count Lpf.E2e.Traffic_shaping = 50) "expected 50 tc scenarios";
  require (family_count Lpf.E2e.Conntrack = 50) "expected 50 conntrack scenarios";
  require (family_count Lpf.E2e.Cleanup_idempotency = 50) "expected 50 cleanup scenarios";
  require (family_count Lpf.E2e.Readback_diff = 50) "expected 50 readback scenarios";
  require (family_count Lpf.E2e.Negative_invalid = 50) "expected 50 negative scenarios";
  let results =
    scenarios
    |> List.map (fun scenario ->
           {
             Lpf.E2e.scenario;
             status = Lpf.E2e.Passed;
             stdout = "";
             stderr = "";
             duration_ms = 1;
           })
  in
  let suite =
    {
      Lpf.E2e.kernel_id = "unit-kernel";
      kernel_release = "unit-release";
      scenario_count = 550;
      passed = 550;
      failed = 0;
      results;
    }
  in
  let junit = Lpf.E2e.to_junit suite in
  require (String.contains junit '<') "expected JUnit XML";
  let manifest = Lpf.E2e.evidence_manifest suite in
  require (String.contains manifest '{') "expected JSON evidence manifest";
  let larger_catalog = Lpf.E2e.scenario_catalog 990 in
  require (List.length larger_catalog = 990) "expected 990 e2e scenarios";
  let max_catalog = Lpf.E2e.scenario_catalog 1000 in
  require (List.length max_catalog = 1000) "expected 1000 e2e scenarios";
  let evidence_dir = Filename.temp_file "lpf-e2e-unit" "" in
  Sys.remove evidence_dir;
  let dry_suite =
    Lpf.E2e.run
      {
        scenario_count = 990;
        junit_path = Some (Filename.concat evidence_dir "nested/junit.xml");
        allure_dir = None;
        evidence_dir = Some evidence_dir;
        kernel_id = Some "unit-kernel";
        dry_run = true;
      }
  in
  require (dry_suite.scenario_count = 990) "expected dry-run suite to contain 990 scenarios";
  let scenario_log_path = Filename.concat evidence_dir "scenario-log.jsonl" in
  let summary_path = Filename.concat evidence_dir "summary.jsonl" in
  require (Sys.file_exists scenario_log_path) "expected scenario-log.jsonl evidence";
  require (Sys.file_exists summary_path) "expected summary.jsonl evidence";
  require (Sys.file_exists (Filename.concat evidence_dir "nested/junit.xml")) "expected nested JUnit output";
  require (line_count (read_file scenario_log_path) = 990) "expected one scenario-log line per scenario";
  require (line_count (read_file summary_path) = 990) "expected one summary line per scenario";
  Sys.remove (Filename.concat evidence_dir "nested/junit.xml");
  Unix.rmdir (Filename.concat evidence_dir "nested");
  Sys.remove scenario_log_path;
  Sys.remove summary_path;
  Sys.remove (Filename.concat evidence_dir "manifest.json");
  Unix.rmdir evidence_dir
