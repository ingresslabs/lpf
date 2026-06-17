let require condition message = if not condition then failwith message

let () =
  let scenarios = Lpf.E2e.scenario_catalog 480 in
  require (List.length scenarios = 480) "expected 480 e2e scenarios";
  let family_count family =
    scenarios |> List.filter (fun scenario -> scenario.Lpf.E2e.family = family) |> List.length
  in
  require (family_count Lpf.E2e.Nft_accept = 80) "expected 80 nft accept scenarios";
  require (family_count Lpf.E2e.Nft_drop = 80) "expected 80 nft drop scenarios";
  require (family_count Lpf.E2e.Nft_log = 80) "expected 80 nft log scenarios";
  require (family_count Lpf.E2e.Routing = 80) "expected 80 routing scenarios";
  require (family_count Lpf.E2e.Traffic_shaping = 80) "expected 80 tc scenarios";
  require (family_count Lpf.E2e.Conntrack = 80) "expected 80 conntrack scenarios";
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
      scenario_count = 480;
      passed = 480;
      failed = 0;
      results;
    }
  in
  let junit = Lpf.E2e.to_junit suite in
  require (String.contains junit '<') "expected JUnit XML";
  let manifest = Lpf.E2e.evidence_manifest suite in
  require (String.contains manifest '{') "expected JSON evidence manifest"
