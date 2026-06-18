let () =
  let require condition message = if not condition then failwith message in

  (* Tc.qdisc_show_with_runner *)
  let qdisc_result =
    Lpf.Tc.qdisc_show_with_runner (fun _ -> Ok "qdisc show output") "eth0"
  in
  require (qdisc_result = Ok "qdisc show output") "tc qdisc show with runner";

  (* Tc.class_show_with_runner *)
  let class_result =
    Lpf.Tc.class_show_with_runner (fun _ -> Ok "class show output") "eth0"
  in
  require (class_result = Ok "class show output") "tc class show with runner";

  (* Tc.delete_with_runner *)
  let delete_result =
    Lpf.Tc.delete_with_runner (fun _ -> Ok "deleted") "eth0"
  in
  require (delete_result = Ok ()) "tc delete with runner";

  (* Ip.rule_list_with_runner *)
  let rules_result =
    Lpf.Ip.rule_list_with_runner (fun _ -> Ok "ip rule output")
  in
  require (rules_result = Ok "ip rule output") "ip rule list with runner";

  (* Ip.route_show_with_runner *)
  let routes_result =
    Lpf.Ip.route_show_with_runner (fun _ -> Ok "ip route output") 100
  in
  require (routes_result = Ok "ip route output") "ip route show with runner";

  (* Ip.delete_rules_with_runner *)
  let del_rules_result =
    Lpf.Ip.delete_rules_with_runner (fun _ -> Ok "deleted")
  in
  require (del_rules_result = Ok ()) "ip delete rules with runner";

  (* Apply_guard.rollback_now_with_runner *)
  let rollback_result =
    Lpf.Apply_guard.rollback_now_with_runner
      (fun _preimage -> Ok ())
      (fun _dev -> Ok ())
      (fun _table -> Ok ())
      ()
  in
  (match rollback_result with
  | Error _ -> () (* no preimage file during unit test *)
  | Ok _ -> require false "rollback should fail without preimage file");

  (* Result-based runner injection for apply guard *)
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
  | Ok ((), diagnostics) -> require (diagnostics = []) "apply with full runners"
  | Error _ -> require false "apply with full runners should succeed");

  Printf.printf "runner injection tests passed\n"
