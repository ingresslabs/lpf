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

let contains_substring text needle =
  let text_length = String.length text in
  let needle_length = String.length needle in
  if needle_length = 0 then true
  else
    let rec loop index =
      index + needle_length <= text_length
      && (String.equal (String.sub text index needle_length) needle || loop (index + 1))
    in
    loop 0

let assert_check_ok path =
  let path = fixture path in
  match Lpf.check_policy_text ~file:path (read_file path) with
  | { Lpf.Policy.policy = Some _; diagnostics = _ } -> ()
  | result -> failwith (Lpf.Policy.format_check_result result)

let assert_check_fails ~contains path =
  let path = fixture path in
  match Lpf.check_policy_text ~file:path (read_file path) with
  | { Lpf.Policy.policy = None; diagnostics } ->
      let text = String.concat "\n" (List.map Lpf.Policy.diagnostic_to_string diagnostics) in
      assert (String.contains text contains)
  | { policy = Some _; diagnostics = _ } -> failwith (path ^ " unexpectedly passed")

let assert_check_has_diagnostic ~line ~column ~message path =
  let path = fixture path in
  match Lpf.check_policy_text ~file:path (read_file path) with
  | { Lpf.Policy.policy = None; diagnostics } ->
      assert (
        List.exists
          (fun (diagnostic : Lpf.Policy.diagnostic) ->
            diagnostic.span.line = line && diagnostic.span.column = column
            && String.equal diagnostic.message message)
          diagnostics)
  | { policy = Some _; diagnostics = _ } -> failwith (path ^ " unexpectedly passed")

let assert_check_has_warning ~line ~column ~message path =
  let path = fixture path in
  match Lpf.check_policy_text ~file:path (read_file path) with
  | { Lpf.Policy.policy = Some _; diagnostics } ->
      if
        not
          (List.exists
             (fun (diagnostic : Lpf.Policy.diagnostic) ->
               diagnostic.severity = Diag_warning && diagnostic.span.line = line
               && diagnostic.span.column = column && String.equal diagnostic.message message)
             diagnostics)
      then
        failwith
          ("expected warning not found in " ^ path ^ ":\n"
          ^ String.concat "\n" (List.map Lpf.Policy.diagnostic_to_string diagnostics))
  | { policy = None; diagnostics = _ } -> failwith (path ^ " unexpectedly failed")

let ir_of_fixture path =
  let path = fixture path in
  match Lpf.check_policy_text ~file:path (read_file path) with
  | { Lpf.Policy.policy = Some policy; diagnostics } ->
      let errors =
        diagnostics
        |> List.filter (fun (diagnostic : Lpf.Policy.diagnostic) ->
               diagnostic.severity = Diag_error)
      in
      if errors <> [] then
        failwith (String.concat "\n" (List.map Lpf.Policy.diagnostic_to_string errors));
      (match Lpf.ir_of_policy policy with
       | Ok ir -> ir
       | Error diagnostics ->
           failwith
             (String.concat "\n" (List.map Lpf.Policy.diagnostic_to_string diagnostics)))
  | result -> failwith (Lpf.Policy.format_check_result result)

let assert_interface (interface : Lpf.Ir.interface_ref) ~name ~device =
  assert (interface.name = name);
  assert (String.equal interface.device device)

let assert_phase1_fixture_ir () =
  let basic = ir_of_fixture "basic.lpf" in
  assert (basic.default_action = Lpf.Policy.Default_deny);
  assert (List.length basic.tables = 1);
  assert (List.length basic.rules = 2);
  let queue_route = ir_of_fixture "queue-route.lpf" in
  assert (List.length queue_route.interfaces = 2);
  assert (List.length queue_route.queues = 2);
  assert (List.length queue_route.nats = 1);
  assert (List.length queue_route.rdrs = 1);
  (match queue_route.queues with
   | std :: voip :: [] ->
       assert (String.equal std.name "std");
       assert_interface std.interface ~name:(Some "wan") ~device:"eth0";
       assert (String.equal voip.name "voip");
       assert (voip.parent = Some "std")
   | _ -> assert false);
  (match queue_route.rules with
   | _in_rule :: out_rule :: [] ->
       assert out_rule.keep_state;
       (match out_rule.route_to with
        | Some (Literal "1.1.1.1", Some interface) ->
            assert_interface interface ~name:(Some "wan") ~device:"eth0"
        | _ -> assert false)
   | _ -> assert false);
  let anchor_log = ir_of_fixture "anchor-log.lpf" in
  (match anchor_log.anchors with
   | anchor :: [] ->
       assert (String.equal anchor.name "internal");
       assert (List.length anchor.rules = 1)
   | _ -> assert false);
  let messy_full = ir_of_fixture "messy-full.lpf" in
  (match List.rev messy_full.rules with
   | block_rule :: pass_rule :: [] ->
       assert (block_rule.action = Block);
       assert (block_rule.log = Some Log_matches);
       assert (pass_rule.log = Some Log_all);
       assert (pass_rule.port = Lpf.Ir.Range (443, 443))
   | _ -> assert false)

let plan_of_fixture path =
  let path = fixture path in
  match Lpf.plan_policy_text ~file:path (read_file path) with
  | Ok (plan, diagnostics) ->
      let errors =
        diagnostics
        |> List.filter (fun (diagnostic : Lpf.Policy.diagnostic) ->
               diagnostic.severity = Diag_error)
      in
      if errors <> [] then
        failwith (String.concat "\n" (List.map Lpf.Policy.diagnostic_to_string errors));
      (plan, diagnostics)
  | Error diagnostics ->
      failwith (String.concat "\n" (List.map Lpf.Policy.diagnostic_to_string diagnostics))

let assert_contains text needle =
  if not (contains_substring text needle) then
    failwith ("expected substring not found: " ^ needle ^ "\n" ^ text)

let checksum_of_text ~file text =
  match Lpf.plan_policy_text ~file text with
  | Ok (plan, diagnostics) ->
      let errors =
        diagnostics
        |> List.filter (fun (diagnostic : Lpf.Policy.diagnostic) ->
               diagnostic.severity = Diag_error)
      in
      if errors <> [] then
        failwith (String.concat "\n" (List.map Lpf.Policy.diagnostic_to_string errors));
      Lpf.Plan.checksum plan
  | Error diagnostics ->
      failwith (String.concat "\n" (List.map Lpf.Policy.diagnostic_to_string diagnostics))

let assert_plan_json () =
  let plan, diagnostics = plan_of_fixture "queue-route.lpf" in
  assert (diagnostics = []);
  let json = Lpf.Plan.to_json plan in
  assert_contains json "\"schema\":\"lpf.plan.v1\"";
  assert_contains json "\"kind\":\"semantic-policy\"";
  assert_contains json "\"checksum\":\"md5:";
  assert_contains json "\"interfaces\":[";
  assert_contains json "\"queues\":[";
  assert_contains json "\"route_to\":";
  let plan_again, _ = plan_of_fixture "queue-route.lpf" in
  assert (String.equal (Lpf.Plan.checksum plan) (Lpf.Plan.checksum plan_again));
  assert (String.equal json (Lpf.Plan.to_json plan_again));
  let warning_plan, warning_diagnostics = plan_of_fixture "warning-shadowed-rule.lpf" in
  assert (String.length (Lpf.Plan.checksum warning_plan) > 4);
  assert (
    List.exists
      (fun (diagnostic : Lpf.Policy.diagnostic) ->
        diagnostic.severity = Diag_warning
        && String.equal diagnostic.message "rule is completely shadowed by rule at line 3")
      warning_diagnostics);
  let messy_path = fixture "messy-full.lpf" in
  let messy = read_file messy_path in
  let formatted =
    match Lpf.format_policy_text ~file:messy_path messy with
    | Ok formatted -> formatted
    | Error diagnostics ->
        failwith (String.concat "\n" (List.map Lpf.Policy.diagnostic_to_string diagnostics))
  in
  assert (
    String.equal
      (checksum_of_text ~file:messy_path messy)
      (checksum_of_text ~file:"messy-full-formatted.lpf" formatted))

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

let assert_live_nftables_readback_wrapper () =
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

let assert_inline_check_has_diagnostic ~file ~text ~line ~column ~message =
  match Lpf.check_policy_text ~file text with
  | { Lpf.Policy.policy = None; diagnostics } ->
      assert (
        List.exists
          (fun (diagnostic : Lpf.Policy.diagnostic) ->
            diagnostic.span.line = line && diagnostic.span.column = column
            && String.equal diagnostic.message message)
          diagnostics)
  | { policy = Some _; diagnostics = _ } -> failwith (file ^ " unexpectedly passed")

let assert_formats_to ~expected path =
  let path = fixture path in
  match Lpf.format_policy_text ~file:path (read_file path) with
  | Ok formatted ->
      assert (String.equal formatted expected);
      (match Lpf.format_policy_text ~file:path formatted with
       | Ok round_tripped -> assert (String.equal round_tripped expected)
       | Error diagnostics ->
           failwith
             (String.concat "\n" (List.map Lpf.Policy.diagnostic_to_string diagnostics)))
  | Error diagnostics ->
      failwith (String.concat "\n" (List.map Lpf.Policy.diagnostic_to_string diagnostics))

let () =
  assert (String.equal Lpf.version "0.1.0-dev");
  assert (Lpf.command_of_string "check" = Some Lpf.Check);
  assert (Lpf.command_of_string "ui" = Some Lpf.Ui);
  assert (Lpf.command_of_string "man" = Some Lpf.Man);
  assert (Lpf.command_of_string "support-bundle" = Some Lpf.Support_bundle);
  assert (Lpf.command_of_string "does-not-exist" = None);
  assert (String.contains (Lpf.help ()) 'c');
  assert (List.length (Lpf.man_pages ()) >= 20);
  assert (
    List.exists
      (fun page -> String.equal page.Lpf.filename "lpf-ui.8")
      (Lpf.man_pages ()));
  Lpf.man_pages ()
  |> List.iter (fun page ->
         let path = Filename.concat "../man/generated" page.Lpf.filename in
         assert (Sys.file_exists path);
         assert (String.equal (read_file path) (Lpf.man_page_content page)));
  assert_check_ok "basic.lpf";
  assert_check_ok "nat-rdr.lpf";
  assert_check_ok "queue-route.lpf";
  assert_check_ok "logging.lpf";
  assert_check_ok "anchor-log.lpf";
  assert_check_fails ~contains:'m' "invalid-unknown-table.lpf";
  assert_check_fails ~contains:'e' "invalid-syntax.lpf";
  assert_check_fails ~contains:'d' "invalid-queue-duplicate-fields.lpf";
  assert_check_fails ~contains:'q' "invalid-queue-name.lpf";
  assert_check_fails ~contains:'q' "invalid-queue-references.lpf";
  assert_check_fails ~contains:'r' "invalid-route-to-syntax.lpf";
  assert_check_has_warning ~line:5 ~column:1
    ~message:"rule is completely shadowed by rule at line 3"
    "warning-shadowed-rule.lpf";
  assert_check_fails ~contains:'l' "invalid-log-duplicate.lpf";
  assert_check_fails ~contains:'l' "invalid-log-option.lpf";
  assert_check_fails ~contains:'l' "invalid-log-syntax.lpf";
  assert_check_fails ~contains:'a' "invalid-anchor-duplicate.lpf";
  assert_check_fails ~contains:'a' "invalid-anchor-name.lpf";
  assert_check_fails ~contains:'a' "invalid-anchor-statement.lpf";
  assert_check_fails ~contains:'a' "invalid-anchor-unknown-reference.lpf";
  assert_check_fails ~contains:'a' "invalid-anchor-unclosed.lpf";
  assert_check_fails ~contains:'i' "invalid-interface-device.lpf";
  assert_check_fails ~contains:'u' "invalid-quoted-string.lpf";
  assert_check_fails ~contains:'t' "invalid-table-trailing-comma.lpf";
  assert_check_fails ~contains:'n' "invalid-nat-extra-token.lpf";
  assert_check_fails ~contains:'r' "invalid-rdr-port.lpf";
  assert_check_has_diagnostic ~line:5 ~column:14
    ~message:"rule source references unknown table `<missing>`"
    "invalid-unknown-table.lpf";
  assert_check_has_diagnostic ~line:5 ~column:32
    ~message:"invalid queue: duplicate bandwidth"
    "invalid-queue-duplicate-fields.lpf";
  assert_check_has_diagnostic ~line:6 ~column:44
    ~message:"invalid queue: duplicate parent"
    "invalid-queue-duplicate-fields.lpf";
  assert_check_has_diagnostic ~line:5 ~column:7
    ~message:"invalid queue name `bad/name`"
    "invalid-queue-name.lpf";
  assert_check_has_diagnostic ~line:5 ~column:40
    ~message:"queue references unknown parent `missing`"
    "invalid-queue-references.lpf";
  assert_check_has_diagnostic ~line:6 ~column:39
    ~message:"rule references unknown queue `missing-queue`"
    "invalid-queue-references.lpf";
  assert_check_has_diagnostic ~line:5 ~column:55
    ~message:"invalid rule: expected closing `)` after route-to interface"
    "invalid-route-to-syntax.lpf";
  assert_check_has_diagnostic ~line:3 ~column:14
    ~message:"invalid rule: duplicate log assignment"
    "invalid-log-duplicate.lpf";
  assert_check_has_diagnostic ~line:3 ~column:11
    ~message:"invalid rule: invalid log option `packet`"
    "invalid-log-option.lpf";
  assert_check_has_diagnostic ~line:3 ~column:15
    ~message:"invalid rule: expected closing `)` after log option"
    "invalid-log-syntax.lpf";
  assert_check_has_diagnostic ~line:7 ~column:8
    ~message:"duplicate anchor `office`"
    "invalid-anchor-duplicate.lpf";
  assert_check_has_diagnostic ~line:3 ~column:8
    ~message:"invalid anchor name `bad/name`"
    "invalid-anchor-name.lpf";
  assert_check_has_diagnostic ~line:4 ~column:3
    ~message:"anchors currently support pass/block rules only"
    "invalid-anchor-statement.lpf";
  assert_check_has_diagnostic ~line:4 ~column:14
    ~message:"rule references unknown interface `missing`"
    "invalid-anchor-unknown-reference.lpf";
  assert_check_has_diagnostic ~line:4 ~column:44
    ~message:"rule references unknown queue `missing-queue`"
    "invalid-anchor-unknown-reference.lpf";
  assert_check_has_diagnostic ~line:3 ~column:1
    ~message:"expected closing `}`"
    "invalid-anchor-unclosed.lpf";
  assert_check_has_diagnostic ~line:3 ~column:17
    ~message:"interface device must be quoted"
    "invalid-interface-device.lpf";
  assert_check_has_diagnostic ~line:3 ~column:17
    ~message:"unterminated quoted string"
    "invalid-quoted-string.lpf";
  assert_check_has_diagnostic ~line:3 ~column:29
    ~message:"empty table entry"
    "invalid-table-trailing-comma.lpf";
  assert_check_has_diagnostic ~line:5 ~column:35
    ~message:"invalid nat: unexpected token after translation"
    "invalid-nat-extra-token.lpf";
  assert_check_has_diagnostic ~line:5 ~column:43
    ~message:"invalid rdr: invalid port `70000`"
    "invalid-rdr-port.lpf";
  assert_inline_check_has_diagnostic ~file:"inline-invalid-port.lpf"
    ~text:"set default deny\npass out proto tcp from any to any port 70000\n"
    ~line:2 ~column:41 ~message:"invalid rule: invalid port `70000`";
  assert_phase1_fixture_ir ();
  assert_plan_json ();
  assert_nftables_golden_fixtures ();
  assert_nftables_diff_fixtures ();
  assert_nftables_structured_diff_fixtures ();
  assert_live_nftables_readback_wrapper ();
  let basic = read_file (fixture "basic.lpf") in
  (match Lpf.format_policy_text ~file:(fixture "basic.lpf") basic with
   | Ok formatted -> assert (String.equal formatted basic)
   | Error diagnostics ->
       failwith
         (String.concat "\n" (List.map Lpf.Policy.diagnostic_to_string diagnostics)));
  let nat_rdr = read_file (fixture "nat-rdr.lpf") in
  (match Lpf.format_policy_text ~file:(fixture "nat-rdr.lpf") nat_rdr with
   | Ok formatted -> assert (String.equal formatted nat_rdr)
   | Error diagnostics ->
       failwith
         (String.concat "\n" (List.map Lpf.Policy.diagnostic_to_string diagnostics)));
  let queue_route = read_file (fixture "queue-route.lpf") in
  (match Lpf.format_policy_text ~file:(fixture "queue-route.lpf") queue_route with
   | Ok formatted -> assert (String.equal formatted queue_route)
   | Error diagnostics ->
       failwith
         (String.concat "\n" (List.map Lpf.Policy.diagnostic_to_string diagnostics)));
  let logging = read_file (fixture "logging.lpf") in
  (match Lpf.format_policy_text ~file:(fixture "logging.lpf") logging with
   | Ok formatted -> assert (String.equal formatted logging)
   | Error diagnostics ->
       failwith
         (String.concat "\n" (List.map Lpf.Policy.diagnostic_to_string diagnostics)));
  let anchor_log = read_file (fixture "anchor-log.lpf") in
  (match Lpf.format_policy_text ~file:(fixture "anchor-log.lpf") anchor_log with
   | Ok formatted -> assert (String.equal formatted anchor_log)
   | Error diagnostics ->
       failwith
         (String.concat "\n" (List.map Lpf.Policy.diagnostic_to_string diagnostics)));
  assert_formats_to
    ~expected:
      "set default deny\n\n\
       table <trusted> { 10.0.0.0/8, 192.168.0.0/16 }\n\n\
       pass out proto tcp from any to any port 443 keep state\n"
    "messy.lpf";
  assert_formats_to
    ~expected:
      "set default deny\n\n\
       wan_port = 443\n\n\
       interface lan = \"eth1\"\n\
       interface wan = \"eth0\"\n\n\
       table <trusted> { 192.168.0.0/16, 10.0.0.0/8 }\n\n\
       queue slow on wan bandwidth 1M\n\
       queue std on wan bandwidth 10M\n\n\
       nat on wan from 10.0.0.0/24 to any -> wan\n\
       rdr on wan proto tcp from any to any port 80 -> 10.0.0.5 port 8080\n\n\
       anchor internal {\n\
       \  pass in on lan from <trusted> to any queue std\n\
       }\n\n\
       pass out log (all) on wan proto tcp from any to any port $wan_port route-to 1.1.1.1 (wan) keep state\n\
       block in log from any to any\n"
    "messy-full.lpf"
