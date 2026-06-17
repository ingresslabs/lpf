let read_file path =
  let channel = open_in path in
  Fun.protect
    ~finally:(fun () -> close_in channel)
    (fun () ->
      let length = in_channel_length channel in
      really_input_string channel length)

let fixture path = Filename.concat "../fixtures/policies" path

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
