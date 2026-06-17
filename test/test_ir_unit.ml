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

let check text =
  match Lpf.Policy.check text with
  | { Lpf.Policy.policy = Some policy; diagnostics = _ } -> policy
  | result -> failwith (Lpf.Policy.format_check_result result)

let ir_of_text text =
  let policy = check text in
  match Lpf.Ir.of_policy policy with
  | Ok ir -> ir
  | Error diags -> failwith (String.concat "\n" (List.map Lpf.Policy.diagnostic_to_string diags))

let () =
  let ir = ir_of_text "set default deny\npass out proto tcp from any to any port 443" in
  assert (ir.default_action = Lpf.Policy.Default_deny);
  assert (List.length ir.tables = 0);
  assert (List.length ir.rules = 1);
  (match ir.rules with
   | [ rule ] ->
       assert (rule.action = Lpf.Policy.Pass);
       assert (rule.protocol = Lpf.Policy.Proto_named "tcp");
       assert (rule.port = Lpf.Ir.Range (443, 443));
       assert (rule.keep_state = false)
   | _ -> assert false);
  let ir = ir_of_text "set default pass\nblock in proto icmp from any to any" in
  assert (ir.default_action = Lpf.Policy.Default_pass);
  assert (List.length ir.rules = 1);
  (match ir.rules with
   | [ rule ] ->
       assert (rule.action = Lpf.Policy.Block);
       assert (rule.direction = Some Lpf.Policy.In);
       assert (rule.protocol = Lpf.Policy.Proto_named "icmp")
   | _ -> assert false);
  let ir = ir_of_text "set default deny\ntable <t> { 10.0.0.0/8 }\npass out from <t> to any" in
  assert (List.length ir.tables = 1);
  (match ir.rules with
   | [ rule ] ->
       assert (rule.source = Lpf.Ir.Table "t");
       assert (rule.destination = Lpf.Ir.Any)
   | _ -> assert false);
  let ir = ir_of_text "set default deny\ninterface wan = \"eth0\"\npass in on wan from any to any" in
  assert (List.length ir.interfaces = 1);
  (match ir.rules with
   | [ rule ] ->
       (match rule.interface with
        | Some iface ->
            assert (String.equal iface.device "eth0")
        | None -> assert false)
   | _ -> assert false);
  let ir = ir_of_text "set default deny\npass in proto tcp from any to any port 22 keep state" in
  (match ir.rules with
   | [ rule ] -> assert rule.keep_state
   | _ -> assert false);
  let ir = ir_of_text "set default deny\nreject in proto tcp from any to any port 22" in
  (match ir.rules with
   | [ rule ] -> assert (rule.action = Lpf.Policy.Reject)
   | _ -> assert false);
  let ir = ir_of_text "set default deny\npass out log (all) proto tcp from any to any port 443" in
  (match ir.rules with
   | [ rule ] -> assert (rule.log = Some Lpf.Policy.Log_all)
   | _ -> assert false);
  let ir = ir_of_text "set default deny\ninterface wan = \"eth0\"\nqueue std on wan bandwidth 10M\npass in on wan from any to any queue std" in
  assert (List.length ir.queues = 1);
  (match ir.queues with
   | [ q ] -> assert (String.equal q.name "std")
   | _ -> assert false);
  (match ir.rules with
   | [ rule ] ->
       (match rule.interface with
        | Some iface -> assert (String.equal iface.device "eth0")
        | None -> assert false);
       assert (rule.queue = Some "std")
   | _ -> assert false);

  let ir = ir_of_text "set default deny\npass out proto tcp from any to any port 443\nblock in from any to any" in
  let shadows = Lpf.Ir.shadow_diagnostics ir in
  assert (shadows = []);
  assert (List.length ir.rules = 2);

  let ir = ir_of_text "set default deny\nblock in from any to any\npass in proto tcp from any to any port 22" in
  let shadows = Lpf.Ir.shadow_diagnostics ir in
  assert (List.length shadows = 1);
  (match shadows with
   | [ diag ] ->
       assert (diag.severity = Lpf.Policy.Diag_warning);
       assert (contains_substring diag.message "shadowed")
   | _ -> assert false)
