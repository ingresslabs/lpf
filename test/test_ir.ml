let read_file path =
  let channel = open_in path in
  Fun.protect
    ~finally:(fun () -> close_in channel)
    (fun () ->
      let length = in_channel_length channel in
      really_input_string channel length)

let fixture path = Filename.concat "../fixtures/policies" path

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

let () =
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
