let span = { Lpf.Policy.file = None; line = 1; column = 1; end_column = 1 }

let empty_ir =
  {
    Lpf.Ir.default_action = Lpf.Policy.Default_deny;
    interfaces = [];
    tables = [];
    queues = [];
    nats = [];
    rdrs = [];
    anchors = [];
    rules = [];
  }

let iface = { Lpf.Ir.name = Some "wan"; device = "eth0"; span }

let () =
  let result = Lpf.Routing.compile empty_ir in
  assert (result = []);

  let ir =
    {
      empty_ir with
      rules =
        [
          {
            Lpf.Ir.action = Lpf.Policy.Pass;
            direction = Some Lpf.Policy.Out;
            interface = None;
            protocol = Lpf.Policy.Proto_any;
            source = Lpf.Ir.Any;
            destination = Lpf.Ir.Any;
            port = Lpf.Ir.Port_any;
            keep_state = false;
            log = None;
            queue = None;
            route_to = Some (Lpf.Ir.Literal "1.1.1.1", Some iface);
            span;
          };
        ];
    }
  in
  let result = Lpf.Routing.compile ir in
  assert (List.length result = 2);
  let rendered = Lpf.Routing.to_string result in
  assert (String.length rendered > 0);
  assert (String.contains rendered 'i');
  let batch = Lpf.Routing.to_batch_string result in
  assert (String.length batch > 0);
  assert (not (String.starts_with ~prefix:"ip " batch));
  assert (String.starts_with ~prefix:"rule del" batch);
  assert (String.contains batch '\n');

  let mark =
    Lpf.Routing.mark_for_target ir (Lpf.Ir.Literal "1.1.1.1", Some iface)
  in
  assert (mark = Some 100);

  let mark = Lpf.Routing.mark_for_target ir (Lpf.Ir.Literal "2.2.2.2", None) in
  assert (mark = None);

  let observed_rules =
    Lpf.Ip.parse_rule_list
      "0:\tfrom all lookup local\n\
       100:\tfrom all fwmark 0x64/0xffffffff lookup 100\n"
  in
  assert (List.length observed_rules = 1);
  assert (
    List.exists
      (fun (rule : Lpf.Ip.observed_rule) ->
        rule.priority = 100 && rule.fwmark = Some 100 && rule.table = 100)
      observed_rules);

  let observed_routes =
    Lpf.Ip.parse_route_show "default via 1.1.1.1 dev eth0 proto static\n"
  in
  assert (
    List.exists
      (fun (route : Lpf.Ip.observed_route) ->
        String.equal route.gateway "1.1.1.1" && route.device = Some "eth0")
      observed_routes);

  Printf.printf "routing tests passed\n"
