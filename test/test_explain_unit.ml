let check text =
  match Lpf.Policy.check text with
  | { Lpf.Policy.policy = Some policy; diagnostics = _ } -> policy
  | result -> failwith (Lpf.Policy.format_check_result result)

let ir_of_text text =
  let policy = check text in
  match Lpf.Ir.of_policy policy with
  | Ok ir -> ir
  | Error diags ->
      failwith
        (String.concat "\n" (List.map Lpf.Policy.diagnostic_to_string diags))

let packet =
  {
    Lpf.Explain.direction = Lpf.Policy.In;
    interface = "eth0";
    protocol = Lpf.Policy.Proto_any;
    source = "0.0.0.0";
    destination = "0.0.0.0";
    port = None;
  }

let () =
  let ir_out_pass =
    ir_of_text "set default deny\npass out proto tcp from any to any port 443"
  in

  let tcp_http_out =
    {
      packet with
      direction = Lpf.Policy.Out;
      protocol = Lpf.Policy.Proto_named "tcp";
      port = Some 443;
    }
  in
  let result = Lpf.Explain.explain ir_out_pass tcp_http_out in
  assert (result.decision = Lpf.Policy.Pass);
  assert (result.matching_rule <> None);

  let tcp_http_in =
    { packet with protocol = Lpf.Policy.Proto_named "tcp"; port = Some 443 }
  in
  let result = Lpf.Explain.explain ir_out_pass tcp_http_in in
  assert (result.decision = Lpf.Policy.Block);

  let tcp_ssh_in =
    { packet with protocol = Lpf.Policy.Proto_named "tcp"; port = Some 22 }
  in
  let result = Lpf.Explain.explain ir_out_pass tcp_ssh_in in
  assert (result.decision = Lpf.Policy.Block);

  let ir_pass_block_icmp =
    ir_of_text "set default pass\nblock in proto icmp from any to any"
  in
  let icmp_in = { packet with protocol = Lpf.Policy.Proto_named "icmp" } in
  let result = Lpf.Explain.explain ir_pass_block_icmp icmp_in in
  assert (result.decision = Lpf.Policy.Block);

  let udp_in =
    { packet with protocol = Lpf.Policy.Proto_named "udp"; port = Some 53 }
  in
  let result = Lpf.Explain.explain ir_pass_block_icmp udp_in in
  assert (result.decision = Lpf.Policy.Pass);

  let ir_pass_ssh =
    ir_of_text
      "set default deny\npass in proto tcp from any to any port 22 keep state"
  in
  let tcp_ssh_in =
    { packet with protocol = Lpf.Policy.Proto_named "tcp"; port = Some 22 }
  in
  let result = Lpf.Explain.explain ir_pass_ssh tcp_ssh_in in
  assert (result.decision = Lpf.Policy.Pass);

  let explanation_text = Lpf.Explain.to_string result in
  assert (String.contains explanation_text 'p');

  let ir_log =
    ir_of_text
      "set default deny\npass out log (all) proto tcp from any to any port 443"
  in
  let tcp_http_out =
    {
      packet with
      direction = Lpf.Policy.Out;
      protocol = Lpf.Policy.Proto_named "tcp";
      port = Some 443;
    }
  in
  let result = Lpf.Explain.explain ir_log tcp_http_out in
  assert (result.log = Some Lpf.Policy.Log_all);

  let ir_route =
    ir_of_text
      "set default deny\n\
       interface wan = \"eth0\"\n\
       pass out proto tcp from any to any port 443 route-to 1.1.1.1 (wan)"
  in
  let tcp_http_out =
    {
      packet with
      direction = Lpf.Policy.Out;
      protocol = Lpf.Policy.Proto_named "tcp";
      port = Some 443;
    }
  in
  let result = Lpf.Explain.explain ir_route tcp_http_out in
  assert (result.decision = Lpf.Policy.Pass);
  assert (result.route_to <> None);

  let json = Lpf.Explain.to_json result in
  assert (String.contains json 'p')
