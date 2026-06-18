let contains_substring text needle =
  let text_length = String.length text in
  let needle_length = String.length needle in
  if needle_length = 0 then true
  else
    let rec loop index =
      index + needle_length <= text_length
      && (String.equal (String.sub text index needle_length) needle
         || loop (index + 1))
    in
    loop 0

let check text = Lpf.Policy.check text

let assert_ok text =
  match check text with
  | { Lpf.Policy.policy = Some _; diagnostics = _ } -> ()
  | result -> failwith (Lpf.Policy.format_check_result result)

let assert_fails ~contains text =
  match check text with
  | { Lpf.Policy.policy = None; diagnostics } ->
      let output =
        String.concat "\n"
          (List.map Lpf.Policy.diagnostic_to_string diagnostics)
      in
      assert (contains_substring output contains)
  | { policy = Some _; _ } -> failwith "unexpectedly passed"

let assert_format_round_trip text =
  match check text with
  | { Lpf.Policy.policy = Some policy; diagnostics = _ } -> (
      let formatted = Lpf.Policy.format policy in
      match Lpf.format_policy_text formatted with
      | Ok round_tripped -> assert (String.equal round_tripped formatted)
      | Error diags ->
          failwith
            (String.concat "\n"
               (List.map Lpf.Policy.diagnostic_to_string diags)))
  | { policy = None; diagnostics } ->
      failwith
        (String.concat "\n"
           (List.map Lpf.Policy.diagnostic_to_string diagnostics))

let assert_parse text =
  match Lpf.Policy.parse text with
  | { Lpf.Policy.policy = Some policy; diagnostics = _ } -> policy
  | result -> failwith (Lpf.Policy.format_check_result result)

let () =
  assert_ok "set default deny\npass out proto tcp from any to any port 443";
  assert_ok "set default pass\nblock in proto udp from any to any port 53";
  assert_ok
    "set default deny\ninterface wan = \"eth0\"\npass in on wan from any to any";
  assert_ok
    "set default deny\n\
     table <trusted> { 10.0.0.0/8 }\n\
     pass in from <trusted> to any";
  assert_fails ~contains:"e"
    "set default deny\npass out proto tcp from any to any port 70000";
  assert_ok "set default deny";
  assert_ok
    "set default deny\n\
     block in from any to any\n\
     pass in proto tcp from any to any port 22";
  assert_ok
    "set default deny\n\
     interface wan = \"eth0\"\n\
     queue std on wan bandwidth 10M\n\
     pass in on wan from any to any queue std";
  assert_fails ~contains:"q"
    "set default deny\n\
     interface wan = \"eth0\"\n\
     pass in on wan from any to any queue missing";
  assert_ok
    "set default deny\n\
     interface wan = \"eth0\"\n\
     nat on wan from 10.0.0.0/24 to any -> wan\n\
     pass out from any to any";
  assert_ok
    "set default deny\n\
     interface wan = \"eth0\"\n\
     rdr on wan proto tcp from any to any port 80 -> 10.0.0.5 port 8080\n\
     pass in from any to any";
  assert_fails ~contains:"r"
    "set default deny\n\
     interface wan = \"eth0\"\n\
     rdr on wan proto tcp from any to any port 99999 -> 10.0.0.5 port 80";
  assert_ok
    "set default deny\n\
     interface wan = \"eth0\"\n\
     anchor trusted {\n\
    \  pass in from any to any\n\
     }\n\
     pass out from any to any";
  assert_fails ~contains:"a"
    "set default deny\n\
     interface wan = \"eth0\"\n\
     anchor trusted {\n\
    \  nat on wan from 10.0.0.0/24 to any -> wan\n\
     }\n";
  assert_ok
    "set default deny\n\
     interface wan = \"eth0\"\n\
     pass out log on wan proto tcp from any to any port 443";
  assert_ok
    "set default deny\n\
     interface wan = \"eth0\"\n\
     pass out log (all) on wan proto tcp from any to any port 443";
  assert_ok
    "set default deny\n\
     interface wan = \"eth0\"\n\
     pass out log (matches) on wan proto tcp from any to any port 443";
  assert_ok
    "set default deny\n\
     interface wan = \"eth0\"\n\
     pass out log (user) on wan proto tcp from any to any port 443";
  assert_fails ~contains:"l"
    "set default deny\n\
     interface wan = \"eth0\"\n\
     pass out log (invalid) from any to any";
  assert_ok
    "set default deny\npass in proto tcp from any to any port 22 keep state";
  assert_ok "set default deny\nreject in proto tcp from any to any port 22";
  assert_format_round_trip
    "set default deny\npass out proto tcp from any to any port 443";
  assert_format_round_trip
    "set default deny\nreject in proto tcp from any to any port 22";
  assert_format_round_trip
    "set default deny\ntable <t> { 10.0.0.0/8 }\npass out from <t> to any";
  let policy =
    assert_parse
      "set default deny\n\
       interface wan = \"eth0\"\n\
       pass out on wan proto tcp from any to any port 443"
  in
  assert (Lpf.Policy.validate policy = []);
  assert (List.length policy.interfaces = 1);
  assert (
    policy.interfaces |> List.hd |> fun i ->
    String.equal i.Lpf.Policy.device "eth0");
  let policy =
    assert_parse
      "set default deny\n\
       table <t> { 10.0.0.0/8, 192.168.0.0/16 }\n\
       pass in from <t> to any"
  in
  assert (List.length policy.tables = 1);
  assert (
    policy.tables |> List.hd |> fun t -> List.length t.Lpf.Policy.entries = 2)
