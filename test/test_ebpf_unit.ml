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

let render policy =
  match Lpf.render_ebpf_policy_text policy with
  | Ok (rendered, _) -> rendered
  | Error diagnostics ->
      failwith
        (String.concat "\n"
           (List.map Lpf.Policy.diagnostic_to_string diagnostics))

let image policy =
  match Lpf.plan_policy_text policy with
  | Ok (plan, _) -> Lpf.Ebpf.of_plan plan
  | Error diagnostics ->
      failwith
        (String.concat "\n"
           (List.map Lpf.Policy.diagnostic_to_string diagnostics))

let () =
  (* Phase 1: a simple policy compiles to the expected map image. *)
  let basic =
    "set default deny\n\n\
     table <trusted> { 10.0.0.0/8 }\n\
     pass in proto tcp from <trusted> to any port 22\n\
     pass out proto tcp from any to any port 443 keep state\n\
     block in from any to any\n"
  in
  let rendered = render basic in
  assert (contains_substring rendered "ebpf policy image");
  assert (contains_substring rendered "map lpf_meta type array");
  assert (contains_substring rendered "map lpf_rules type array");
  assert (contains_substring rendered "map lpf_cidr4 type lpm_trie");
  (* <trusted> is set id 1, so its membership bitmask is bit 1 = 2. *)
  assert (contains_substring rendered "10.0.0.0/8 => 2");
  assert (contains_substring rendered "saddr_set=1");
  assert (contains_substring rendered "verdict=pass proto=tcp dport=443");
  assert (contains_substring rendered "program lpf_xdp_eth0");
  assert (contains_substring rendered "keep_state=yes");
  assert (contains_substring rendered "rule_count => 3");

  (* Phase 1: identical images diff clean; a changed image needs changes. *)
  let diff_same = Lpf.Ebpf.diff ~intended:rendered ~observed:rendered in
  assert (not diff_same.Lpf.Ebpf.changes_required);
  let drifted =
    rendered ^ "  rule 9 drop proto any dport any comment \"drift\"\n"
  in
  let diff_drift = Lpf.Ebpf.diff ~intended:rendered ~observed:drifted in
  assert diff_drift.Lpf.Ebpf.changes_required;
  assert (
    String.length (Lpf.Ebpf.diff_text ~intended:rendered ~observed:drifted) > 0);

  (* Phase 2: loader and rollback scripts are well-formed. *)
  let img = image basic in
  let loader = Lpf.Ebpf.loader_script img in
  assert (contains_substring loader "bpftool map create \"$PIN/lpf_meta\"");
  assert (
    contains_substring loader "bpftool map update pinned \"$PIN/lpf_rules\"");
  assert (
    contains_substring loader
      "map name lpf_meta pinned \"$PIN/lpf_meta\" map name lpf_rules pinned \
       \"$PIN/lpf_rules\"");
  assert (contains_substring loader "lpf-ebpf-loaded version=1 rules=3");
  let rollback = Lpf.Ebpf.rollback_script ~to_version:3 in
  assert (
    contains_substring rollback "bpftool map update pinned \"$PIN/lpf_meta\"");
  assert (contains_substring rollback "lpf-ebpf-rolled-back version=3");

  (* Phase 3: observed counters parse from a bpftool-style dump. *)
  let dump =
    "key: 02 00 00 00  value: 05 00 00 00 00 00 00 00 0a 00 00 00 00 00 00 00\n\
     key: 00 00 00 00  value: 07 00 00 00 00 00 00 00 14 00 00 00 00 00 00 00\n"
  in
  let counters = Lpf.Ebpf.parse_counters dump in
  assert (List.length counters = 2);
  let c2 = List.find (fun c -> c.Lpf.Ebpf.rule_index = 2) counters in
  assert (c2.Lpf.Ebpf.packets = 5);
  assert (c2.Lpf.Ebpf.bytes = 10);
  assert (String.length (Lpf.Ebpf.render_counters counters) > 0);

  (* Phase 4: identity selectors via reserved table names. *)
  let identity_policy =
    "set default deny\n\n\
     table <cgroup_web> { 10.1.0.0/16 }\n\
     table <dns_api> { 10.2.0.0/16 }\n\
     pass out proto tcp from <cgroup_web> to any port 443\n\
     pass out proto tcp from any to <dns_api> port 443\n"
  in
  let identity_rendered = render identity_policy in
  assert (contains_substring identity_rendered "map lpf_cgroup type hash");
  assert (contains_substring identity_rendered "map lpf_dns type hash");
  assert (contains_substring identity_rendered "id=cgroup:web");
  assert (contains_substring identity_rendered "id=dns:api");
  assert (contains_substring identity_rendered "program lpf_cgroup_ingress");
  assert (contains_substring identity_rendered "program lpf_lsm_connect");

  (* Phase 4 / explain: classify resolves a packet to a hook + rule. *)
  let img = image basic in
  let packet =
    {
      Lpf.Explain.direction = Lpf.Policy.Out;
      interface = "eth0";
      protocol = Lpf.Policy.Proto_named "tcp";
      source = "10.0.0.5";
      destination = "1.1.1.1";
      port = Some 443;
    }
  in
  let classification = Lpf.Ebpf.classify img packet in
  assert (contains_substring classification "rule 1");
  assert (contains_substring classification "pass");

  (* set membership: an in/22 packet from <trusted> matches rule 0. *)
  let trusted_packet =
    {
      Lpf.Explain.direction = Lpf.Policy.In;
      interface = "eth0";
      protocol = Lpf.Policy.Proto_named "tcp";
      source = "10.0.0.5";
      destination = "1.1.1.1";
      port = Some 22;
    }
  in
  let trusted_class = Lpf.Ebpf.classify img trusted_packet in
  assert (contains_substring trusted_class "rule 0");
  assert (contains_substring trusted_class "pass");
  (* a non-trusted in/22 packet misses rule 0 and is caught by `block in`. *)
  let untrusted_class =
    Lpf.Ebpf.classify img { trusted_packet with source = "8.8.8.8" }
  in
  assert (contains_substring untrusted_class "rule 2");
  assert (contains_substring untrusted_class "drop");

  print_endline "ebpf unit tests passed"
