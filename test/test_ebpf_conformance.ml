let contains text needle =
  let tlen = String.length text and nlen = String.length needle in
  if nlen = 0 then true
  else
    let rec loop i =
      i + nlen <= tlen
      && (String.equal (String.sub text i nlen) needle || loop (i + 1))
    in
    loop 0

let plan_of policy =
  match Lpf.plan_policy_text policy with
  | Ok (plan, _) -> plan
  | Error diagnostics ->
      failwith
        (String.concat "\n"
           (List.map Lpf.Policy.diagnostic_to_string diagnostics))

(* Canonical IR decision (what `lpf explain` reports). *)
let explain_verdict ir pkt =
  match (Lpf.Explain.explain ir pkt).Lpf.Explain.decision with
  | Lpf.Policy.Pass -> "pass"
  | Lpf.Policy.Block -> "drop"
  | Lpf.Policy.Reject -> "reject"

(* eBPF backend decision (what `lpf ebpf explain` reports). *)
let ebpf_verdict image pkt =
  let s = Lpf.Ebpf.classify image pkt in
  if contains s "(pass)" || contains s "default pass" then "pass"
  else if contains s "(drop)" || contains s "default drop" then "drop"
  else if contains s "(reject)" then "reject"
  else failwith ("unrecognized classify output: " ^ s)

let packet direction interface protocol source destination port =
  {
    Lpf.Explain.direction;
    interface;
    protocol;
    source;
    destination;
    port;
  }

let tcp = Lpf.Policy.Proto_named "tcp"
let udp = Lpf.Policy.Proto_named "udp"
let i = Lpf.Policy.In
let o = Lpf.Policy.Out

let () =
  (* Anchor-free policy: Explain and Ebpf scan the same flat rule list, so any
     divergence is a real semantic bug, not an ordering artifact. *)
  let policy =
    "set default deny\n\n\
     table <trusted> { 10.0.0.0/8, 192.168.1.0/24 }\n\
     pass in proto tcp from <trusted> to any port 22\n\
     pass out proto tcp from any to any port 443\n\
     block in proto udp from any to any port 53\n\
     pass in proto tcp from 203.0.113.5 to any port 80\n"
  in
  let plan = plan_of policy in
  let ir = plan.Lpf.Plan.policy in
  let image = Lpf.Ebpf.of_plan plan in
  let cases =
    [
      ("trusted /8 ssh", packet i "eth0" tcp "10.1.2.3" "10.0.0.1" (Some 22), "pass");
      ("trusted /24 ssh", packet i "eth0" tcp "192.168.1.10" "10.0.0.1" (Some 22), "pass");
      ("untrusted ssh", packet i "eth0" tcp "8.8.8.8" "10.0.0.1" (Some 22), "drop");
      ("egress https", packet o "eth0" tcp "10.0.0.1" "1.1.1.1" (Some 443), "pass");
      ("ingress dns block", packet i "eth0" udp "9.9.9.9" "10.0.0.1" (Some 53), "drop");
      ("literal web", packet i "eth0" tcp "203.0.113.5" "10.0.0.1" (Some 80), "pass");
      ("non-literal web", packet i "eth0" tcp "203.0.113.6" "10.0.0.1" (Some 80), "drop");
      (* `block in udp` must NOT match an egress packet (direction parity). *)
      ("egress dns default", packet o "eth0" udp "10.0.0.1" "9.9.9.9" (Some 53), "drop");
    ]
  in
  List.iter
    (fun (label, pkt, expected) ->
      let ir_verdict = explain_verdict ir pkt in
      let bpf_verdict = ebpf_verdict image pkt in
      if not (String.equal ir_verdict bpf_verdict) then
        failwith
          (Printf.sprintf "[%s] backend drift: explain=%s ebpf=%s" label
             ir_verdict bpf_verdict);
      if not (String.equal ir_verdict expected) then
        failwith
          (Printf.sprintf "[%s] expected %s but got %s" label expected
             ir_verdict))
    cases;

  (* Capability gating: unsupported IR features surface as warnings instead of
     being silently dropped. *)
  let gated =
    "set default deny\n\n\
     pass in proto tcp from any to any port 22 keep state\n\
     reject in proto tcp from any to any port 23\n\
     pass out proto tcp from any to any port 443 route-to 1.1.1.1 keep state\n"
  in
  match Lpf.render_ebpf_policy_text gated with
  | Error diagnostics ->
      failwith
        (String.concat "\n"
           (List.map Lpf.Policy.diagnostic_to_string diagnostics))
  | Ok (_, diagnostics) ->
      let messages =
        List.map (fun (d : Lpf.Policy.diagnostic) -> d.message) diagnostics
      in
      let has needle = List.exists (fun m -> contains m needle) messages in
      assert (has "keep state is not supported");
      assert (has "route-to is not supported");
      assert (has "reject");
      print_endline "ebpf conformance tests passed"
