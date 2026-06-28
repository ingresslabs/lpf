let () =
  let require condition message = if not condition then failwith message in
  let contains s sub =
    try
      ignore (Str.search_forward (Str.regexp_string sub) s 0);
      true
    with Not_found -> false
  in
  let count_sub s sub =
    let regexp = Str.regexp_string sub in
    let rec loop pos count =
      try
        let found = Str.search_forward regexp s pos in
        loop (found + String.length sub) (count + 1)
      with Not_found -> count
    in
    loop 0 0
  in

  let hash_a = Lpf.Lpf_daemon.policy_hash "set default pass\n" in
  let hash_b = Lpf.Lpf_daemon.policy_hash "set default pass\n" in
  let hash_c = Lpf.Lpf_daemon.policy_hash "set default deny\n" in
  require (String.equal hash_a hash_b) "policy_hash stable";
  require (not (String.equal hash_a hash_c)) "policy_hash changes";

  let status = Lpf.Lpf_daemon.create_status () in
  let code, _content_type, body =
    Lpf.Lpf_daemon.route_response status "/livez"
  in
  require (code = 200) "livez is always healthy";
  require (String.equal body "ok\n") "livez body";

  let code, _content_type, _body =
    Lpf.Lpf_daemon.route_response status "/readyz"
  in
  require (code = 503) "readyz starts unavailable";

  status.ready <- true;
  status.reloads <- 2;
  status.failures <- 1;
  status.last_policy_hash <- Some "abc123";
  status.last_reload_at <- Some 42.;

  let code, _content_type, body =
    Lpf.Lpf_daemon.route_response status "/readyz"
  in
  require (code = 200) "readyz ok after load";
  require (String.equal body "ok\n") "readyz body";

  let metrics = Lpf.Lpf_daemon.metrics_text status in
  require (contains metrics "lpf_daemon_ready 1") "metrics ready";
  require (contains metrics "lpf_daemon_reload_total 2") "metrics reload count";
  require
    (contains metrics "lpf_daemon_reload_failure_total 1")
    "metrics failure count";
  require
    (contains metrics "lpf_daemon_policy_info{hash=\"abc123\"} 1")
    "metrics policy hash";

  let cluster_policies =
    {|
{
  "items": [
    {
      "metadata": { "name": "base" },
      "spec": {
        "priority": 5,
        "defaultAction": "deny",
        "policy": "set default pass\npass out proto udp from any to any port 53 keep state"
      }
    }
  ]
}
|}
  in
  let namespaced_policies =
    {|
{
  "items": [
    {
      "metadata": { "namespace": "tenant-a", "name": "ns-web" },
      "spec": {
        "priority": 20,
        "policy": "pass in proto tcp from any to any port 8080"
      }
    }
  ]
}
|}
  in
  let staged_policies =
    {|
{
  "items": [
    {
      "metadata": { "namespace": "tenant-a", "name": "staged-ssh" },
      "spec": {
        "priority": 30,
        "policy": "block in proto tcp from any to any port 22"
      }
    }
  ]
}
|}
  in
  let network_policies =
    {|
{
  "items": [
    {
      "apiVersion": "networking.k8s.io/v1",
      "kind": "NetworkPolicy",
      "metadata": { "namespace": "tenant-a", "name": "allow-web" },
      "spec": {
        "podSelector": {},
        "policyTypes": ["Ingress"],
        "ingress": [
          {
            "from": [
              { "ipBlock": { "cidr": "10.10.0.0/16" } }
            ],
            "ports": [
              { "port": 80, "protocol": "TCP" }
            ]
          }
        ]
      }
    }
  ]
}
|}
  in
  let effective =
    match
      Lpf.Lpf_daemon.effective_policy_of_kubernetes_json ~cluster_policies
        ~namespaced_policies ~staged_policies ~network_policies
    with
    | Ok text -> text
    | Error error -> failwith ("effective policy merge failed: " ^ error)
  in
  require
    (count_sub effective "set default " = 1)
    "effective policy has one default";
  require
    (contains effective "set default deny")
    "effective policy uses ClusterPolicy defaultAction";
  require
    (not (contains effective "set default pass"))
    "embedded fragment default was stripped";
  require
    (contains effective "ClusterPolicy base priority=5")
    "effective policy includes ClusterPolicy";
  require
    (contains effective "NamespacedPolicy tenant-a/ns-web priority=20")
    "effective policy includes NamespacedPolicy";
  require
    (contains effective "anchor tenant-a-allow-web")
    "effective policy includes translated NetworkPolicy";
  require
    (contains effective
       "pass in on eth0 proto tcp from 10.10.0.0/16 to any port 80")
    "effective policy renders parseable NetworkPolicy rule";
  require
    (contains effective
       "# staged tenant-a/staged-ssh priority=30 (not enforced)")
    "effective policy carries StagedPolicy as non-enforced text";
  let checked = Lpf.check_policy_text ~file:"kubernetes-api" effective in
  let diagnostics =
    checked.Lpf.Policy.diagnostics
    |> List.map Lpf.Policy.diagnostic_to_string
    |> String.concat "\n"
  in
  require
    (Option.is_some checked.Lpf.Policy.policy)
    ("effective policy parses:\n" ^ effective ^ "\n" ^ diagnostics);

  let code, _content_type, body =
    Lpf.Lpf_daemon.route_response status "/missing"
  in
  require (code = 404) "unknown path";
  require (String.equal body "not found\n") "unknown path body";

  Printf.printf "lpf_daemon tests passed\n"
