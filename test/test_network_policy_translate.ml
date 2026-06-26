let () =
  let require condition message =
    if not condition then failwith message
  in
  let contains s sub =
    try ignore (Str.search_forward (Str.regexp_string sub) s 0); true
    with Not_found -> false
  in

  let open Lpf.Network_policy_translate in

  (* ─── Test 1: Simple ingress allow on port 80 ─── *)
  let np1 = {|
{
  "apiVersion": "networking.k8s.io/v1",
  "kind": "NetworkPolicy",
  "metadata": {
    "name": "allow-web",
    "namespace": "default"
  },
  "spec": {
    "podSelector": {
      "matchLabels": {
        "app": "web"
      }
    },
    "policyTypes": ["Ingress"],
    "ingress": [
      {
        "from": [
          {
            "podSelector": {
              "matchLabels": {
                "app": "frontend"
              }
            }
          }
        ],
        "ports": [
          {
            "port": 80,
            "protocol": "TCP"
          }
        ]
      }
    ]
  }
}
|} in
  match Lpf.Json_parse.parse np1 with
  | Error e -> failwith ("parse error: " ^ e)
  | Ok json ->
    match translate_network_policy json with
    | Error e -> failwith ("translate error: " ^ e)
    | Ok policy ->
      require (contains policy "anchor") "policy contains anchor";
      require (contains policy "pass in on eth0") "policy contains pass in";
      require (contains policy "port 80") "policy contains port 80";
      Printf.printf "test1 basic ingress: OK\n%!";

  (* ─── Test 2: Egress allow with keep state ─── *)
  let np2 = {|
{
  "apiVersion": "networking.k8s.io/v1",
  "kind": "NetworkPolicy",
  "metadata": {
    "name": "allow-egress",
    "namespace": "default"
  },
  "spec": {
    "podSelector": {
      "matchLabels": {
        "app": "api"
      }
    },
    "policyTypes": ["Egress"],
    "egress": [
      {
        "to": [
          {
            "ipBlock": {
              "cidr": "0.0.0.0/0",
              "except": ["10.0.0.0/8"]
            }
          }
        ],
        "ports": [
          {
            "port": 443,
            "protocol": "TCP"
          }
        ]
      }
    ]
  }
}
|} in
  match Lpf.Json_parse.parse np2 with
  | Error e -> failwith ("parse error: " ^ e)
  | Ok json ->
    match translate_network_policy json with
    | Error e -> failwith ("translate error: " ^ e)
    | Ok policy ->
      require (contains policy "pass out on eth0") "policy contains pass out";
      require (contains policy "port 443") "policy contains port 443";
      require (contains policy "keep state") "policy contains keep state";
      Printf.printf "test2 egress: OK\n%!";

  (* ─── Test 3: Namespace selector ─── *)
  let np3 = {|
{
  "apiVersion": "networking.k8s.io/v1",
  "kind": "NetworkPolicy",
  "metadata": {
    "name": "allow-from-ns",
    "namespace": "tenant-a"
  },
  "spec": {
    "podSelector": {},
    "policyTypes": ["Ingress"],
    "ingress": [
      {
        "from": [
          {
            "namespaceSelector": {
              "matchLabels": {
                "kubernetes.io/metadata.name": "tenant-b"
              }
            }
          }
        ],
        "ports": [
          {
            "port": 5432,
            "protocol": "TCP"
          }
        ]
      }
    ]
  }
}
|} in
  match Lpf.Json_parse.parse np3 with
  | Error e -> failwith ("parse error: " ^ e)
  | Ok json ->
    match translate_network_policy json with
    | Error e -> failwith ("translate error: " ^ e)
    | Ok policy ->
      require (contains policy "pass in on eth0") "policy contains pass in";
      require (contains policy "from <") "policy contains from <set>";
      require (contains policy "port 5432") "policy contains port 5432";
      Printf.printf "test3 namespace selector: OK\n%!";

  (* ─── Test 4: Port range (endPort) ─── *)
  let np4 = {|
{
  "apiVersion": "networking.k8s.io/v1",
  "kind": "NetworkPolicy",
  "metadata": {
    "name": "port-range",
    "namespace": "default"
  },
  "spec": {
    "podSelector": {},
    "policyTypes": ["Ingress"],
    "ingress": [
      {
        "from": [],
        "ports": [
          {
            "port": 30000,
            "endPort": 32767,
            "protocol": "TCP"
          }
        ]
      }
    ]
  }
}
|} in
  match Lpf.Json_parse.parse np4 with
  | Error e -> failwith ("parse error: " ^ e)
  | Ok json ->
    match translate_network_policy json with
    | Error e -> failwith ("translate error: " ^ e)
    | Ok policy ->
      require (contains policy "port 30000:32767") "policy contains port range";
      Printf.printf "test4 port range: OK\n%!";

  (* ─── Test 5: Default deny (no ingress rules) ─── *)
  let np5 = {|
{
  "apiVersion": "networking.k8s.io/v1",
  "kind": "NetworkPolicy",
  "metadata": {
    "name": "default-deny",
    "namespace": "default"
  },
  "spec": {
    "podSelector": {},
    "policyTypes": ["Ingress"],
    "ingress": []
  }
}
|} in
  match Lpf.Json_parse.parse np5 with
  | Error e -> failwith ("parse error: " ^ e)
  | Ok json ->
    match translate_network_policy json with
    | Error e -> failwith ("translate error: " ^ e)
    | Ok policy ->
      require (contains policy "anchor") "policy contains anchor";
      Printf.printf "test5 default deny: OK\n%!";

  Printf.printf "network_policy_translate tests passed\n"
