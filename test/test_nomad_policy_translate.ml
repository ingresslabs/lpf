let () =
  let require condition message =
    if not condition then failwith message
  in
  let contains s sub =
    try ignore (Str.search_forward (Str.regexp_string sub) s 0); true
    with Not_found -> false
  in

  let open Lpf.Nomad_policy_translate in

  (* ─── Test 1: Nomad job with bridge network and ports ─── *)
  let nomad1 = {|
{
  "Name": "web-server",
  "TaskGroups": [
    {
      "Name": "web",
      "Networks": [
        {
          "Mode": "bridge",
          "DynamicPorts": [
            {
              "Label": "http",
              "Value": "8080"
            }
          ],
          "ReservedPorts": [
            {
              "Label": "metrics",
              "Value": "9090"
            }
          ]
        }
      ]
    }
  ]
}
|} in
  match Lpf.Json_parse.parse nomad1 with
  | Error e -> failwith ("parse error: " ^ e)
  | Ok json ->
    match translate_nomad_network json with
    | Error e -> failwith ("translate error: " ^ e)
    | Ok policy ->
      require (contains policy "Generated from Nomad job: web-server") "policy contains header";
      require (contains policy "anchor nomad-web") "policy contains anchor";
      require (contains policy "pass in on eth0") "policy contains pass in";
      require (contains policy "port 8080") "policy contains port 8080";
      require (contains policy "port 9090") "policy contains port 9090";
      require (contains policy "keep state") "policy contains keep state";
      Printf.printf "test1 nomad bridge: OK\n%!";

  (* ─── Test 2: Nomad job without ports ─── *)
  let nomad2 = {|
{
  "Name": "batch-job",
  "TaskGroups": [
    {
      "Name": "worker",
      "Networks": [
        {
          "Mode": "bridge",
          "DynamicPorts": [],
          "ReservedPorts": []
        }
      ]
    }
  ]
}
|} in
  match Lpf.Json_parse.parse nomad2 with
  | Error e -> failwith ("parse error: " ^ e)
  | Ok json ->
    match translate_nomad_network json with
    | Error e -> failwith ("translate error: " ^ e)
    | Ok policy ->
      require (contains policy "Generated from Nomad job: batch-job") "policy contains header";
      require (contains policy "anchor nomad-worker") "policy contains anchor";
      Printf.printf "test2 nomad no ports: OK\n%!";

  (* ─── Test 3: Nomad job with multiple groups ─── *)
  let nomad3 = {|
{
  "Name": "multi-group",
  "TaskGroups": [
    {
      "Name": "api",
      "Networks": [
        {
          "Mode": "bridge",
          "DynamicPorts": [
            {
              "Label": "http",
              "Value": "8080"
            }
          ]
        }
      ]
    },
    {
      "Name": "worker",
      "Networks": [
        {
          "Mode": "bridge",
          "DynamicPorts": [
            {
              "Label": "grpc",
              "Value": "50051"
            }
          ]
        }
      ]
    }
  ]
}
|} in
  match Lpf.Json_parse.parse nomad3 with
  | Error e -> failwith ("parse error: " ^ e)
  | Ok json ->
    match translate_nomad_network json with
    | Error e -> failwith ("translate error: " ^ e)
    | Ok policy ->
      require (contains policy "anchor nomad-api") "policy contains api anchor";
      require (contains policy "anchor nomad-worker") "policy contains worker anchor";
      require (contains policy "port 8080") "policy contains port 8080";
      require (contains policy "port 50051") "policy contains port 50051";
      Printf.printf "test3 nomad multi-group: OK\n%!";

  Printf.printf "nomad_policy_translate tests passed\n"
