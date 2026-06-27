let property_name option_name =
  let token =
    option_name |> String.trim |> String.split_on_char ' ' |> function
    | first :: _ -> first
    | [] -> option_name
  in
  let token =
    if String.starts_with ~prefix:"--" token then
      String.sub token 2 (String.length token - 2)
    else token
  in
  let buffer = Buffer.create (String.length token) in
  String.iter
    (fun character ->
      let code = Char.code character in
      let valid =
        (code >= Char.code 'a' && code <= Char.code 'z')
        || (code >= Char.code 'A' && code <= Char.code 'Z')
        || (code >= Char.code '0' && code <= Char.code '9')
      in
      Buffer.add_char buffer (if valid then character else '_'))
    token;
  let name = Buffer.contents buffer in
  if String.length name = 0 then "option" else name

let deduplicate properties =
  let rec loop seen acc = function
    | [] -> List.rev acc
    | ((name, _) as property) :: rest ->
        if List.mem name seen then loop seen acc rest
        else loop (name :: seen) (property :: acc) rest
  in
  loop [] [] properties

let properties doc =
  let option_properties =
    match doc with
    | None -> []
    | Some d ->
        List.map
          (fun (opt_name, opt_desc) ->
            (property_name opt_name, ("string", opt_desc)))
          d.Lpf.options
  in
  deduplicate (option_properties @ [ ("policy", ("string", "the policy text")) ])

let properties_json properties =
  String.concat ","
    (List.map
       (fun (k, (t, desc)) ->
         Printf.sprintf "%s:{\"type\":%s,\"description\":%s}"
           (Lpf.Json_util.string k) (Lpf.Json_util.string t)
           (Lpf.Json_util.string desc))
       properties)

let command_doc command =
  List.find_opt (fun d -> d.Lpf.command = command) Lpf.command_docs

let openai (name, command, summary) =
  let properties = command_doc command |> properties in
  let required = [ "policy" ] in
  Printf.sprintf
    "{\"name\":%s,\"description\":%s,\"parameters\":{\"type\":\"object\",\"properties\":{%s},\"required\":%s}}"
    (Lpf.Json_util.string name)
    (Lpf.Json_util.string summary)
    (properties_json properties)
    (Lpf.Json_util.list Lpf.Json_util.string required)

let jsonschema (name, command, summary) =
  let properties = command_doc command |> properties in
  let required = [ "policy" ] in
  Printf.sprintf
    "{\"$id\":%s,\"title\":%s,\"description\":%s,\"type\":\"object\",\"properties\":{%s},\"required\":%s}"
    (Lpf.Json_util.string ("lpf-" ^ name))
    (Lpf.Json_util.string name)
    (Lpf.Json_util.string summary)
    (properties_json properties)
    (Lpf.Json_util.list Lpf.Json_util.string required)

let system_prompt =
  "You are an lpf firewall automation agent. lpf is an OCaml control plane for \
   Linux networking that compiles a PF-inspired policy language to nftables, \
   policy routing, tc traffic shaping, and conntrack.\n\n\
   Commands available:\n\
   - lpf check <policy> - Parse and validate a policy without host changes. \
   Use --json for structured output.\n\
   - lpf fmt <policy> - Format policy files deterministically. Use --json for \
   machine output.\n\
   - lpf plan --json <policy> - Compile policy to a versioned JSON plan with \
   stable checksum.\n\
   - lpf diff --json <policy> - Compare intended state with live \
   nftables/routing/tc state.\n\
   - lpf apply <policy> [--confirm 60s] - Apply policy with atomic rollback \
   support.\n\
   - lpf apply --dry-run <policy> - Validate and plan without changing host \
   state.\n\
   - lpf explain --json from <addr> to <addr> proto <proto> port <port> \
   <policy> - Explain packet handling.\n\
   - lpf test --junit <path> <fixture> - Run policy assertion tests.\n\
   - lpf table <name> <add|delete|replace|show|flush|counters> [--json] - \
   Manage dynamic tables.\n\
   - lpf state <list|show|flush|kill> [--json] - Inspect conntrack state.\n\
   - lpf history [--json] - Show policy apply history.\n\
   - lpf rollback [--now] [<policy-id>] - Restore previous policy.\n\
   - lpf confirm - Confirm pending guarded apply.\n\n\
   Safety: Always use lpf check before apply. Use guarded apply (--confirm) \
   for remote hosts. Use rollback if traffic is disrupted. lpf requires \
   root/CAP_NET_ADMIN.\n\n\
   When writing policies, follow the lpf policy format: interfaces, tables, \
   macros, NAT, RDR, queues, anchors, and rules with pass/block/reject \
   actions. Use lpf fmt to normalize before applying."
