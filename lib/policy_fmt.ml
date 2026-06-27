open Policy_types
open Json_util

let string_of_default_action = function
  | Default_pass -> "pass"
  | Default_deny -> "deny"

let string_of_action = function
  | Pass -> "pass"
  | Block -> "block"
  | Reject -> "reject"

let string_of_direction = function In -> "in" | Out -> "out"

let string_of_log_option = function
  | Log_all -> "all"
  | Log_matches -> "matches"
  | Log_user -> "user"

let string_of_reference = function
  | Any -> "any"
  | Literal value -> value
  | Table_ref name -> "<" ^ name ^ ">"
  | Macro_ref name -> "$" ^ name

let string_of_port = function
  | Port_any -> "any"
  | Port_number number -> string_of_int number
  | Port_range (low, high) -> Printf.sprintf "%d:%d" low high
  | Port_macro name -> "$" ^ name

let format_policy (policy : policy) =
  let default_lines =
    match policy.default_action with
    | None -> []
    | Some action -> [ "set default " ^ string_of_default_action action ]
  in
  let macro_lines =
    policy.macros
    |> List.sort (fun (a : macro) b -> String.compare a.name b.name)
    |> List.map (fun (macro : macro) -> macro.name ^ " = " ^ macro.value)
  in
  let interface_lines =
    policy.interfaces
    |> List.sort (fun (a : interface_decl) b -> String.compare a.name b.name)
    |> List.map (fun (interface : interface_decl) ->
           "interface " ^ interface.name ^ " = \"" ^ interface.device ^ "\"")
  in
  let table_lines =
    policy.tables
    |> List.sort (fun (a : table) b -> String.compare a.name b.name)
    |> List.map (fun (table : table) ->
           "table <" ^ table.name ^ "> { "
           ^ String.concat ", " table.entries
           ^ " }")
  in
  let nat_lines =
    policy.nats
    |> List.map (fun (nat : nat) ->
           let parts = [ "nat" ] in
           let parts =
             if nat.interface <> Any then
               parts @ [ "on"; string_of_reference nat.interface ]
             else parts
           in
           let parts =
             match nat.protocol with
             | Proto_any -> parts
             | Proto_named name -> parts @ [ "proto"; name ]
           in
           let parts =
             parts
             @ [
                 "from";
                 string_of_reference nat.source;
                 "to";
                 string_of_reference nat.destination;
               ]
           in
           let parts = parts @ [ "->"; string_of_reference nat.translation ] in
           String.concat " " parts)
  in
  let rdr_lines =
    policy.rdrs
    |> List.map (fun (rdr : rdr) ->
           let parts = [ "rdr" ] in
           let parts =
             if rdr.interface <> Any then
               parts @ [ "on"; string_of_reference rdr.interface ]
             else parts
           in
           let parts =
             match rdr.protocol with
             | Proto_any -> parts
             | Proto_named name -> parts @ [ "proto"; name ]
           in
           let parts =
             parts
             @ [
                 "from";
                 string_of_reference rdr.source;
                 "to";
                 string_of_reference rdr.destination;
               ]
           in
           let parts =
             match rdr.port with
             | Port_any -> parts
             | port -> parts @ [ "port"; string_of_port port ]
           in
           let parts = parts @ [ "->"; string_of_reference rdr.translation ] in
           let parts =
             match rdr.translation_port with
             | Port_any -> parts
             | port -> parts @ [ "port"; string_of_port port ]
           in
           String.concat " " parts)
  in
  let queue_lines =
    policy.queues
    |> List.map (fun (queue : queue) ->
           let parts =
             [
               "queue";
               queue.name;
               "on";
               string_of_reference queue.interface;
               "bandwidth";
               queue.bandwidth;
             ]
           in
           let parts =
             match queue.parent with
             | None -> parts
             | Some parent -> parts @ [ "parent"; parent ]
           in
           String.concat " " parts)
  in
  let format_rule (rule : rule) =
    let parts = [ string_of_action rule.action ] in
    let parts =
      match rule.direction with
      | None -> parts
      | Some direction -> parts @ [ string_of_direction direction ]
    in
    let parts =
      match rule.log with
      | None -> parts
      | Some Log_matches -> parts @ [ "log" ]
      | Some option ->
          parts @ [ "log"; "(" ^ string_of_log_option option ^ ")" ]
    in
    let parts =
      match rule.interface with
      | None -> parts
      | Some interface -> parts @ [ "on"; string_of_reference interface ]
    in
    let parts =
      match rule.protocol with
      | Proto_any -> parts
      | Proto_named name -> parts @ [ "proto"; name ]
    in
    let parts =
      parts
      @ [
          "from";
          string_of_reference rule.source;
          "to";
          string_of_reference rule.destination;
        ]
    in
    let parts =
      match rule.port with
      | Port_any -> parts
      | port -> parts @ [ "port"; string_of_port port ]
    in
    let parts =
      match rule.queue with
      | None -> parts
      | Some name -> parts @ [ "queue"; name ]
    in
    let parts =
      match rule.route_to with
      | None -> parts
      | Some (gateway, interface) ->
          let target =
            match interface with
            | None -> string_of_reference gateway
            | Some iface ->
                string_of_reference gateway
                ^ " (" ^ string_of_reference iface ^ ")"
          in
          parts @ [ "route-to"; target ]
    in
    let parts =
      if rule.keep_state then parts @ [ "keep"; "state" ] else parts
    in
    String.concat " " parts
  in
  let anchor_lines =
    policy.anchors
    |> List.map (fun (anchor : anchor) ->
           let rule_lines = List.map format_rule anchor.rules in
           "anchor " ^ anchor.name ^ " {\n  "
           ^ String.concat "\n  " rule_lines
           ^ "\n}")
  in
  let rule_lines = List.map format_rule policy.rules in
  [
    default_lines;
    macro_lines;
    interface_lines;
    table_lines;
    queue_lines;
    nat_lines @ rdr_lines;
    anchor_lines;
    rule_lines;
  ]
  |> List.filter (fun group -> group <> [])
  |> List.map (String.concat "\n")
  |> String.concat "\n\n"
  |> fun formatted -> formatted ^ "\n"

let format = format_policy

let severity_to_string = function
  | Diag_error -> "error"
  | Diag_warning -> "warning"

let diagnostic_to_string (diagnostic : diagnostic) =
  let location =
    match diagnostic.span.file with
    | None -> Printf.sprintf "%d:%d" diagnostic.span.line diagnostic.span.column
    | Some file ->
        Printf.sprintf "%s:%d:%d" file diagnostic.span.line
          diagnostic.span.column
  in
  Printf.sprintf "%s: %s: %s" location
    (severity_to_string diagnostic.severity)
    diagnostic.message

let diagnostic_to_json (diagnostic : diagnostic) =
  field_object
    [
      ("severity", string (severity_to_string diagnostic.severity));
      ("message", string diagnostic.message);
      ("line", int diagnostic.span.line);
      ("column", int diagnostic.span.column);
      ("file", option string diagnostic.span.file);
    ]

let check_result_to_json result =
  field_object
    [
      ("valid", if Option.is_some result.policy then "true" else "false");
      ("diagnostics", list diagnostic_to_json result.diagnostics);
    ]
  ^ "\n"

let format_check_result result =
  let diagnostics = List.map diagnostic_to_string result.diagnostics in
  match result.policy with
  | None -> String.concat "\n" diagnostics
  | Some policy ->
      let summary =
        Printf.sprintf
          "ok: %d interface(s), %d macro(s), %d table(s), %d queue(s), %d \
           nat(s), %d rdr(s), %d anchor(s), %d rule(s)"
          (List.length policy.interfaces)
          (List.length policy.macros)
          (List.length policy.tables)
          (List.length policy.queues)
          (List.length policy.nats) (List.length policy.rdrs)
          (List.length policy.anchors)
          (List.length policy.rules)
      in
      String.concat "\n" (summary :: diagnostics)
