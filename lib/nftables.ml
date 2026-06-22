type family = Inet | Ip
type chain_type = Filter | Nat
type hook = Input | Forward | Output | Prerouting | Postrouting
type policy = Policy_accept | Policy_drop
type table = { family : family; name : string }

type chain = {
  table : string;
  name : string;
  chain_type : chain_type option;
  hook : hook option;
  priority : int option;
  policy : policy option;
}

type set = {
  table : string;
  name : string;
  set_type : string;
  flags : string list;
  elements : string list;
}

type expression =
  | Meta of string * string
  | Payload of string * string * string
  | Ct_state of string list

type statement =
  | Accept
  | Drop
  | Reject
  | Log of string option
  | Snat of string
  | Dnat of string
  | Masquerade
  | Meta_priority_set of string
  | Meta_mark_set of int

type rule = {
  table : string;
  chain : string;
  expressions : expression list;
  statements : statement list;
  comment : string option;
}

type t = {
  tables : table list;
  chains : chain list;
  sets : set list;
  rules : rule list;
}

let filter_table_name = "lpf_filter"
let nat_table_name = "lpf_nat"

let sanitize_identifier name =
  let buffer = Buffer.create (String.length name) in
  String.iter
    (function
      | ('a' .. 'z' | 'A' .. 'Z' | '0' .. '9' | '_') as character ->
          Buffer.add_char buffer character
      | _ -> Buffer.add_char buffer '_')
    name;
  let sanitized = Buffer.contents buffer in
  if sanitized = "" then "unnamed" else sanitized

let set_name name = "tbl_" ^ sanitize_identifier name

let policy_of_default = function
  | Policy.Default_pass -> Policy_accept
  | Policy.Default_deny -> Policy_drop

let address_family_of_entry entry =
  if String.contains entry ':' then "ipv6_addr" else "ipv4_addr"

let split_ipv4 text =
  match String.split_on_char '.' text with
  | [ a; b; c; d ] -> (
      match
        List.map int_of_string_opt [ a; b; c; d ]
        |> List.fold_left
             (fun acc value ->
               match (acc, value) with
               | Some values, Some value when value >= 0 && value <= 255 ->
                   Some (values @ [ value ])
               | _ -> None)
             (Some [])
      with
      | Some [ a; b; c; d ] ->
          Some
            Int64.(
              logor
                (shift_left (of_int a) 24)
                (logor
                   (shift_left (of_int b) 16)
                   (logor (shift_left (of_int c) 8) (of_int d))))
      | _ -> None)
  | _ -> None

let parse_ipv4_cidr text =
  match String.split_on_char '/' text with
  | [ network; prefix_text ] -> (
      match (split_ipv4 network, int_of_string_opt prefix_text) with
      | Some network, Some prefix when prefix >= 0 && prefix <= 32 ->
          let mask =
            if prefix = 0 then 0L
            else
              let host_bits = 32 - prefix in
              let host_mask =
                if host_bits = 0 then 0L
                else Int64.sub (Int64.shift_left 1L host_bits) 1L
              in
              Int64.logand 0xffffffffL (Int64.lognot host_mask)
          in
          Some (Int64.logand network mask, mask)
      | _ -> None)
  | _ -> Option.map (fun address -> (address, 0xffffffffL)) (split_ipv4 text)

let ipv4_cidr_contains cidr value =
  match (parse_ipv4_cidr cidr, parse_ipv4_cidr value) with
  | Some (network, mask), Some (address, value_mask) ->
      let value_prefix_is_narrower =
        Int64.equal (Int64.logand value_mask mask) mask
      in
      value_prefix_is_narrower
      && Int64.equal (Int64.logand address mask) network
  | _ -> false

let normalize_set_elements entries =
  entries
  |> List.sort_uniq String.compare
  |> List.filter (fun entry ->
         not
           (List.exists
              (fun other ->
                (not (String.equal entry other))
                && ipv4_cidr_contains other entry)
              entries))

let table_of_policy_table ?(table_name = filter_table_name) (table : Ir.table) =
  let set_type =
    match table.entries with
    | [] -> "ipv4_addr"
    | entry :: _ -> address_family_of_entry entry
  in
  {
    table = table_name;
    name = set_name table.name;
    set_type;
    flags = [ "interval" ];
    elements = normalize_set_elements table.entries;
  }

let address_to_nft = function
  | Ir.Any -> None
  | Ir.Literal value -> Some value
  | Ir.Table name -> Some ("@" ^ set_name name)

let address_to_comment = function
  | Ir.Any -> "any"
  | Ir.Literal value -> value
  | Ir.Table name -> "<" ^ name ^ ">"

let port_to_nft = function
  | Ir.Port_any -> None
  | Ir.Range (lower, upper) when lower = upper -> Some (string_of_int lower)
  | Ir.Range (lower, upper) ->
      Some (string_of_int lower ^ "-" ^ string_of_int upper)

let protocol_for_port = function
  | Policy.Proto_named protocol -> protocol
  | Policy.Proto_any -> "tcp"

let interface_expression chain_name (interface : Ir.interface_ref) =
  let key = if String.equal chain_name "output" then "oifname" else "iifname" in
  Meta (key, Json_util.string interface.device)

let address_family_heuristic = function
  | Ir.Any -> None
  | Ir.Literal value ->
      if String.contains value ':' then Some "ip6" else Some "ip"
  | Ir.Table _ -> None

let rule_family source destination =
  match
    (address_family_heuristic source, address_family_heuristic destination)
  with
  | Some "ip6", _ | _, Some "ip6" -> "ip6"
  | Some "ip", _ | _, Some "ip" -> "ip"
  | _ -> "ip"

let base_expressions ?chain_name rule_protocol source destination port interface
    =
  let family = rule_family source destination in
  let expressions = [] in
  let expressions =
    match interface with
    | None -> expressions
    | Some interface ->
        interface_expression
          (Option.value chain_name ~default:"forward")
          interface
        :: expressions
  in
  let expressions =
    match rule_protocol with
    | Policy.Proto_any -> expressions
    | Policy.Proto_named protocol -> Meta ("l4proto", protocol) :: expressions
  in
  let expressions =
    match address_to_nft source with
    | None -> expressions
    | Some address -> Payload (family, "saddr", address) :: expressions
  in
  let expressions =
    match address_to_nft destination with
    | None -> expressions
    | Some address -> Payload (family, "daddr", address) :: expressions
  in
  let expressions =
    match port_to_nft port with
    | None -> expressions
    | Some port ->
        Payload (protocol_for_port rule_protocol, "dport", port) :: expressions
  in
  List.rev expressions

let rule_chain = function
  | Some Policy.In -> "input"
  | Some Policy.Out -> "output"
  | None -> "forward"

let log_statement = function
  | None -> []
  | Some Policy.Log_matches -> [ Log None ]
  | Some Policy.Log_all -> [ Log (Some "lpf all ") ]
  | Some Policy.Log_user -> [ Log (Some "lpf user ") ]

let verdict_statement = function
  | Policy.Pass -> Accept
  | Policy.Block -> Drop
  | Policy.Reject -> Reject

let route_to_comment = function
  | None -> []
  | Some (gateway, None) -> [ "route-to=" ^ address_to_comment gateway ]
  | Some (gateway, Some (interface : Ir.interface_ref)) ->
      [
        "route-to=" ^ address_to_comment gateway ^ "(" ^ interface.device ^ ")";
      ]

let rule_comment ?anchor (rule : Ir.rule) =
  let location =
    match anchor with
    | None -> Printf.sprintf "lpf rule %d:%d" rule.span.line rule.span.column
    | Some name ->
        Printf.sprintf "lpf anchor %s rule %d:%d" name rule.span.line
          rule.span.column
  in
  let extras =
    (match rule.queue with None -> [] | Some queue -> [ "queue=" ^ queue ])
    @ route_to_comment rule.route_to
  in
  String.concat " " (location :: extras)

let compile_rule ?anchor (ir : Ir.t) (rule : Ir.rule) =
  let chain =
    match anchor with
    | None -> rule_chain rule.direction
    | Some name -> "anchor_" ^ sanitize_identifier name
  in
  let expressions =
    base_expressions ~chain_name:chain rule.protocol rule.source
      rule.destination rule.port rule.interface
  in
  let expressions =
    if rule.keep_state then
      expressions @ [ Ct_state [ "new"; "established"; "related" ] ]
    else expressions
  in
  let statements = log_statement rule.log @ [ verdict_statement rule.action ] in
  let statements =
    match rule.queue with
    | None -> statements
    | Some qname -> (
        match Tc.queue_classid ir.queues qname with
        | Some id -> Meta_priority_set id :: statements
        | None -> statements)
  in
  let statements =
    match rule.route_to with
    | None -> statements
    | Some target -> (
        match Routing.mark_for_target ir target with
        | Some mark -> Meta_mark_set mark :: statements
        | None -> statements)
  in
  {
    table = filter_table_name;
    chain;
    expressions;
    statements;
    comment = Some (rule_comment ?anchor rule);
  }

let nat_translation (nat : Ir.nat) =
  match nat.translation with
  | Ir.Literal value when nat.interface.name = Some value -> Masquerade
  | Ir.Literal value -> Snat value
  | Ir.Table name -> Snat ("@" ^ set_name name)
  | Ir.Any -> Masquerade

let compile_nat (nat : Ir.nat) =
  {
    table = nat_table_name;
    chain = "postrouting";
    expressions =
      base_expressions ~chain_name:"output" nat.protocol nat.source
        nat.destination Ir.Port_any (Some nat.interface);
    statements = [ nat_translation nat ];
    comment =
      Some (Printf.sprintf "lpf nat %d:%d" nat.span.line nat.span.column);
  }

let dnat_target (rdr : Ir.rdr) =
  let address =
    match address_to_nft rdr.translation with
    | None -> ""
    | Some address -> address
  in
  match port_to_nft rdr.translation_port with
  | None -> address
  | Some port -> address ^ ":" ^ port

let compile_rdr (rdr : Ir.rdr) =
  {
    table = nat_table_name;
    chain = "prerouting";
    expressions =
      base_expressions ~chain_name:"input" rdr.protocol rdr.source
        rdr.destination rdr.port (Some rdr.interface);
    statements = [ Dnat (dnat_target rdr) ];
    comment =
      Some (Printf.sprintf "lpf rdr %d:%d" rdr.span.line rdr.span.column);
  }

let anchor_chain (anchor : Ir.anchor) =
  {
    table = filter_table_name;
    name = "anchor_" ^ sanitize_identifier anchor.name;
    chain_type = None;
    hook = None;
    priority = None;
    policy = None;
  }

let table_refs_in_address = function Ir.Table name -> [ name ] | _ -> []

let nat_table_refs (ir : Ir.t) =
  let add refs name =
    if List.exists (String.equal name) refs then refs else name :: refs
  in
  let refs =
    List.fold_left
      (fun refs (nat : Ir.nat) ->
        table_refs_in_address nat.source
        @ table_refs_in_address nat.destination
        @ table_refs_in_address nat.translation
        |> List.fold_left add refs)
      [] ir.nats
  in
  List.fold_left
    (fun refs (rdr : Ir.rdr) ->
      table_refs_in_address rdr.source
      @ table_refs_in_address rdr.destination
      @ table_refs_in_address rdr.translation
      |> List.fold_left add refs)
    refs ir.rdrs

let of_ir (ir : Ir.t) =
  let filter_table = { family = Inet; name = filter_table_name } in
  let nat_needed = ir.nats <> [] || ir.rdrs <> [] in
  let nat_table = { family = Inet; name = nat_table_name } in
  let default_policy = policy_of_default ir.default_action in
  let base_filter_chain name hook =
    {
      table = filter_table_name;
      name;
      chain_type = Some Filter;
      hook = Some hook;
      priority = Some 0;
      policy = Some default_policy;
    }
  in
  let nat_chain name hook priority =
    {
      table = nat_table_name;
      name;
      chain_type = Some Nat;
      hook = Some hook;
      priority = Some priority;
      policy = Some Policy_accept;
    }
  in
  let tables =
    if nat_needed then [ filter_table; nat_table ] else [ filter_table ]
  in
  let chains =
    [
      base_filter_chain "input" Input;
      base_filter_chain "forward" Forward;
      base_filter_chain "output" Output;
    ]
    @ List.map anchor_chain ir.anchors
    @
    if nat_needed then
      [
        nat_chain "prerouting" Prerouting (-100);
        nat_chain "postrouting" Postrouting 100;
      ]
    else []
  in
  let anchor_rules =
    ir.anchors
    |> List.concat_map (fun (anchor : Ir.anchor) ->
           List.map (compile_rule ~anchor:anchor.name ir) anchor.rules)
  in

  {
    tables;
    chains;
    sets =
      List.map table_of_policy_table ir.tables
      @ (nat_table_refs ir
        |> List.filter_map (fun name ->
               List.find_opt
                 (fun (table : Ir.table) -> String.equal table.name name)
                 ir.tables)
        |> List.map (table_of_policy_table ~table_name:nat_table_name));
    rules =
      List.map (compile_rule ir) ir.rules
      @ anchor_rules
      @ List.map compile_nat ir.nats
      @ List.map compile_rdr ir.rdrs;
  }

let of_plan (plan : Plan.t) = of_ir plan.policy
let string_of_family = function Inet -> "inet" | Ip -> "ip"
let string_of_chain_type = function Filter -> "filter" | Nat -> "nat"

let string_of_hook = function
  | Input -> "input"
  | Forward -> "forward"
  | Output -> "output"
  | Prerouting -> "prerouting"
  | Postrouting -> "postrouting"

let string_of_policy = function
  | Policy_accept -> "accept"
  | Policy_drop -> "drop"

let nat_address_family target =
  if String.contains target ':' && not (String.contains target '.') then "ip6"
  else "ip"

let string_of_expression = function
  | Meta (key, value) -> "meta " ^ key ^ " " ^ value
  | Payload (protocol, field, value) -> protocol ^ " " ^ field ^ " " ^ value
  | Ct_state states -> "ct state " ^ String.concat "," states

let string_of_statement = function
  | Accept -> "accept"
  | Drop -> "drop"
  | Reject -> "reject"
  | Log None -> "log"
  | Log (Some prefix) -> "log prefix " ^ Json_util.string prefix
  | Snat address -> "snat " ^ nat_address_family address ^ " to " ^ address
  | Dnat target -> "dnat " ^ nat_address_family target ^ " to " ^ target
  | Masquerade -> "masquerade"
  | Meta_priority_set p -> "meta priority set " ^ p
  | Meta_mark_set m -> Printf.sprintf "meta mark set %d" m

let render_rule (rule : rule) =
  let parts =
    List.map string_of_expression rule.expressions
    @ List.map string_of_statement rule.statements
    @
    match rule.comment with
    | None -> []
    | Some comment -> [ "comment " ^ Json_util.string comment ]
  in
  "    " ^ String.concat " " parts

let render_set (set : set) =
  let lines =
    [ "  set " ^ set.name ^ " {"; "    type " ^ set.set_type ]
    @ (if set.flags = [] then []
       else [ "    flags " ^ String.concat ", " set.flags ])
    @ [ "    elements = { " ^ String.concat ", " set.elements ^ " }"; "  }" ]
  in
  String.concat "\n" lines

let render_chain (chains_rules : rule list) (chain : chain) =
  let header = "  chain " ^ chain.name ^ " {" in
  let base =
    match (chain.chain_type, chain.hook, chain.priority, chain.policy) with
    | Some chain_type, Some hook, Some priority, Some policy ->
        [
          Printf.sprintf "    type %s hook %s priority %d; policy %s;"
            (string_of_chain_type chain_type)
            (string_of_hook hook) priority (string_of_policy policy);
        ]
    | _ -> []
  in
  String.concat "\n"
    ((header :: base) @ List.map render_rule chains_rules @ [ "  }" ])

let render_table (nft : t) (table : table) =
  let table_sets =
    (nft : t).sets
    |> List.filter (fun (set : set) -> String.equal set.table table.name)
  in
  let table_chains =
    (nft : t).chains
    |> List.filter (fun (chain : chain) -> String.equal chain.table table.name)
  in
  let body =
    List.map render_set table_sets
    @ List.map
        (fun (chain : chain) ->
          let rules =
            (nft : t).rules
            |> List.filter (fun (rule : rule) ->
                   String.equal rule.table table.name
                   && String.equal rule.chain chain.name)
          in
          render_chain rules chain)
        table_chains
  in
  "table "
  ^ string_of_family table.family
  ^ " " ^ table.name ^ " {\n" ^ String.concat "\n\n" body ^ "\n}"

let to_string nft =
  "flush ruleset\n\n"
  ^ String.concat "\n\n" (List.map (render_table nft) nft.tables)
  ^ "\n"

let owned_table_names = [ filter_table_name; nat_table_name ]
let is_owned_table name = List.exists (String.equal name) owned_table_names

let words text =
  text |> String.trim |> String.split_on_char ' '
  |> List.filter (fun word -> not (String.equal word ""))

let owned_table_name_from_header line =
  match words line with
  | "table" :: _family :: name :: _ when is_owned_table name -> Some name
  | _ -> None

let owned_table_header_from_header line =
  match words line with
  | "table" :: family :: name :: _ when is_owned_table name ->
      Some (family, name)
  | _ -> None

let brace_delta line =
  let delta = ref 0 in
  String.iter (function '{' -> incr delta | '}' -> decr delta | _ -> ()) line;
  !delta

let extract_owned_tables text =
  let rec outside tables = function
    | [] -> List.rev tables
    | line :: rest -> (
        match owned_table_name_from_header line with
        | None -> outside tables rest
        | Some name ->
            let depth = brace_delta line in
            if depth <= 0 then outside ((name, line) :: tables) rest
            else inside tables name depth [ line ] rest)
  and inside tables name depth lines = function
    | [] -> List.rev ((name, String.concat "\n" (List.rev lines)) :: tables)
    | line :: rest ->
        let depth = depth + brace_delta line in
        let lines = line :: lines in
        if depth <= 0 then
          outside ((name, String.concat "\n" (List.rev lines)) :: tables) rest
        else inside tables name depth lines rest
  in
  outside [] (String.split_on_char '\n' text)

let owned_table_headers text =
  extract_owned_tables text
  |> List.filter_map (fun (_name, block) ->
         match String.split_on_char '\n' block with
         | header :: _ -> owned_table_header_from_header header
         | [] -> None)

let owned_ruleset_text text =
  let tables = extract_owned_tables text in
  let blocks =
    owned_table_names
    |> List.filter_map (fun name ->
           tables
           |> List.find_opt (fun (table_name, _) ->
                  String.equal table_name name)
           |> Option.map snd)
  in
  match blocks with [] -> "" | _ -> String.concat "\n\n" blocks ^ "\n"

let rollback_script ~current ~preimage =
  let deletes =
    owned_table_headers current
    |> List.map (fun (family, name) -> "delete table " ^ family ^ " " ^ name)
  in
  String.concat "\n" deletes
  ^ (if deletes = [] then "" else "\n")
  ^ preimage
  ^ if preimage = "" || String.ends_with ~suffix:"\n" preimage then "" else "\n"

let compress_spaces text =
  text |> String.split_on_char ' '
  |> List.filter (fun part -> not (String.equal part ""))
  |> String.concat " "

let normalize_state_list states =
  states |> String.split_on_char ',' |> List.sort String.compare
  |> String.concat ","

let replace_all ~pattern ~replacement text =
  let pattern_len = String.length pattern in
  if pattern_len = 0 then text
  else
    let buffer = Buffer.create (String.length text) in
    let rec loop index =
      if index >= String.length text then ()
      else if
        index + pattern_len <= String.length text
        && String.equal pattern (String.sub text index pattern_len)
      then (
        Buffer.add_string buffer replacement;
        loop (index + pattern_len))
      else (
        Buffer.add_char buffer text.[index];
        loop (index + 1))
    in
    loop 0;
    Buffer.contents buffer

let normalize_ct_state line =
  match String.split_on_char ' ' line with
  | parts ->
      let rec loop acc = function
        | "ct" :: "state" :: states :: rest ->
            List.rev_append acc
              ("ct" :: "state" :: normalize_state_list states :: rest)
        | part :: rest -> loop (part :: acc) rest
        | [] -> parts
      in
      loop [] parts |> String.concat " "

let normalize_hex_int_token token =
  if String.length token > 2 && String.sub token 0 2 = "0x" then
    match Int64.of_string_opt token with
    | Some value -> Int64.to_string value
    | None -> token
  else token

let normalize_mark_set line =
  let parts = String.split_on_char ' ' line in
  let rec loop acc = function
    | "meta" :: "mark" :: "set" :: value :: rest ->
        List.rev_append acc
          ("meta" :: "mark" :: "set" :: normalize_hex_int_token value :: rest)
    | part :: rest -> loop (part :: acc) rest
    | [] -> parts
  in
  loop [] parts |> String.concat " "

let normalize_elements_line line =
  match String.split_on_char '{' line with
  | [ prefix; rest ] when String.contains rest '}' ->
      let elements_text =
        match String.split_on_char '}' rest with
        | before :: _ -> before
        | [] -> rest
      in
      let elements =
        elements_text |> String.split_on_char ',' |> List.map String.trim
        |> List.filter (fun element -> not (String.equal element ""))
        |> List.sort String.compare
      in
      String.trim prefix ^ "{ " ^ String.concat ", " elements ^ " }"
  | _ -> line

let normalize_nft_line line =
  line |> String.trim |> compress_spaces
  |> replace_all ~pattern:"priority filter" ~replacement:"priority 0"
  |> replace_all ~pattern:"priority dstnat" ~replacement:"priority -100"
  |> replace_all ~pattern:"priority srcnat" ~replacement:"priority 100"
  |> replace_all ~pattern:"meta iifname" ~replacement:"iifname"
  |> replace_all ~pattern:"meta oifname" ~replacement:"oifname"
  |> replace_all ~pattern:"meta l4proto tcp " ~replacement:""
  |> replace_all ~pattern:"meta l4proto udp " ~replacement:""
  |> replace_all ~pattern:"meta l4proto icmp " ~replacement:""
  |> normalize_ct_state |> normalize_mark_set |> normalize_elements_line

let join_wrapped_elements lines =
  let rec loop acc pending = function
    | [] -> (
        match pending with
        | None -> List.rev acc
        | Some line -> List.rev (line :: acc))
    | line :: rest -> (
        let trimmed = String.trim line in
        if String.length trimmed = 0 then loop acc pending rest
        else
          match pending with
          | Some current ->
              let combined = current ^ " " ^ trimmed in
              if String.contains trimmed '}' then
                loop (combined :: acc) None rest
              else loop acc (Some combined) rest
          | None ->
              if
                String.contains trimmed '{'
                && (not (String.contains trimmed '}'))
                && String.contains trimmed '='
              then loop acc (Some trimmed) rest
              else loop (trimmed :: acc) None rest)
  in
  loop [] None lines

let normalized_owned_ruleset_text text =
  owned_ruleset_text text |> String.split_on_char '\n' |> join_wrapped_elements
  |> List.map normalize_nft_line
  |> List.filter (fun line -> not (String.equal line ""))
  |> String.concat "\n"

let split_lines text =
  let lines = String.split_on_char '\n' text in
  match List.rev lines with "" :: rest -> List.rev rest | _ -> lines

type diff_line = Context of string | Remove of string | Add of string

let diff_lines ~observed ~intended =
  let observed = Array.of_list (split_lines observed) in
  let intended = Array.of_list (split_lines intended) in
  let observed_count = Array.length observed in
  let intended_count = Array.length intended in
  let common = Array.make_matrix (observed_count + 1) (intended_count + 1) 0 in
  for i = observed_count - 1 downto 0 do
    for j = intended_count - 1 downto 0 do
      common.(i).(j) <-
        (if String.equal observed.(i) intended.(j) then
           common.(i + 1).(j + 1) + 1
         else max common.(i + 1).(j) common.(i).(j + 1))
    done
  done;
  let rec walk i j acc =
    if i = observed_count && j = intended_count then List.rev acc
    else if
      i < observed_count && j < intended_count
      && String.equal observed.(i) intended.(j)
    then walk (i + 1) (j + 1) (Context observed.(i) :: acc)
    else if
      i < observed_count
      && (j = intended_count || common.(i + 1).(j) >= common.(i).(j + 1))
    then walk (i + 1) j (Remove observed.(i) :: acc)
    else walk i (j + 1) (Add intended.(j) :: acc)
  in
  walk 0 0 []

let render_diff_line = function
  | Context line -> " " ^ line
  | Remove line -> "-" ^ line
  | Add line -> "+" ^ line

type diff_result = { changes_required : bool; text : string }

let diff ~intended ~observed =
  let intended = owned_ruleset_text intended in
  let observed = owned_ruleset_text observed in
  if
    String.equal intended observed
    || String.equal
         (normalized_owned_ruleset_text intended)
         (normalized_owned_ruleset_text observed)
  then { changes_required = false; text = "nftables diff: no changes\n" }
  else
    {
      changes_required = true;
      text =
        "nftables diff: changes required\n\
         --- observed lpf-owned nftables\n\
         +++ intended lpf-owned nftables\n"
        ^ String.concat "\n"
            (List.map render_diff_line (diff_lines ~observed ~intended))
        ^ "\n";
    }

let diff_text ~intended ~observed = (diff ~intended ~observed).text
let render_plan plan = plan |> of_plan |> to_string
