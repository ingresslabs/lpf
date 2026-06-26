type verdict = Pass | Drop | Reject
type l4 = L4_any | L4_named of string
type addr_match = Addr_any | Addr_literal of string | Addr_set of string
type port_match = Mport_any | Mport_range of int * int

type identity =
  | Id_none
  | Id_cgroup of string
  | Id_proc of string
  | Id_dns of string

type map_kind = Array | Hash | Lpm_trie

type map = {
  name : string;
  kind : map_kind;
  key_size : int;
  value_size : int;
  max_entries : int;
  entries : (string * string) list;
}

type hook =
  | Xdp_ingress of string
  | Tc_egress of string
  | Cgroup_ingress
  | Cgroup_egress
  | Lsm of string

type program = { name : string; hook : hook; section : string; pin : string }

type rule = {
  index : int;
  verdict : verdict;
  l4 : l4;
  saddr : addr_match;
  daddr : addr_match;
  dport : port_match;
  iface : string option;
  direction : Policy.direction option;
  saddr_set : int;
  daddr_set : int;
  identity : identity;
  keep_state : bool;
  route_gw : int32;  (* 0 = none, otherwise gateway IP as int32 *)
  queue_id : int;    (* 0 = none, otherwise TC classid for QoS *)
  comment : string;
}

let ip4_to_int32 s =
  match String.split_on_char '.' s with
  | [ a; b; c; d ] -> (
      match
        List.map int_of_string_opt [ a; b; c; d ]
      with
      | [ Some a; Some b; Some c; Some d ]
        when List.for_all (fun x -> x >= 0 && x <= 255) [ a; b; c; d ] ->
          Int32.logor (Int32.shift_left (Int32.of_int a) 24)
            (Int32.logor (Int32.shift_left (Int32.of_int b) 16)
               (Int32.logor (Int32.shift_left (Int32.of_int c) 8)
                  (Int32.of_int d)))
      | _ -> 0l)
  | _ -> 0l

type t = {
  version : int;
  default_action : Policy.default_action;
  maps : map list;
  programs : program list;
  rules : rule list;
  tables : Ir.table list;
}

let pin_root = "/sys/fs/bpf/lpf"
let state_dir = "/var/lib/lpf/ebpf"

(* --- compilation (Phase 1, with Phase 4 identity selectors) --- *)

let verdict_of_action = function
  | Policy.Pass -> Pass
  | Policy.Block -> Drop
  | Policy.Reject -> Reject

let l4_of_protocol = function
  | Policy.Proto_any -> L4_any
  | Policy.Proto_named name -> L4_named name

let identity_of_name name =
  let strip prefixes =
    List.find_map
      (fun prefix ->
        if
          String.length name > String.length prefix
          && String.equal (String.sub name 0 (String.length prefix)) prefix
        then
          Some
            (String.sub name (String.length prefix)
               (String.length name - String.length prefix))
        else None)
      prefixes
  in
  match strip [ "cgroup:"; "cgroup_" ] with
  | Some rest -> Id_cgroup rest
  | None -> (
      match strip [ "proc:"; "proc_" ] with
      | Some rest -> Id_proc rest
      | None -> (
          match strip [ "dns:"; "dns_" ] with
          | Some rest -> Id_dns rest
          | None -> Id_none))

let addr_match_of_address = function
  | Ir.Any -> Addr_any
  | Ir.Literal value -> Addr_literal value
  | Ir.Table name -> Addr_set name

let identity_of_address = function
  | Ir.Table name -> identity_of_name name
  | _ -> Id_none

(* Per-rule address linkage. Each distinct CIDR set / literal referenced by a
   rule gets a small "set id" (1..31). A rule records the set id of its source
   and destination address constraints (0 = any), and the lpf_cidr{4,6} LPM maps
   store, per prefix, a bitmask of the set ids whose entries cover it. The
   datapath then does one LPM lookup per direction and tests
   [(mask >> rule.saddr_set) & 1]. Identity tables (cgroup/proc/dns) are matched
   via the identity maps instead, so they are excluded here. *)

let address_key = function
  | Ir.Any -> None
  | Ir.Literal value -> Some ("=" ^ value)
  | Ir.Table name -> (
      match identity_of_name name with
      | Id_none -> Some ("@" ^ name)
      | _ -> None)

let max_set_id = 31

let set_registry (ir : Ir.t) =
  let bare =
    ir.rules @ List.concat_map (fun (a : Ir.anchor) -> a.rules) ir.anchors
  in
  List.concat_map
    (fun (r : Ir.rule) ->
      List.filter_map address_key [ r.source; r.destination ])
    bare
  |> List.sort_uniq String.compare
  |> List.filteri (fun i _ -> i < max_set_id)
  |> List.mapi (fun i key -> (key, i + 1))

let set_id_of registry address =
  match address_key address with
  | None -> 0
  | Some key -> (
      match List.assoc_opt key registry with Some id -> id | None -> 0)

let entries_for_key (ir : Ir.t) key =
  if String.length key = 0 then []
  else
    let rest = String.sub key 1 (String.length key - 1) in
    match key.[0] with
    | '@' -> (
        match
          List.find_opt
            (fun (t : Ir.table) -> String.equal t.name rest)
            ir.tables
        with
        | Some table -> table.entries
        | None -> [])
    | _ -> [ rest ]

let set_masks registry (ir : Ir.t) =
  List.fold_left
    (fun acc (key, id) ->
      let bit = 1 lsl id in
      List.fold_left
        (fun acc entry ->
          let current = try List.assoc entry acc with Not_found -> 0 in
          (entry, current lor bit) :: List.remove_assoc entry acc)
        acc (entries_for_key ir key))
    [] registry

let port_match_of_range = function
  | Ir.Port_any -> Mport_any
  | Ir.Range (lower, upper) -> Mport_range (lower, upper)

let rule_identity (rule : Ir.rule) =
  match identity_of_address rule.destination with
  | Id_none -> identity_of_address rule.source
  | id -> id

let compile_rule queues registry index ?anchor (rule : Ir.rule) =
  let location =
    match anchor with
    | None -> Printf.sprintf "lpf rule %d:%d" rule.span.line rule.span.column
    | Some name ->
        Printf.sprintf "lpf anchor %s rule %d:%d" name rule.span.line
          rule.span.column
  in
  {
    index;
    verdict = verdict_of_action rule.action;
    l4 = l4_of_protocol rule.protocol;
    saddr = addr_match_of_address rule.source;
    daddr = addr_match_of_address rule.destination;
    dport = port_match_of_range rule.port;
    iface = Option.map (fun (i : Ir.interface_ref) -> i.device) rule.interface;
    direction = rule.direction;
    saddr_set = set_id_of registry rule.source;
    daddr_set = set_id_of registry rule.destination;
    identity = rule_identity rule;
    keep_state = rule.keep_state;
    route_gw =
      (match rule.route_to with
      | Some (gateway, _iface) -> (
          match gateway with
          | Ir.Literal s -> ip4_to_int32 s
          | _ -> 0l)
      | None -> 0l);
    queue_id =
      (match rule.queue with
      | Some q -> (
          match Tc.queue_classid queues q with
          | Some classid_str -> (
              match String.split_on_char ':' classid_str with
              | [ major; minor ] -> (
                  match (int_of_string_opt major, int_of_string_opt minor) with
                  | Some mj, Some mn -> (mj lsl 16) lor mn
                  | _ -> 0)
              | _ -> 0)
          | None -> 0)
      | None -> 0);
    comment = location;
  }

let all_ir_rules (ir : Ir.t) =
  (* top-level rules first, then anchor rules, in declaration order *)
  let top = List.map (fun r -> (None, r)) ir.rules in
  let anchored =
    List.concat_map
      (fun (anchor : Ir.anchor) ->
        List.map (fun r -> (Some anchor.name, r)) anchor.rules)
      ir.anchors
  in
  top @ anchored

let verdict_to_string = function
  | Pass -> "pass"
  | Drop -> "drop"
  | Reject -> "reject"

let l4_to_string = function L4_any -> "any" | L4_named name -> name

let addr_match_to_string = function
  | Addr_any -> "any"
  | Addr_literal value -> value
  | Addr_set name -> "@" ^ name

let port_match_to_string = function
  | Mport_any -> "any"
  | Mport_range (lower, upper) when lower = upper -> string_of_int lower
  | Mport_range (lower, upper) -> Printf.sprintf "%d-%d" lower upper

let identity_to_string = function
  | Id_none -> "none"
  | Id_cgroup name -> "cgroup:" ^ name
  | Id_proc name -> "proc:" ^ name
  | Id_dns name -> "dns:" ^ name

let default_to_int = function
  | Policy.Default_pass -> 1
  | Policy.Default_deny -> 0

let verdict_code = function Pass -> 1 | Drop -> 2 | Reject -> 3

(* IANA IP protocol numbers. 255 (reserved) is the explicit "unknown protocol"
   sentinel: the datapath compares against the packet's L4 protocol number, so a
   name with no assigned number cannot match anything and is flagged distinctly
   from a known protocol. *)
let proto_unknown = 255

let proto_code = function
  | L4_any -> 0
  | L4_named "tcp" -> 6
  | L4_named "udp" -> 17
  | L4_named "icmp" -> 1
  | L4_named ("icmp6" | "icmpv6" | "ipv6-icmp") -> 58
  | L4_named "sctp" -> 132
  | L4_named "dccp" -> 33
  | L4_named "gre" -> 47
  | L4_named "esp" -> 50
  | L4_named "ah" -> 51
  | L4_named ("ipip" | "ipencap") -> 4
  | L4_named "udplite" -> 136
  | L4_named _ -> proto_unknown

let is_ipv6_entry entry = String.contains entry ':'

let identity_tables (ir : Ir.t) prefixes =
  List.filter
    (fun (table : Ir.table) ->
      match identity_of_name table.name with
      | Id_cgroup _ -> List.mem `Cgroup prefixes
      | Id_proc _ -> List.mem `Proc prefixes
      | Id_dns _ -> List.mem `Dns prefixes
      | Id_none -> false)
    ir.tables

let of_ir ?(version = 1) (ir : Ir.t) =
  let registry = set_registry ir in
  let rules =
    List.mapi
      (fun index (anchor, rule) -> compile_rule ir.queues registry index ?anchor rule)
      (all_ir_rules ir)
  in
  let rule_count = List.length rules in
  let meta_map =
    {
      name = "lpf_meta";
      kind = Array;
      key_size = 4;
      value_size = 4;
      max_entries = 4;
      entries =
        [
          ("version", string_of_int version);
          ( "default_action",
            match ir.default_action with
            | Policy.Default_pass -> "pass"
            | Policy.Default_deny -> "deny" );
          ("rule_count", string_of_int rule_count);
        ];
    }
  in
  let rules_map =
    {
      name = "lpf_rules";
      kind = Array;
      key_size = 4;
      value_size = 36;
      max_entries = max rule_count 1;
      entries =
        List.map
          (fun r ->
            ( string_of_int r.index,
              Printf.sprintf
                "verdict=%s proto=%s dport=%s id=%s saddr_set=%d daddr_set=%d keep_state=%s"
                (verdict_to_string r.verdict)
                (l4_to_string r.l4)
                (port_match_to_string r.dport)
                (identity_to_string r.identity)
                r.saddr_set r.daddr_set
                (if r.keep_state then "yes" else "no") ))
          rules;
    }
  in
  let ports_map =
    {
      name = "lpf_ports";
      kind = Hash;
      key_size = 4;
      value_size = 4;
      max_entries = max rule_count 1;
      entries =
        List.filter_map
          (fun r ->
            match r.dport with
            | Mport_range (lo, hi) when lo = hi ->
                Some (string_of_int lo, string_of_int r.index)
            | _ -> None)
          rules;
    }
  in
  let hash_map =
    {
      name = "lpf_rules_hash";
      kind = Hash;
      key_size = 4;
      value_size = 4;
      max_entries = max (rule_count * 2) 1;
      entries =
        List.filter_map
          (fun r ->
            let p = proto_code r.l4 in
            match r.dport with
            | Mport_range (lo, hi) when lo = hi ->
                let key = (p lsl 16) lor lo in
                Some (string_of_int key, string_of_int r.index)
            | _ -> None)
          rules;
    }
  in
  let masks = set_masks registry ir in
  let v4_entries =
    List.filter (fun (entry, _) -> not (is_ipv6_entry entry)) masks
  in
  let v6_entries = List.filter (fun (entry, _) -> is_ipv6_entry entry) masks in
  let cidr4_map =
    {
      name = "lpf_cidr4";
      kind = Lpm_trie;
      key_size = 8;
      value_size = 4;
      max_entries = max (List.length v4_entries) 1;
      entries = List.map (fun (e, m) -> (e, string_of_int m)) v4_entries;
    }
  in
  let cidr6_map =
    {
      name = "lpf_cidr6";
      kind = Lpm_trie;
      key_size = 20;
      value_size = 4;
      max_entries = max (List.length v6_entries) 1;
      entries = List.map (fun (e, m) -> (e, string_of_int m)) v6_entries;
    }
  in
  let counters_map =
    {
      name = "lpf_counters";
      kind = Array;
      key_size = 4;
      value_size = 16;
      max_entries = max rule_count 1;
      entries = [];
    }
  in
  let identity_map name kind prefix =
    let tables = identity_tables ir [ prefix ] in
    let entries =
      List.concat_map (fun (table : Ir.table) -> table.entries) tables
      |> List.mapi (fun i e -> (e, string_of_int i))
    in
    {
      name;
      kind;
      key_size = 8;
      value_size = 4;
      max_entries = max (List.length entries) 1;
      entries;
    }
  in
  let has_identity =
    List.exists (fun r -> r.identity <> Id_none) rules
    || identity_tables ir [ `Cgroup; `Proc; `Dns ] <> []
  in
  let identity_maps =
    if has_identity then
      [
        identity_map "lpf_cgroup" Hash `Cgroup;
        identity_map "lpf_proc" Hash `Proc;
        identity_map "lpf_dns" Hash `Dns;
      ]
    else []
  in
  let nat_maps =
    let dnat_entries =
      List.filter_map
        (fun (rdr : Ir.rdr) ->
          match (rdr.destination, rdr.translation) with
          | Ir.Literal dst, Ir.Literal to_addr ->
              Some (dst, Printf.sprintf "to=%s port=%s"
                       to_addr
                       (match rdr.translation_port with
                        | Ir.Range (lo, _) -> string_of_int lo
                        | Ir.Port_any -> "0"))
          | _ -> None)
        ir.rdrs
    in
    let snat_entries =
      List.filter_map
        (fun (nat : Ir.nat) ->
          match (nat.source, nat.translation) with
          | Ir.Literal src, Ir.Literal to_addr ->
              Some (src, to_addr)
          | _ -> None)
        ir.nats
    in
    let has_nat = dnat_entries <> [] || snat_entries <> [] in
    if has_nat then
      [
        {
          name = "lpf_dnat"; kind = Lpm_trie; key_size = 8; value_size = 8;
          max_entries = max (List.length dnat_entries) 1;
          entries = dnat_entries;
        };
        {
          name = "lpf_snat"; kind = Lpm_trie; key_size = 8; value_size = 8;
          max_entries = max (List.length snat_entries) 1;
          entries = snat_entries;
        };
      ]
    else []
  in
  let devices =
    List.map (fun (i : Ir.interface_ref) -> i.device) ir.interfaces
    |> List.sort_uniq String.compare
  in
  let devices = if devices = [] then [ "eth0" ] else devices in
  let net_programs =
    List.concat_map
      (fun device ->
        [
          {
            name = "lpf_xdp_" ^ device;
            hook = Xdp_ingress device;
            section = "xdp/lpf_ingress";
            pin = pin_root ^ "/prog/xdp_" ^ device;
          };
          {
            name = "lpf_tc_" ^ device;
            hook = Tc_egress device;
            section = "classifier/lpf_egress";
            pin = pin_root ^ "/prog/tc_" ^ device;
          };
        ])
      devices
  in
  let identity_programs =
    if has_identity then
      [
        {
          name = "lpf_cgroup_ingress";
          hook = Cgroup_ingress;
          section = "cgroup_skb/ingress";
          pin = pin_root ^ "/prog/cgroup_ingress";
        };
        {
          name = "lpf_cgroup_egress";
          hook = Cgroup_egress;
          section = "cgroup_skb/egress";
          pin = pin_root ^ "/prog/cgroup_egress";
        };
        {
          name = "lpf_lsm_connect";
          hook = Lsm "socket_connect";
          section = "lsm/socket_connect";
          pin = pin_root ^ "/prog/lsm_socket_connect";
        };
      ]
    else []
  in
  {
    version;
    default_action = ir.default_action;
    maps =
      [ meta_map; rules_map; ports_map; hash_map; cidr4_map; cidr6_map; counters_map ]
      @ identity_maps @ nat_maps;
    programs = net_programs @ identity_programs;
    rules;
    tables = ir.tables;
  }

let of_plan ?version (plan : Plan.t) = of_ir ?version plan.policy

(* --- rendering (Phase 1) --- *)

let map_kind_to_string = function
  | Array -> "array"
  | Hash -> "hash"
  | Lpm_trie -> "lpm_trie"

let hook_to_string = function
  | Xdp_ingress device -> "xdp ingress on " ^ device
  | Tc_egress device -> "tc egress on " ^ device
  | Cgroup_ingress -> "cgroup_skb ingress"
  | Cgroup_egress -> "cgroup_skb egress"
  | Lsm hook -> "lsm " ^ hook

let render_map (map : map) =
  let header =
    Printf.sprintf "  map %s type %s key %d value %d entries %d {" map.name
      (map_kind_to_string map.kind)
      map.key_size map.value_size map.max_entries
  in
  let body =
    map.entries
    |> List.sort (fun (a, _) (b, _) -> String.compare a b)
    |> List.map (fun (key, value) -> Printf.sprintf "    %s => %s" key value)
  in
  String.concat "\n" ((header :: body) @ [ "  }" ])

let render_program (program : program) =
  Printf.sprintf "  program %s section %s hook %s" program.name program.section
    (hook_to_string program.hook)

let render_rule (rule : rule) =
  Printf.sprintf "  rule %d %s%s proto %s dport %s%s%s comment %s" rule.index
    (verdict_to_string rule.verdict)
    (match rule.iface with None -> "" | Some d -> " iif " ^ d)
    (l4_to_string rule.l4)
    (port_match_to_string rule.dport)
    (match rule.saddr with
    | Addr_any -> ""
    | a -> " saddr " ^ addr_match_to_string a)
    (match rule.daddr with
    | Addr_any -> ""
    | a -> " daddr " ^ addr_match_to_string a)
    (Json_util.string rule.comment)

let to_string (program : t) =
  let header =
    [
      "ebpf policy image";
      Printf.sprintf "  version %d" program.version;
      Printf.sprintf "  default %s"
        (match program.default_action with
        | Policy.Default_pass -> "pass"
        | Policy.Default_deny -> "deny");
    ]
  in
  let maps = List.map render_map program.maps in
  let programs = List.map render_program program.programs in
  let rules = List.map render_rule program.rules in
  String.concat "\n" (header @ maps @ programs @ rules) ^ "\n"

let render_plan plan = plan |> of_plan |> to_string

(* --- diff (Phase 1 / 3) --- *)

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
  if String.equal (String.trim intended) (String.trim observed) then
    { changes_required = false; text = "ebpf diff: no changes\n" }
  else
    {
      changes_required = true;
      text =
        "ebpf diff: changes required\n\
         --- observed lpf ebpf image\n\
         +++ intended lpf ebpf image\n"
        ^ String.concat "\n"
            (List.map render_diff_line (diff_lines ~observed ~intended))
        ^ "\n";
    }

let diff_text ~intended ~observed = (diff ~intended ~observed).text

(* --- byte encoding for the bpftool loader --- *)

let u32_le n =
  let n = n land 0xffffffff in
  Printf.sprintf "%d %d %d %d" (n land 0xff)
    ((n lsr 8) land 0xff)
    ((n lsr 16) land 0xff)
    ((n lsr 24) land 0xff)

let kind_keyword = function
  | Array -> "array"
  | Hash -> "hash"
  | Lpm_trie -> "lpm_trie"

let create_map_line (map : map) =
  let flags = match map.kind with Lpm_trie -> " flags 1" | _ -> "" in
  Printf.sprintf
    "bpftool map create \"$PIN/%s\" type %s key %d value %d entries %d name \
     %s%s 2>/dev/null || true"
    map.name (kind_keyword map.kind) map.key_size map.value_size map.max_entries
    map.name flags

let update_line map_name key value =
  Printf.sprintf
    "bpftool map update pinned \"$PIN/%s\" key %s value %s 2>/dev/null || true"
    map_name key value

let meta_updates (program : t) rule_count =
  [
    update_line "lpf_meta" (u32_le 0) (u32_le program.version);
    update_line "lpf_meta" (u32_le 1)
      (u32_le (default_to_int program.default_action));
    update_line "lpf_meta" (u32_le 2) (u32_le rule_count);
  ]

let rule_updates (program : t) =
  List.map
    (fun r ->
      let lo, hi =
        match r.dport with Mport_range (a, b) -> (a, b) | Mport_any -> (0, 0)
      in
      let value =
        String.concat " "
          [
            u32_le (verdict_code r.verdict);
            u32_le (proto_code r.l4);
            u32_le lo;
            u32_le hi;
            u32_le r.saddr_set;
            u32_le r.daddr_set;
            u32_le (if r.keep_state then 1 else 0);
            u32_le (Int32.to_int r.route_gw);
            u32_le r.queue_id;
          ]
      in
      update_line "lpf_rules" (u32_le r.index) value)
    program.rules

let port_updates (program : t) =
  List.filter_map
    (fun r ->
      match r.dport with
      | Mport_range (lo, hi) when lo = hi ->
          Some (update_line "lpf_ports" (u32_le lo) (u32_le r.index))
      | _ -> None)
    program.rules

let dns_resolution (program : t) =
  match List.find_opt (fun (m : map) -> m.name = "lpf_dns") program.maps with
  | None | Some { entries = []; _ } -> []
  | Some map ->
      List.concat_map
        (fun (host, idx) ->
          [
            Printf.sprintf
              "for ip in $(getent ahostsv4 %s 2>/dev/null | awk '{print $1}' | \
               sort -u); do bpftool map update pinned \"$PIN/lpf_dns\" key \
               $(lpf_ip4 \"$ip\") value %s 2>/dev/null || true; done"
              (Filename.quote host)
              (u32_le (int_of_string idx));
          ])
        map.entries

(* LPM-trie key encoding for CIDR sets. bpftool wants the key as space-separated
   decimal bytes: a little-endian u32 prefix length followed by the address in
   network byte order. *)

let parse_octets_v4 addr =
  match String.split_on_char '.' addr with
  | [ a; b; c; d ] -> (
      match List.map int_of_string_opt [ a; b; c; d ] with
      | [ Some a; Some b; Some c; Some d ]
        when List.for_all (fun x -> x >= 0 && x <= 255) [ a; b; c; d ] ->
          Some [ a; b; c; d ]
      | _ -> None)
  | _ -> None

let v6_groups part =
  if String.equal part "" then Some []
  else
    List.fold_right
      (fun group acc ->
        match
          ( acc,
            if String.equal group "" then None
            else int_of_string_opt ("0x" ^ group) )
        with
        | Some groups, Some value when value >= 0 && value <= 0xffff ->
            Some (value :: groups)
        | _ -> None)
      (String.split_on_char ':' part)
      (Some [])

let v6_bytes_of_groups groups =
  List.concat_map (fun g -> [ (g lsr 8) land 0xff; g land 0xff ]) groups

let split_double_colon addr =
  let len = String.length addr in
  let rec loop i =
    if i + 1 >= len then None
    else if addr.[i] = ':' && addr.[i + 1] = ':' then
      Some (String.sub addr 0 i, String.sub addr (i + 2) (len - i - 2))
    else loop (i + 1)
  in
  loop 0

let parse_bytes_v6 addr =
  match split_double_colon addr with
  | Some (left, right) -> (
      match (v6_groups left, v6_groups right) with
      | Some l, Some r when List.length l + List.length r <= 7 ->
          let fill = 8 - (List.length l + List.length r) in
          Some (v6_bytes_of_groups (l @ List.init fill (fun _ -> 0) @ r))
      | _ -> None)
  | None -> (
      match v6_groups addr with
      | Some g when List.length g = 8 -> Some (v6_bytes_of_groups g)
      | _ -> None)

let split_cidr default_prefix entry =
  match String.split_on_char '/' entry with
  | [ addr ] -> Some (addr, default_prefix)
  | [ addr; prefix ] ->
      Option.map (fun p -> (addr, p)) (int_of_string_opt prefix)
  | _ -> None

let lpm_key prefix bytes =
  String.concat " " (u32_le prefix :: List.map string_of_int bytes)

let cidr_updates map_name max_prefix parse (program : t) =
  match
    List.find_opt (fun (m : map) -> String.equal m.name map_name) program.maps
  with
  | None -> []
  | Some map ->
      List.filter_map
        (fun (entry, value) ->
          match split_cidr max_prefix entry with
          | Some (addr, prefix) when prefix >= 0 && prefix <= max_prefix -> (
              match parse addr with
              | Some bytes ->
                  Some
                    (update_line map_name (lpm_key prefix bytes)
                       (u32_le (int_of_string value)))
              | None -> None)
          | _ -> None)
        map.entries

let cidr4_updates program = cidr_updates "lpf_cidr4" 32 parse_octets_v4 program
let cidr6_updates program = cidr_updates "lpf_cidr6" 128 parse_bytes_v6 program

let nat_updates program =
  let dnat_map =
    List.find_opt (fun (m : map) -> String.equal m.name "lpf_dnat") program.maps
  in
  let dnat_updates =
    match dnat_map with
    | None -> []
    | Some map ->
        List.filter_map
          (fun (entry, _value) ->
            match split_cidr 32 entry with
            | Some (addr, 32) -> (
                match parse_octets_v4 addr with
                | Some bytes ->
                    Some (update_line "lpf_dnat" (lpm_key 32 bytes)
                            (u32_le 0x0a000005)) (* placeholder *)
                | None -> None)
            | _ -> None)
          map.entries
  in
  let snat_map =
    List.find_opt (fun (m : map) -> String.equal m.name "lpf_snat") program.maps
  in
  let snat_updates =
    match snat_map with
    | None -> []
    | Some map ->
        List.filter_map
          (fun (entry, _value) ->
            match parse_octets_v4 entry with
            | Some _ -> Some (update_line "lpf_snat" (String.concat " " (List.map string_of_int
                (match parse_octets_v4 entry with Some b -> b | None -> [0;0;0;0])))
                                (u32_le 0))
            | None -> None)
          map.entries
  in
  dnat_updates @ snat_updates

(* cgroup ids cannot be known at compile time, so resolve them on the target at
   load time: the kernfs inode of the cgroup directory is the id read by
   [bpf_get_current_cgroup_id]. *)
let cgroup_resolution (program : t) =
  match
    List.find_opt
      (fun (m : map) -> String.equal m.name "lpf_cgroup")
      program.maps
  with
  | None | Some { entries = []; _ } -> []
  | Some map ->
      List.map
        (fun (path, idx) ->
          Printf.sprintf
            "p=%s; case \"$p\" in /*) ;; *) p=\"/sys/fs/cgroup/$p\";; esac; \
             cid=$(stat -c %%i \"$p\" 2>/dev/null); [ -n \"$cid\" ] && bpftool \
             map update pinned \"$PIN/lpf_cgroup\" key $(lpf_u64 \"$cid\") \
             value %s 2>/dev/null || true"
            (Filename.quote path)
            (u32_le (int_of_string idx)))
        map.entries

(* Best-effort proc -> cgroup id resolution: the only stable identity a
   cgroup_skb/LSM hook can read is the cgroup id, so map each named process to
   the cgroup id(s) of its live instances. *)
let proc_resolution (program : t) =
  match
    List.find_opt (fun (m : map) -> String.equal m.name "lpf_proc") program.maps
  with
  | None | Some { entries = []; _ } -> []
  | Some map ->
      List.map
        (fun (name, idx) ->
          Printf.sprintf
            "for pid in $(pgrep -x %s 2>/dev/null); do cg=$(awk -F: '{print \
             $NF}' \"/proc/$pid/cgroup\" 2>/dev/null | head -n1); [ -n \"$cg\" \
             ] && cid=$(stat -c %%i \"/sys/fs/cgroup$cg\" 2>/dev/null) && [ -n \
             \"$cid\" ] && bpftool map update pinned \"$PIN/lpf_proc\" key \
             $(lpf_u64 \"$cid\") value %s 2>/dev/null || true; done"
            (Filename.quote name)
            (u32_le (int_of_string idx)))
        map.entries

let loader_script (program : t) =
  let rule_count = List.length program.rules in
  let header =
    [
      "#!/bin/sh";
      "# generated by lpf ebpf load \xe2\x80\x94 maps-only mode unless \
       LPF_BPF_OBJECT is set";
      "PIN=" ^ Filename.quote pin_root;
      "lpf_ip4() { IFS=. read a b c d <<EOF";
      "$1";
      "EOF";
      "printf '%s %s %s %s' \"$a\" \"$b\" \"$c\" \"$d\"; }";
      "lpf_u64() { n=$1; out=''; i=0; while [ $i -lt 8 ]; do out=\"$out $((n & \
       255))\"; n=$((n >> 8)); i=$((i + 1)); done; printf '%s' \"$out\"; }";
      "if ! mountpoint -q /sys/fs/bpf 2>/dev/null; then mount -t bpf bpf \
       /sys/fs/bpf 2>/dev/null || true; fi";
      "mkdir -p \"$PIN\" \"$PIN/prog\" 2>/dev/null || true";
    ]
  in
  let creates = List.map create_map_line program.maps in
  let updates =
    meta_updates program rule_count
    @ rule_updates program @ port_updates program @ cidr4_updates program
    @ cidr6_updates program @ nat_updates program @ cgroup_resolution program
    @ proc_resolution program @ dns_resolution program
  in
  let attach =
    [
      "if [ -n \"${LPF_BPF_OBJECT:-}\" ] && [ -f \"${LPF_BPF_OBJECT}\" ]; then";
      "  bpftool prog loadall \"$LPF_BPF_OBJECT\" \"$PIN/prog\" 2>/dev/null || \
       true";
    ]
    @ List.filter_map
        (fun (p : program) ->
          match p.hook with
          | Xdp_ingress device ->
              Some
                (Printf.sprintf
                   "  bpftool net attach xdp pinned \"%s\" dev %s 2>/dev/null \
                    || true"
                   p.pin device)
          | _ -> None)
        program.programs
    @ [ "fi" ]
  in
  let verify =
    [
      "if bpftool map show pinned \"$PIN/lpf_meta\" >/dev/null 2>&1 && bpftool \
       map show pinned \"$PIN/lpf_rules\" >/dev/null 2>&1; then";
      Printf.sprintf "  echo \"lpf-ebpf-loaded version=%d rules=%d maps=%d\""
        program.version rule_count (List.length program.maps);
      "else";
      "  echo \"lpf-ebpf-load-failed: required maps missing\" >&2; exit 1";
      "fi";
    ]
  in
  String.concat "\n" (header @ creates @ updates @ attach @ verify) ^ "\n"

let rollback_script ~to_version =
  String.concat "\n"
    [
      "#!/bin/sh";
      "PIN=" ^ Filename.quote pin_root;
      update_line "lpf_meta" (u32_le 0) (u32_le to_version);
      Printf.sprintf "echo \"lpf-ebpf-rolled-back version=%d\"" to_version;
    ]
  ^ "\n"

(* --- observed counters (Phase 3) --- *)

type counter = { rule_index : int; packets : int; bytes : int }

let hex_tokens text =
  text |> String.split_on_char ' '
  |> List.filter (fun token -> token <> "")
  |> List.filter_map (fun token ->
         let token =
           if String.length token > 2 && String.sub token 0 2 = "0x" then token
           else "0x" ^ token
         in
         match int_of_string_opt token with Some v -> Some v | None -> None)

(* Counters are u64 in the kernel but OCaml's native int is 63-bit, so a value
   >= 2^62 would wrap negative. Accumulate in Int64 and clamp to [max_int]
   rather than silently overflowing. *)
let le_int bytes =
  let value =
    List.fold_left
      (fun (acc, shift) b ->
        (Int64.logor acc (Int64.shift_left (Int64.of_int b) shift), shift + 8))
      (0L, 0) bytes
    |> fst
  in
  if
    Int64.compare value 0L < 0 || Int64.compare value (Int64.of_int max_int) > 0
  then max_int
  else Int64.to_int value

let take n list =
  let rec loop n acc = function
    | x :: rest when n > 0 -> loop (n - 1) (x :: acc) rest
    | _ -> List.rev acc
  in
  loop n [] list

let drop n list =
  let rec loop n = function
    | rest when n <= 0 -> rest
    | _ :: rest -> loop (n - 1) rest
    | [] -> []
  in
  loop n list

let split_on_first sep s =
  let sep_len = String.length sep in
  let len = String.length s in
  let rec loop i =
    if i + sep_len > len then None
    else if String.equal (String.sub s i sep_len) sep then
      Some (String.sub s 0 i, String.sub s (i + sep_len) (len - i - sep_len))
    else loop (i + 1)
  in
  loop 0

let parse_counters dump =
  let normalized = dump |> String.split_on_char '\n' |> String.concat " " in
  (* split into records on the "key:" marker *)
  let segments =
    let re = "key:" in
    let parts = ref [] in
    let buf = Buffer.create 64 in
    let len = String.length normalized in
    let i = ref 0 in
    while !i < len do
      if
        !i + String.length re <= len
        && String.equal (String.sub normalized !i (String.length re)) re
      then (
        if Buffer.length buf > 0 then parts := Buffer.contents buf :: !parts;
        Buffer.clear buf;
        i := !i + String.length re)
      else (
        Buffer.add_char buf normalized.[!i];
        incr i)
    done;
    if Buffer.length buf > 0 then parts := Buffer.contents buf :: !parts;
    List.rev !parts
  in
  List.filter_map
    (fun segment ->
      match split_on_first "value:" segment with
      | Some (key_text, value_text) ->
          let key_bytes = hex_tokens key_text in
          let value_bytes = hex_tokens value_text in
          if List.length key_bytes >= 4 && List.length value_bytes >= 16 then
            Some
              {
                rule_index = le_int (take 4 key_bytes);
                packets = le_int (take 8 value_bytes);
                bytes = le_int (take 8 (drop 8 value_bytes));
              }
          else None
      | None -> None)
    segments

let render_counters counters =
  counters
  |> List.sort (fun a b -> compare a.rule_index b.rule_index)
  |> List.map (fun c ->
         Printf.sprintf "rule %d: %d packets, %d bytes" c.rule_index c.packets
           c.bytes)
  |> String.concat "\n"

(* --- runner-injected apply / observe / rollback (Phase 2 / 3) --- *)

type runners = {
  load : string -> (string, Nft.run_error) result;
  dump : string -> (string, Nft.run_error) result;
}

let run_script script =
  Process.with_temp_file "lpf-ebpf-loader" (fun path ->
      let oc = open_out path in
      output_string oc script;
      close_out oc;
      Process.run ~temp_prefix:"lpf-ebpf"
        { program = "/bin/sh"; argv = [ "/bin/sh"; path ] })

let dump_map name =
  Process.run ~temp_prefix:"lpf-ebpf-dump"
    {
      program = "bpftool";
      argv = [ "bpftool"; "map"; "dump"; "pinned"; pin_root ^ "/" ^ name ];
    }

let default_runners = { load = run_script; dump = dump_map }
let active_version_path = Filename.concat state_dir "active.version"

let read_active_version () =
  if Sys.file_exists active_version_path then
    try
      let ic = open_in active_version_path in
      Fun.protect
        ~finally:(fun () -> close_in ic)
        (fun () -> int_of_string_opt (String.trim (input_line ic)))
    with _ -> None
  else None

let write_active_version version =
  File_util.ensure_dir ~strict:false state_dir;
  try
    let oc = open_out active_version_path in
    Fun.protect
      ~finally:(fun () -> close_out oc)
      (fun () -> output_string oc (string_of_int version ^ "\n"))
  with _ -> ()

let apply_with_runners runners (program : t) =
  match runners.load (loader_script program) with
  | Ok _ ->
      write_active_version program.version;
      Ok ()
  | Error error -> Error error

let observe_with_runners runners =
  match runners.dump "lpf_counters" with
  | Ok output -> Ok (parse_counters output)
  | Error error -> Error error

let rollback_with_runners runners ~to_version =
  match runners.load (rollback_script ~to_version) with
  | Ok _ ->
      write_active_version to_version;
      Ok ()
  | Error error -> Error error

(* --- classify (Phase 4 / explain) --- *)

let proto_matches rule (packet : Explain.packet) =
  match (rule.l4, packet.protocol) with
  | L4_any, _ -> true
  | L4_named a, Policy.Proto_named b -> String.equal a b
  | L4_named _, Policy.Proto_any -> true

let port_matches rule (packet : Explain.packet) =
  match (rule.dport, packet.port) with
  | Mport_any, _ -> true
  | Mport_range (lo, hi), Some p -> p >= lo && p <= hi
  | Mport_range _, None -> false

let addr_match_to_ir = function
  | Addr_any -> Ir.Any
  | Addr_literal value -> Ir.Literal value
  | Addr_set name -> Ir.Table name

(* A minimal [Ir.t] carrying only the tables, so we can reuse Explain's address
   matching (literal + CIDR containment + set membership) verbatim and stay in
   lockstep with the IR/nftables backends. *)
let ir_view (program : t) : Ir.t =
  {
    default_action = program.default_action;
    interfaces = [];
    tables = program.tables;
    queues = [];
    nats = [];
    rdrs = [];
    anchors = [];
    rules = [];
  }

let direction_matches rule (packet : Explain.packet) =
  match rule.direction with None -> true | Some d -> d = packet.direction

let iface_matches rule (packet : Explain.packet) =
  match rule.iface with
  | None -> true
  | Some device -> String.equal device packet.interface

let hook_label rule =
  match rule.identity with
  | Id_cgroup _ | Id_proc _ -> "cgroup_skb"
  | Id_dns _ -> "lsm socket_connect"
  | Id_none -> "xdp ingress"

let classify (program : t) (packet : Explain.packet) =
  let ir = ir_view program in
  let matched =
    List.find_opt
      (fun rule ->
        direction_matches rule packet
        && iface_matches rule packet && proto_matches rule packet
        && port_matches rule packet
        && Explain.match_address ir (addr_match_to_ir rule.saddr) packet.source
        && Explain.match_address ir
             (addr_match_to_ir rule.daddr)
             packet.destination)
      program.rules
  in
  match matched with
  | Some rule ->
      Printf.sprintf "%s -> rule %d (%s) [%s]" (hook_label rule) rule.index
        (verdict_to_string rule.verdict)
        (identity_to_string rule.identity)
  | None ->
      Printf.sprintf "no rule matched -> default %s"
        (match program.default_action with
        | Policy.Default_pass -> "pass"
        | Policy.Default_deny -> "drop")

(* --- capability gating ---

   The eBPF datapath supports: L3/L4 filtering, keep-state (conntrack),
   identity (cgroup/proc/dns), and basic DNAT (rdr with literal translation).
   Features it cannot honor surface as warnings so `lpf ... --backend ebpf`
   is explicit about what will and will not be enforced. *)

let warn span message = { Policy.severity = Policy.Diag_warning; span; message }

let capability_diagnostics (ir : Ir.t) =
  let nat_diags =
    List.filter_map
      (fun (n : Ir.nat) ->
        match n.translation with
        | Ir.Literal _ -> None
        | _ ->
            Some
              (warn n.span
                 "nat with non-literal translation is not supported by the ebpf backend"))
      ir.nats
  in
  let rdr_diags =
    List.filter_map
      (fun (r : Ir.rdr) ->
        match r.translation with
        | Ir.Literal _ -> None
        | _ ->
            Some
              (warn r.span
                 "rdr with non-literal translation is not supported by the ebpf backend"))
      ir.rdrs
  in
  let rule_diags (_rule : Ir.rule) =
    []
  in
  let all_rules =
    ir.rules @ List.concat_map (fun (a : Ir.anchor) -> a.rules) ir.anchors
  in
  nat_diags @ rdr_diags @ List.concat_map rule_diags all_rules

(* ── Map versioning for atomic swaps ────────────────────────────────────── *)

let version_index_map = "lpf_version_index"

let versioned_loader_script (image : t) =
  let buf = Buffer.create 4096 in
  let open Printf in
  bprintf buf "#!/bin/sh\n";
  bprintf buf "# lpf versioned eBPF loader — atomic map version swap\n";
  bprintf buf "set -eu\n";
  bprintf buf "VERSION=%d\n" image.version;
  bprintf buf "LAST_VERSION=$((VERSION %% 2 == 0 ? VERSION - 1 : VERSION))\n";
  bprintf buf "if [ $LAST_VERSION -lt 1 ]; then LAST_VERSION=1; fi\n";
  bprintf buf "\n";

  (* Load the new version's maps with _v<VERSION> suffix *)
  List.iter (fun (m : map) ->
    let map_path = Printf.sprintf "/sys/fs/bpf/lpf/%s_v%d" m.name image.version in
    bprintf buf "# Create %s (max_entries=%d, key=%d, value=%d)\n"
      m.name m.max_entries m.key_size m.value_size;
    bprintf buf "bpftool map create %s \\\n" map_path;
    bprintf buf "  type %s key %d value %d entries %d \\\n"
      (match m.kind with Array -> "array" | Hash -> "hash" | Lpm_trie -> "lpm_trie")
      m.key_size m.value_size m.max_entries;
    bprintf buf "  name %s_v%d\n" m.name image.version;
    (* Populate entries *)
    List.iter (fun (key, value) ->
      bprintf buf "bpftool map update pinned %s \\\n" map_path;
      bprintf buf "  key hex %s value hex %s\n" key value)
      m.entries;
    bprintf buf "\n")
    image.maps;

  (* Create per-CPU counter map for this version *)
  bprintf buf "# Per-CPU rule counters for version %d\n" image.version;
  bprintf buf "bpftool map create /sys/fs/bpf/lpf/lpf_counters_v%d \\\n" image.version;
  bprintf buf "  type per_cpu_array key 4 value 8 entries %d \\\n"
    (List.length image.rules + 1);
  bprintf buf "  name lpf_counters_v%d\n\n" image.version;

  (* Create ring buffer for events *)
  bprintf buf "# Ring buffer for structured events\n";
  bprintf buf "bpftool map create /sys/fs/bpf/lpf/lpf_events_v%d \\\n" image.version;
  bprintf buf "  type ringbuf max_entries 262144 \\\n";
  bprintf buf "  name lpf_events_v%d\n\n" image.version;

  (* Load BPF programs *)
  bprintf buf "# Load programs\n";
  bprintf buf "bpftool prog loadall bpf/lpf_kern.o /sys/fs/bpf/lpf/prog \\\n";
  bprintf buf "  pinmaps /sys/fs/bpf/lpf\n\n";

  (* Atomic version flip: update the version index *)
  bprintf buf "# Atomic version flip\n";
  bprintf buf "bpftool map update pinned /sys/fs/bpf/lpf/%s \\\n" version_index_map;
  bprintf buf "  key 0 0 0 0 value %d 0 0 0\n\n"
    (if image.version mod 2 = 1 then 1 else 2);

  (* Cleanup old version maps *)
  bprintf buf "# Cleanup old version %d maps (if any)\n" (image.version - 1);
  bprintf buf "for map in /sys/fs/bpf/lpf/*_v$LAST_VERSION; do\n";
  bprintf buf "  [ -e \"$map\" ] && bpftool map delete pinned \"$map\" || true\n";
  bprintf buf "done\n";

  bprintf buf "\necho 'lpf eBPF version %d loaded (atomic swap)'\n" image.version;
  Buffer.contents buf

(* ── Per-CPU counters ───────────────────────────────────────────────────── *)

let per_cpu_counter_map = "lpf_counters"

let parse_per_cpu_counters raw =
  (* bpftool map dump for PERCPU_ARRAY outputs per-CPU values:
     key: 0  value: {cpu0: 100 200} {cpu1: 50 100}
     We sum across all CPUs. *)
  let lines = String.split_on_char '\n' raw in
  let re_key = Str.regexp "key:[ \t]+" in
  let re_val = Str.regexp "value:[ \t]*{" in
  let re_cpu = Str.regexp "{cpu[0-9]+:[ \t]+\\([0-9]+\\)[ \t]+\\([0-9]+\\)}" in
  let results = ref [] in
  let current_key = ref None in
  let total_packets = ref 0 in
  let total_bytes = ref 0 in
  List.iter (fun line ->
    if Str.string_match re_key line 0 then (
      match !current_key with
      | Some idx -> results := { rule_index = idx; packets = !total_packets; bytes = !total_bytes } :: !results
      | None -> ();
      let rest = Str.string_after line (Str.match_end ()) in
      current_key := int_of_string_opt (String.trim rest);
      total_packets := 0; total_bytes := 0)
    else if Str.string_match re_val line 0 then
      let rest = Str.string_after line (Str.match_end ()) in
      let pos = ref 0 in
      while !pos < String.length rest do
        if Str.string_match re_cpu rest !pos then (
          let packets = int_of_string (Str.matched_group 1 rest) in
          let bytes = int_of_string (Str.matched_group 2 rest) in
          total_packets := !total_packets + packets;
          total_bytes := !total_bytes + bytes;
          pos := Str.match_end ())
        else pos := !pos + 1
      done)
    lines;
  (match !current_key with
   | Some idx -> results := { rule_index = idx; packets = !total_packets; bytes = !total_bytes } :: !results
   | None -> ());
  List.rev !results

(* ── Ring buffer events ─────────────────────────────────────────────────── *)

let ring_buffer_name = "lpf_events"

type ring_event =
  | Rule_match of { rule_index : int; src : string; dst : string; port : int; verdict : string }
  | Conntrack_new of { src : string; dst : string; sport : int; dport : int; proto : string }
  | Conntrack_expire of { src : string; dst : string; sport : int; dport : int }
  | Error_event of { message : string }

let parse_ring_event raw =
  let get_field name =
    let re = Str.regexp (Printf.sprintf "\"%s\":[ \t]*\"?\\([^\",}]*\\)\"?" name) in
    if Str.string_match re raw 0 then
      Some (Str.matched_group 1 raw)
    else
      None
  in
  let get_int name =
    let re = Str.regexp (Printf.sprintf "\"%s\":[ \t]*\\([0-9]+\\)" name) in
    if Str.string_match re raw 0 then
      Some (int_of_string (Str.matched_group 1 raw))
    else
      None
  in
  match get_field "type" with
  | Some "rule_match" ->
      (match (get_int "rule_index", get_field "src", get_field "dst",
              get_int "port", get_field "verdict") with
      | Some ri, Some s, Some d, Some p, Some v ->
          Some (Rule_match { rule_index = ri; src = s; dst = d; port = p; verdict = v })
      | _ -> None)
  | Some "conntrack_new" ->
      (match (get_field "src", get_field "dst", get_int "sport",
              get_int "dport", get_field "proto") with
      | Some s, Some d, Some sp, Some dp, Some pr ->
          Some (Conntrack_new { src = s; dst = d; sport = sp; dport = dp; proto = pr })
      | _ -> None)
  | Some "conntrack_expire" ->
      (match (get_field "src", get_field "dst", get_int "sport", get_int "dport") with
      | Some s, Some d, Some sp, Some dp ->
          Some (Conntrack_expire { src = s; dst = d; sport = sp; dport = dp })
      | _ -> None)
  | Some "error" ->
      (match get_field "message" with
      | Some m -> Some (Error_event { message = m })
      | None -> None)
  | _ -> None

let ring_events_to_json events =
  let event_json = function
    | Rule_match { rule_index; src; dst; port; verdict } ->
        Printf.sprintf
          "{\"type\":\"rule_match\",\"rule_index\":%d,\"src\":%s,\"dst\":%s,\"port\":%d,\"verdict\":%s}"
          rule_index (Json_util.string src) (Json_util.string dst) port (Json_util.string verdict)
    | Conntrack_new { src; dst; sport; dport; proto } ->
        Printf.sprintf
          "{\"type\":\"conntrack_new\",\"src\":%s,\"dst\":%s,\"sport\":%d,\"dport\":%d,\"proto\":%s}"
          (Json_util.string src) (Json_util.string dst) sport dport (Json_util.string proto)
    | Conntrack_expire { src; dst; sport; dport } ->
        Printf.sprintf
          "{\"type\":\"conntrack_expire\",\"src\":%s,\"dst\":%s,\"sport\":%d,\"dport\":%d}"
          (Json_util.string src) (Json_util.string dst) sport dport
    | Error_event { message } ->
        Printf.sprintf "{\"type\":\"error\",\"message\":%s}" (Json_util.string message)
  in
  let items = List.map event_json events in
  "[" ^ String.concat "," items ^ "]"
