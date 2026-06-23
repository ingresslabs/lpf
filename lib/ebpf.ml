type verdict = Pass | Drop | Reject
type l4 = L4_any | L4_named of string
type addr_match = Addr_any | Addr_literal of string | Addr_set of string
type port_match = Mport_any | Mport_range of int * int
type identity = Id_none | Id_cgroup of string | Id_proc of string | Id_dns of string
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
  identity : identity;
  comment : string;
}

type t = {
  version : int;
  default_action : Policy.default_action;
  maps : map list;
  programs : program list;
  rules : rule list;
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
        if String.length name > String.length prefix
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

let port_match_of_range = function
  | Ir.Port_any -> Mport_any
  | Ir.Range (lower, upper) -> Mport_range (lower, upper)

let rule_identity (rule : Ir.rule) =
  match identity_of_address rule.destination with
  | Id_none -> identity_of_address rule.source
  | id -> id

let compile_rule index ?anchor (rule : Ir.rule) =
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
    identity = rule_identity rule;
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
  | Mport_range (lower, upper) ->
      Printf.sprintf "%d-%d" lower upper

let identity_to_string = function
  | Id_none -> "none"
  | Id_cgroup name -> "cgroup:" ^ name
  | Id_proc name -> "proc:" ^ name
  | Id_dns name -> "dns:" ^ name

let default_to_int = function
  | Policy.Default_pass -> 1
  | Policy.Default_deny -> 0

let verdict_code = function Pass -> 1 | Drop -> 2 | Reject -> 3

let proto_code = function
  | L4_any -> 0
  | L4_named "tcp" -> 6
  | L4_named "udp" -> 17
  | L4_named "icmp" -> 1
  | L4_named "icmp6" -> 58
  | L4_named _ -> 255

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

let plain_tables (ir : Ir.t) =
  List.filter
    (fun (table : Ir.table) ->
      match identity_of_name table.name with Id_none -> true | _ -> false)
    ir.tables

let of_ir ?(version = 1) (ir : Ir.t) =
  let rules =
    List.mapi
      (fun index (anchor, rule) -> compile_rule index ?anchor rule)
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
            (match ir.default_action with
            | Policy.Default_pass -> "pass"
            | Policy.Default_deny -> "deny") );
          ("rule_count", string_of_int rule_count);
        ];
    }
  in
  let rules_map =
    {
      name = "lpf_rules";
      kind = Array;
      key_size = 4;
      value_size = 16;
      max_entries = max rule_count 1;
      entries =
        List.map
          (fun r ->
            ( string_of_int r.index,
              Printf.sprintf "verdict=%s proto=%s dport=%s id=%s"
                (verdict_to_string r.verdict)
                (l4_to_string r.l4)
                (port_match_to_string r.dport)
                (identity_to_string r.identity) ))
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
  let plain = plain_tables ir in
  let v4_entries =
    List.concat_map
      (fun (table : Ir.table) ->
        List.filter (fun e -> not (is_ipv6_entry e)) table.entries)
      plain
  in
  let v6_entries =
    List.concat_map
      (fun (table : Ir.table) ->
        List.filter is_ipv6_entry table.entries)
      plain
  in
  let cidr4_map =
    {
      name = "lpf_cidr4";
      kind = Lpm_trie;
      key_size = 8;
      value_size = 4;
      max_entries = max (List.length v4_entries) 1;
      entries = List.map (fun e -> (e, "1")) v4_entries;
    }
  in
  let cidr6_map =
    {
      name = "lpf_cidr6";
      kind = Lpm_trie;
      key_size = 20;
      value_size = 4;
      max_entries = max (List.length v6_entries) 1;
      entries = List.map (fun e -> (e, "1")) v6_entries;
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
    { name; kind; key_size = 8; value_size = 4; max_entries = max (List.length entries) 1; entries }
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
      [ meta_map; rules_map; ports_map; cidr4_map; cidr6_map; counters_map ]
      @ identity_maps;
    programs = net_programs @ identity_programs;
    rules;
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
      (map_kind_to_string map.kind) map.key_size map.value_size map.max_entries
  in
  let body =
    map.entries
    |> List.sort (fun (a, _) (b, _) -> String.compare a b)
    |> List.map (fun (key, value) ->
           Printf.sprintf "    %s => %s" key value)
  in
  String.concat "\n" ((header :: body) @ [ "  }" ])

let render_program (program : program) =
  Printf.sprintf "  program %s section %s hook %s" program.name
    program.section
    (hook_to_string program.hook)

let render_rule (rule : rule) =
  Printf.sprintf "  rule %d %s%s proto %s dport %s%s%s comment %s" rule.index
    (verdict_to_string rule.verdict)
    (match rule.iface with None -> "" | Some d -> " iif " ^ d)
    (l4_to_string rule.l4)
    (port_match_to_string rule.dport)
    (match rule.saddr with Addr_any -> "" | a -> " saddr " ^ addr_match_to_string a)
    (match rule.daddr with Addr_any -> "" | a -> " daddr " ^ addr_match_to_string a)
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
    "bpftool map create \"$PIN/%s\" type %s key %d value %d entries %d name %s%s 2>/dev/null || true"
    map.name (kind_keyword map.kind) map.key_size map.value_size
    map.max_entries map.name flags

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
              "for ip in $(getent ahostsv4 %s 2>/dev/null | awk '{print $1}' \
               | sort -u); do bpftool map update pinned \"$PIN/lpf_dns\" key \
               $(lpf_ip4 \"$ip\") value %s 2>/dev/null || true; done"
              (Filename.quote host) (u32_le (int_of_string idx));
          ])
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
      "if ! mountpoint -q /sys/fs/bpf 2>/dev/null; then mount -t bpf bpf \
       /sys/fs/bpf 2>/dev/null || true; fi";
      "mkdir -p \"$PIN\" \"$PIN/prog\" 2>/dev/null || true";
    ]
  in
  let creates = List.map create_map_line program.maps in
  let updates =
    meta_updates program rule_count
    @ rule_updates program @ port_updates program @ dns_resolution program
  in
  let attach =
    [
      "if [ -n \"${LPF_BPF_OBJECT:-}\" ] && [ -f \"${LPF_BPF_OBJECT}\" ]; then";
      "  bpftool prog loadall \"$LPF_BPF_OBJECT\" \"$PIN/prog\" \
       2>/dev/null || true";
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
      Printf.sprintf
        "  echo \"lpf-ebpf-loaded version=%d rules=%d maps=%d\"" program.version
        rule_count (List.length program.maps);
      "else";
      "  echo \"lpf-ebpf-load-failed: required maps missing\" >&2; exit 1";
      "fi";
    ]
  in
  String.concat "\n"
    (header @ creates @ updates @ attach @ verify) ^ "\n"

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
  text
  |> String.split_on_char ' '
  |> List.filter (fun token -> token <> "")
  |> List.filter_map (fun token ->
         let token =
           if String.length token > 2 && String.sub token 0 2 = "0x" then token
           else "0x" ^ token
         in
         match int_of_string_opt token with Some v -> Some v | None -> None)

let le_int bytes =
  List.fold_left (fun (acc, shift) b -> (acc lor (b lsl shift), shift + 8)) (0, 0) bytes
  |> fst

let take n list =
  let rec loop n acc = function
    | x :: rest when n > 0 -> loop (n - 1) (x :: acc) rest
    | _ -> List.rev acc
  in
  loop n [] list

let drop n list =
  let rec loop n = function rest when n <= 0 -> rest | _ :: rest -> loop (n - 1) rest | [] -> [] in
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
  let normalized =
    dump |> String.split_on_char '\n' |> String.concat " "
  in
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
  (try if not (Sys.file_exists state_dir) then Unix.mkdir state_dir 0o755
   with _ -> ());
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

let addr_matches matcher value =
  match matcher with
  | Addr_any -> true
  | Addr_set _ -> true
  | Addr_literal literal -> String.equal literal value

let hook_label rule =
  match rule.identity with
  | Id_cgroup _ | Id_proc _ -> "cgroup_skb"
  | Id_dns _ -> "lsm socket_connect"
  | Id_none -> "xdp ingress"

let classify (program : t) (packet : Explain.packet) =
  let matched =
    List.find_opt
      (fun rule ->
        proto_matches rule packet && port_matches rule packet
        && addr_matches rule.saddr packet.source
        && addr_matches rule.daddr packet.destination)
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
