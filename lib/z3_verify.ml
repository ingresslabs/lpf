open Policy
open Ir

(* ── Z3 context (single shared, lazily created) ─────────────────────────── *)

let ctx = lazy (Z3.mk_context [])
let ctxt () = Lazy.force ctx

(* ── Sorts ──────────────────────────────────────────────────────────────── *)

let bool_sort = lazy (Z3.Boolean.mk_sort (ctxt ()))
let bv32_sort = lazy (Z3.BitVector.mk_sort (ctxt ()) 32)
let bv16_sort = lazy (Z3.BitVector.mk_sort (ctxt ()) 16)

(* Symbolic enums for protocol and interface *)
let mk_enum_sort name values =
  let c = ctxt () in
  let syms = List.map (fun v -> Z3.Symbol.mk_string c v) values in
  let sorts = List.map (fun _ -> Z3.EnumSort.mk_constructor_s c "c" (Z3.Symbol.mk_string c "c") [] (Some 0)) values in
  let sort = Z3.EnumSort.mk_sort_s c (Z3.Symbol.mk_string c name) syms sorts in
  (sort, syms)

let proto_names = [ "tcp"; "udp"; "icmp"; "any" ]
let proto_sort, proto_syms =
  lazy (mk_enum_sort "protocol" proto_names)
let proto_sort_val () = fst (Lazy.force proto_sort)
let proto_tcp () = Z3.Expr.mk_const_s (ctxt ()) (snd (Lazy.force proto_sort) |> List.hd) (proto_sort_val ())
let proto_udp () = Z3.Expr.mk_const_s (ctxt ()) (List.nth (snd (Lazy.force proto_sort)) 1) (proto_sort_val ())
let proto_icmp () = Z3.Expr.mk_const_s (ctxt ()) (List.nth (snd (Lazy.force proto_sort)) 2) (proto_sort_val ())
let proto_any_val () = Z3.Expr.mk_const_s (ctxt ()) (List.nth (snd (Lazy.force proto_sort)) 3) (proto_sort_val ())

(* ── Z3 expression helpers ──────────────────────────────────────────────── *)

let i32_to_z3 n =
  Z3.BitVector.mk_numeral (ctxt ()) (Int32.to_string n) 32

let mk_true () = Z3.Boolean.mk_true (ctxt ())
let mk_false () = Z3.Boolean.mk_false (ctxt ())
let mk_eq a b = Z3.Boolean.mk_eq (ctxt ()) a b
let mk_not a = Z3.Boolean.mk_not (ctxt ()) a
let mk_and a b = Z3.Boolean.mk_and (ctxt ()) [| a; b |]
let mk_or a b = Z3.Boolean.mk_or (ctxt ()) [| a; b |]
let mk_implies a b = Z3.Boolean.mk_implies (ctxt ()) a b
let mk_bv_uge a b = Z3.BitVector.mk_uge (ctxt ()) a b
let mk_bv_ule a b = Z3.BitVector.mk_ule (ctxt ()) a b
let mk_bv_eq a b = mk_eq a b
let mk_all_of xs = List.fold_left mk_and (mk_true ()) xs
let mk_any_of xs = List.fold_left mk_or (mk_false ()) xs

(* ── IP helpers ──────────────────────────────────────────────────────────── *)

let ip4_to_int32 s =
  match String.split_on_char '.' s with
  | [ a; b; c; d ] -> (
      match ( int_of_string_opt a, int_of_string_opt b,
              int_of_string_opt c, int_of_string_opt d ) with
      | Some a, Some b, Some c, Some d ->
          Int32.logor
            (Int32.shift_left (Int32.of_int a) 24)
            (Int32.logor
               (Int32.shift_left (Int32.of_int b) 16)
               (Int32.logor (Int32.shift_left (Int32.of_int c) 8)
                  (Int32.of_int d)))
      | _ -> 0l)
  | _ -> 0l

let ip4_cidr_low_high cidr =
  match String.split_on_char '/' cidr with
  | [ net; plen ] -> (
      match int_of_string_opt plen with
      | Some plen when plen >= 0 && plen <= 32 ->
          let net_int = ip4_to_int32 net in
          let host = 32 - plen in
          let mask =
            if plen = 0 then 0l
            else Int32.shift_right_logical 0xffffffffl host
          in
          let low = Int32.logand net_int mask in
          let high =
            if host = 0 then low
            else Int32.add low (Int32.sub (Int32.shift_left 1l host) 1l)
          in
          Some (low, high)
      | _ -> None)
  | _ -> None

let int32_to_ip4_str n =
  Printf.sprintf "%ld.%ld.%ld.%ld"
    (Int32.shift_right_logical n 24)
    (Int32.logand (Int32.shift_right_logical n 16) 0xffl)
    (Int32.logand (Int32.shift_right_logical n 8) 0xffl)
    (Int32.logand n 0xffl)

(* ── Symbolic packet ────────────────────────────────────────────────────── *)

type sym_packet = {
  pkt_dir : Z3.Expr.expr;
  pkt_src : Z3.Expr.expr;
  pkt_dst : Z3.Expr.expr;
  pkt_port : Z3.Expr.expr;
  pkt_proto : Z3.Expr.expr;
  pkt_iface : Z3.Expr.expr;  (* integer index into iface list *)
}

let iface_names (ir : Ir.t) =
  let names =
    ir.interfaces |> List.map (fun i -> i.device)
    |> List.sort_uniq String.compare
  in
  if names = [] then [ "eth0" ] else names

let mk_sym_packet (ir : Ir.t) =
  let c = ctxt () in
  let src = Z3.Expr.mk_const_s c (Z3.Symbol.mk_string c "pkt_src") (Lazy.force bv32_sort) in
  let dst = Z3.Expr.mk_const_s c (Z3.Symbol.mk_string c "pkt_dst") (Lazy.force bv32_sort) in
  let port = Z3.Expr.mk_const_s c (Z3.Symbol.mk_string c "pkt_port") (Lazy.force bv16_sort) in
  let dir = Z3.Expr.mk_const_s c (Z3.Symbol.mk_string c "pkt_dir") (Lazy.force bool_sort) in
  let proto = Z3.Expr.mk_const_s c (Z3.Symbol.mk_string c "pkt_proto") (proto_sort_val ()) in
  let iface = Z3.Expr.mk_const_s c (Z3.Symbol.mk_string c "pkt_iface") (Z3.Arithmetic.Integer.mk_sort c) in
  { pkt_dir = dir; pkt_src = src; pkt_dst = dst; pkt_port = port;
    pkt_proto = proto; pkt_iface = iface }

(* ── Address encoding (supports Any, Literal, Table with CIDR) ──────────── *)

let encode_address (ir : Ir.t) (var : Z3.Expr.expr) (addr : address) =
  match addr with
  | Any -> mk_true ()
  | Literal s -> mk_bv_eq var (i32_to_z3 (ip4_to_int32 s))
  | Table name -> (
      match List.find_opt (fun (t : table) -> String.equal t.name name) ir.tables with
      | None -> mk_false ()
      | Some t ->
          let entries = t.entries in
          let constraints =
            List.filter_map (fun entry ->
              if String.contains entry '/' then
                match ip4_cidr_low_high entry with
                | Some (low, high) ->
                    Some (mk_all_of [ mk_bv_uge var (i32_to_z3 low);
                                     mk_bv_ule var (i32_to_z3 high) ])
                | None -> None
              else
                Some (mk_bv_eq var (i32_to_z3 (ip4_to_int32 entry))))
              entries
          in
          mk_any_of constraints)

(* ── Port encoding ──────────────────────────────────────────────────────── *)

let encode_port (var : Z3.Expr.expr) (range : port_range) =
  match range with
  | Port_any -> mk_true ()
  | Range (low, high) ->
      mk_all_of [
        Z3.BitVector.mk_uge (ctxt ()) var (Z3.BitVector.mk_numeral (ctxt ()) (string_of_int low) 16);
        Z3.BitVector.mk_ule (ctxt ()) var (Z3.BitVector.mk_numeral (ctxt ()) (string_of_int high) 16);
      ]

(* ── Direction encoding ─────────────────────────────────────────────────── *)

let encode_direction (dir_var : Z3.Expr.expr) (rule_dir : direction option) =
  match rule_dir with
  | None -> mk_true ()
  | Some In -> dir_var  (* true = out, false = in *)
  | Some Out -> Z3.Boolean.mk_not (ctxt ()) dir_var

(* ── Protocol encoding ──────────────────────────────────────────────────── *)

let encode_protocol (proto_var : Z3.Expr.expr) (rule_proto : protocol) =
  match rule_proto with
  | Proto_any -> mk_true ()
  | Proto_named "tcp" -> mk_eq proto_var (proto_tcp ())
  | Proto_named "udp" -> mk_eq proto_var (proto_udp ())
  | Proto_named "icmp" -> mk_eq proto_var (proto_icmp ())
  | Proto_named _ -> mk_true ()

(* ── Interface encoding (as integer index into sorted device list) ───────── *)

let iface_index (ir : Ir.t) (device : string) =
  let names = iface_names ir in
  match List.find_index (fun d -> String.equal d device) names with
  | Some i -> i
  | None -> 0

let encode_interface (ir : Ir.t) (iface_var : Z3.Expr.expr) (rule_iface : interface_ref option) =
  match rule_iface with
  | None -> mk_true ()
  | Some i ->
      let idx = iface_index ir i.device in
      mk_eq iface_var
        (Z3.Arithmetic.Integer.mk_numeral_i (ctxt ()) idx)

(* ── Full rule match ────────────────────────────────────────────────────── *)

let encode_rule_match (ir : Ir.t) (sp : sym_packet) (rule : rule) =
  let conds = [
    encode_direction sp.pkt_dir rule.direction;
    encode_interface ir sp.pkt_iface rule.interface;
    encode_protocol sp.pkt_proto rule.protocol;
    encode_address ir sp.pkt_src rule.source;
    encode_address ir sp.pkt_dst rule.destination;
    encode_port sp.pkt_port rule.port;
  ] in
  mk_all_of conds

(* ── NAT match (post-routing, outbound) ──────────────────────────────────── *)

let encode_nat_match (ir : Ir.t) (sp : sym_packet) (nat : nat) =
  Z3.Boolean.mk_not (ctxt ()) sp.pkt_dir  (* Out = false in dir encoding, so NOT dir means Out *)
  |> ignore;
  (* NAT fires for outbound traffic on matching interface *)
  let conds = [
    mk_eq sp.pkt_dir (Z3.Boolean.mk_true (ctxt ()));  (* true = out in our encoding *)
    encode_interface ir sp.pkt_iface (Some nat.interface);
    encode_protocol sp.pkt_proto nat.protocol;
    encode_address ir sp.pkt_src nat.source;
    encode_address ir sp.pkt_dst nat.destination;
  ] in
  (* NAT means: src is rewritten to nat.translation.
     We encode this as: post-NAT src = translation *)
  let nat_src = Z3.Expr.mk_const_s (ctxt ()) (Z3.Symbol.mk_string (ctxt ()) "nat_src") (Lazy.force bv32_sort) in
  let match_expr = mk_all_of conds in
  let trans_expr =
    match nat.translation with
    | Literal s -> mk_bv_eq nat_src (i32_to_z3 (ip4_to_int32 s))
    | _ -> mk_bv_eq nat_src sp.pkt_src  (* no translation if non-literal *)
  in
  Some (match_expr, trans_expr, nat_src)

(* ── RDR match (pre-routing, inbound) ───────────────────────────────────── *)

let encode_rdr_match (ir : Ir.t) (sp : sym_packet) (rdr : rdr) =
  let conds = [
    Z3.Boolean.mk_not (ctxt ()) sp.pkt_dir;  (* false = in *)
    encode_interface ir sp.pkt_iface (Some rdr.interface);
    encode_protocol sp.pkt_proto rdr.protocol;
    encode_address ir sp.pkt_dst rdr.destination;
    encode_port sp.pkt_port rdr.port;
  ] in
  let rdr_dst = Z3.Expr.mk_const_s (ctxt ()) (Z3.Symbol.mk_string (ctxt ()) "rdr_dst") (Lazy.force bv32_sort) in
  let match_expr = mk_all_of conds in
  let trans_expr =
    match rdr.translation with
    | Literal s -> mk_bv_eq rdr_dst (i32_to_z3 (ip4_to_int32 s))
    | _ -> mk_bv_eq rdr_dst sp.pkt_dst
  in
  Some (match_expr, trans_expr, rdr_dst)

(* ── Decision tree encoding ────────────────────────────────────────────────

   Rules are ordered. Rule R_i fires iff: (¬R₀ ∧ ¬R₁ ∧ ... ∧ ¬R_{i-1}) ∧ R_i
   After RDR rewrites destination, rules match against rewritten address.
   After NAT rewrites source, packets have translated source.
   Default action fires if no rule matches.

   We encode the full decision tree as a function:
     decision(pkt) = first_matching_rule(pkt).action
*)

type symbolic_policy = {
  sp : sym_packet;
  rules : (Z3.Expr.expr * Ir.action * int) list;  (* (matches, action, line_number) *)
  default_action : Ir.action;
  nats : (Z3.Expr.expr * Z3.Expr.expr) list;  (* (matches, translation_constraint) pairs *)
  rdrs : (Z3.Expr.expr * Z3.Expr.expr) list;  (* (matches, translation_constraint) pairs *)
}

let encode_policy (ir : Ir.t) =
  let sp = mk_sym_packet ir in
  let all_rules =
    List.concat_map (fun (a : anchor) -> a.rules) ir.anchors @ ir.rules
  in
  let encoded_rules =
    List.map (fun rule ->
      (encode_rule_match ir sp rule, rule.action, rule.span.line))
      all_rules
  in
  let nats =
    List.filter_map (fun nat ->
      match encode_nat_match ir sp nat with
      | Some (m, t, _) -> Some (m, t)
      | None -> None)
      ir.nats
  in
  let rdrs =
    List.filter_map (fun rdr ->
      match encode_rdr_match ir sp rdr with
      | Some (m, t, _) -> Some (m, t)
      | None -> None)
      ir.rdrs
  in
  { sp; rules = encoded_rules;
    default_action = (match ir.default_action with Default_pass -> Pass | Default_deny -> Block);
    nats; rdrs }

(* Build the decision function.
   Returns (pass, block, matching_rule_line) as Z3 expressions.
   pass = ∃ rule with pass action that matches (and all prior don't).
   block = similarly.
   line = the line number of the first matching rule (or -1 for default). *)

let encode_decision (pol : symbolic_policy) =
  let rec fold_rules seen_not (line_var : Z3.Expr.expr) = function
    | [] ->
        (* Default action *)
        (match pol.default_action with
         | Pass -> (mk_true (), mk_false (), line_var)
         | Block -> (mk_false (), mk_true (), line_var)
         | Reject -> (mk_false (), mk_false (), line_var))
    | (matches, action, line) :: rest ->
        let cond = mk_and seen_not matches in
        let line_val = Z3.Arithmetic.Integer.mk_numeral_i (ctxt ()) line in
        let then_pass, then_block, then_line =
          match action with
          | Pass -> (mk_true (), mk_false (), line_val)
          | Block -> (mk_false (), mk_true (), line_val)
          | Reject -> (mk_false (), mk_false (), line_val)
        in
        let else_pass, else_block, else_line =
          fold_rules (mk_and seen_not (mk_not matches)) line_var rest
        in
        ( mk_or (mk_and cond then_pass) (mk_and (mk_not cond) else_pass),
          mk_or (mk_and cond then_block) (mk_and (mk_not cond) else_block),
          (* line: if cond then line_val else rest_line.
             Encode via: (cond ∧ line = line_val) ∨ (¬cond ∧ line = else_line) *)
          let new_line_var = Z3.Expr.mk_const_s (ctxt ())
            (Z3.Symbol.mk_string (ctxt ()) "rule_line") (Z3.Arithmetic.Integer.mk_sort (ctxt ())) in
          (* This is simplified — we only care about pass/block for the decision.
             For counterexample extraction, we use the solver model directly. *)
          line_val
        )
  in
  let line_var = Z3.Expr.mk_const_s (ctxt ())
    (Z3.Symbol.mk_string (ctxt ()) "matched_line") (Z3.Arithmetic.Integer.mk_sort (ctxt ())) in
  let pass, block, matched_line = fold_rules (mk_true ()) line_var pol.rules in
  (pass, block)

(* ── Solver helpers ─────────────────────────────────────────────────────── *)

let mk_solver () = Z3.Solver.mk_solver (ctxt ()) None

let check_sat solver =
  match Z3.Solver.check (ctxt ()) solver with
  | Z3.Solver.SATISFIABLE -> true
  | _ -> false

let get_model solver = Z3.Solver.get_model (ctxt ()) solver

let model_get_bool model expr =
  match Z3.Model.get_const_interp_e (ctxt ()) model expr with
  | Some v -> Z3.Boolean.is_true (ctxt ()) v
  | None -> false

let model_get_int model expr =
  match Z3.Model.get_const_interp_e (ctxt ()) model expr with
  | Some v -> (
      try Some (int_of_string (Z3.Expr.get_numeral_string v))
      with _ -> None)
  | None -> None

let model_get_ip4 model expr =
  match Z3.Model.get_const_interp_e (ctxt ()) model expr with
  | None -> "0.0.0.0"
  | Some v ->
      try int32_to_ip4_str (Int32.of_string (Z3.Expr.get_numeral_string v))
      with _ -> "0.0.0.0"

let model_get_port model expr =
  match Z3.Model.get_const_interp_e (ctxt ()) model expr with
  | None -> None
  | Some v -> int_of_string_opt (Z3.Expr.get_numeral_string v)

let model_get_proto model expr =
  match Z3.Model.get_const_interp_e (ctxt ()) model expr with
  | None -> "any"
  | Some v ->
      let s = Z3.Expr.to_string v in
      if String.contains s '0' then "any"
      else if String.contains s '1' then "tcp"
      else if String.contains s '2' then "udp"
      else if String.contains s '3' then "icmp"
      else "any"

let model_get_iface (ir : Ir.t) model expr =
  let names = iface_names ir in
  match model_get_int model expr with
  | Some idx when idx >= 0 && idx < List.length names -> List.nth names idx
  | _ -> "eth0"

let model_to_ce (ir : Ir.t) sp model decision =
  let dir_bool = model_get_bool model sp.pkt_dir in
  {
    direction = (if dir_bool then "out" else "in");
    interface = model_get_iface ir model sp.pkt_iface;
    protocol = model_get_proto model sp.pkt_proto;
    source = model_get_ip4 model sp.pkt_src;
    destination = model_get_ip4 model sp.pkt_dst;
    port = model_get_port model sp.pkt_port;
    decision = (match decision with Pass -> "pass" | Block -> "block" | Reject -> "reject");
    matched_rule_line = None;
    nat_applied = None;
    rdr_applied = None;
  }

(* ── Find which rule matched the packet in the model ────────────────────── *)

let match_rule_concrete (ir : Ir.t) (rule : rule) (pkt : Explain.packet) =
  let dir_ok = match rule.direction with None -> true | Some d -> d = pkt.direction in
  let iface_ok = match rule.interface with None -> true | Some i -> String.equal i.device pkt.interface in
  let proto_ok = match rule.protocol with
    | Proto_any -> true
    | Proto_named n -> (match pkt.protocol with Proto_any -> false | Proto_named pn -> String.equal n pn)
  in
  let src_ok = match rule.source with
    | Any -> true
    | Literal s -> String.equal s pkt.source
    | Table name -> (
        match List.find_opt (fun (t : table) -> String.equal t.name name) ir.tables with
        | None -> false
        | Some t -> List.exists (fun entry ->
            String.equal entry pkt.source || (
              match ip4_cidr_low_high entry with
              | Some (low, high) ->
                  let pkt_int = ip4_to_int32 pkt.source in
                  Int32.compare pkt_int low >= 0 && Int32.compare pkt_int high <= 0
              | None -> false))
            t.entries)
  in
  let dst_ok = match rule.destination with
    | Any -> true
    | Literal s -> String.equal s pkt.destination
    | Table name -> (
        match List.find_opt (fun (t : table) -> String.equal t.name name) ir.tables with
        | None -> false
        | Some t -> List.exists (fun entry ->
            String.equal entry pkt.destination || (
              match ip4_cidr_low_high entry with
              | Some (low, high) ->
                  let pkt_int = ip4_to_int32 pkt.destination in
                  Int32.compare pkt_int low >= 0 && Int32.compare pkt_int high <= 0
              | None -> false))
            t.entries)
  in
  let port_ok = match rule.port with
    | Port_any -> true
    | Range (low, high) -> (
        match pkt.port with Some p -> p >= low && p <= high | None -> false)
  in
  dir_ok && iface_ok && proto_ok && src_ok && dst_ok && port_ok

(* ── Find which rule matched in the model ────────────────────────────────── *)

let find_matching_rule_line (ir : Ir.t) sp model =
  let all_rules =
    List.concat_map (fun (a : anchor) -> a.rules) ir.anchors @ ir.rules
  in
  let src = model_get_ip4 model sp.pkt_src in
  let dst = model_get_ip4 model sp.pkt_dst in
  let port = model_get_port model sp.pkt_port in
  let pkt : Explain.packet = {
    direction = (if model_get_bool model sp.pkt_dir then Out else In);
    interface = model_get_iface ir model sp.pkt_iface;
    protocol = (match model_get_proto model sp.pkt_proto with
                | "tcp" -> Proto_named "tcp" | "udp" -> Proto_named "udp"
                | "icmp" -> Proto_named "icmp" | _ -> Proto_any);
    source = src; destination = dst; port = port;
  } in
  let rec find_first = function
    | [] -> None
    | r :: rest -> if match_rule_concrete ir r pkt then Some r.span.line else find_first rest
  in
  find_first all_rules

(* ── Public API ─────────────────────────────────────────────────────────── *)

let check_consistency (ir : Ir.t) =
  let pol = encode_policy ir in
  let solver = mk_solver () in
  let result = ref [] in
  let rec check_rules seen_not idx = function
    | [] -> ()
    | (matches, action, line) :: rest ->
        let fires = mk_and seen_not matches in
        Z3.Solver.push (ctxt ()) solver;
        Z3.Solver.add (ctxt ()) solver [ fires ];
        if not (check_sat solver) then
          result := { line; action = (match action with
                       | Pass -> "pass" | Block -> "block" | Reject -> "reject");
                      reason = "shadowed by earlier rule(s)"; } :: !result;
        Z3.Solver.pop (ctxt ()) solver 1;
        check_rules (mk_and seen_not (mk_not matches)) (idx + 1) rest
  in
  check_rules (mk_true ()) 1 pol.rules;
  List.rev !result

let check_equivalence (ir1 : Ir.t) (ir2 : Ir.t) =
  let pol1 = encode_policy ir1 in
  let pol2 = encode_policy ir2 in
  let pass1, block1 = encode_decision pol1 in
  let pass2, block2 = encode_decision pol2 in

  (* Policies differ if: pass1≠pass2 ∨ block1≠block2 *)
  let diff = mk_or (mk_not (mk_eq pass1 pass2)) (mk_not (mk_eq block1 block2)) in
  let solver = mk_solver () in
  Z3.Solver.add (ctxt ()) solver [ diff ];
  if check_sat solver then
    match get_model solver with
    | Some model ->
        let ce = model_to_ce ir1 pol1.sp model Pass in
        let line = find_matching_rule_line ir1 pol1.sp model in
        let ce = { ce with matched_rule_line = line } in
        Not_equivalent
          { counterexample = ce;
            decision_in_first = "unknown";
            decision_in_second = "unknown"; }
    | None -> Equivalent
  else Equivalent

let check_reachable (ir : Ir.t) ~constraints ~target_action =
  let pol = encode_policy ir in
  let pass_expr, block_expr = encode_decision pol in
  let solver = mk_solver () in

  let target_expr = match target_action with
    | Pass -> pass_expr | Block -> block_expr | Reject -> mk_false ()
  in
  Z3.Solver.add (ctxt ()) solver [ target_expr ];

  List.iter (fun (field, value) ->
    let c = match field with
      | "src" | "source" ->
          mk_bv_eq pol.sp.pkt_src (i32_to_z3 (ip4_to_int32 value))
      | "dst" | "destination" ->
          mk_bv_eq pol.sp.pkt_dst (i32_to_z3 (ip4_to_int32 value))
      | "dport" | "port" -> (
          match int_of_string_opt value with
          | Some p -> mk_bv_eq pol.sp.pkt_port
                        (Z3.BitVector.mk_numeral (ctxt ()) (string_of_int p) 16)
          | None -> mk_true ())
      | _ -> mk_true ()
    in
    Z3.Solver.add (ctxt ()) solver [ c ])
    constraints;

  if check_sat solver then
    match get_model solver with
    | Some model ->
        let ce = model_to_ce ir pol.sp model target_action in
        let line = find_matching_rule_line ir pol.sp model in
        Reachable { ce with matched_rule_line = line }
    | None -> Unreachable
  else Unreachable

let rec encode_clause (ir : Ir.t) (sp : sym_packet) = function
  | Field (field, _op, value) -> (
      match field with
      | "src" | "source" -> mk_bv_eq sp.pkt_src (i32_to_z3 (ip4_to_int32 value))
      | "dst" | "destination" -> mk_bv_eq sp.pkt_dst (i32_to_z3 (ip4_to_int32 value))
      | "dport" | "port" -> (
          match int_of_string_opt value with
          | Some p -> mk_eq sp.pkt_port
                        (Z3.BitVector.mk_numeral (ctxt ()) (string_of_int p) 16)
          | None -> mk_true ())
      | "proto" -> (
          match value with
          | "tcp" -> mk_eq sp.pkt_proto (proto_tcp ())
          | "udp" -> mk_eq sp.pkt_proto (proto_udp ())
          | "icmp" -> mk_eq sp.pkt_proto (proto_icmp ())
          | _ -> mk_true ())
      | _ -> mk_true ())
  | And (a, b) -> mk_and (encode_clause ir sp a) (encode_clause ir sp b)
  | Or (a, b) -> mk_or (encode_clause ir sp a) (encode_clause ir sp b)
  | Not a -> mk_not (encode_clause ir sp a)

let check_invariant (ir : Ir.t) clauses =
  let pol = encode_policy ir in
  let solver = mk_solver () in

  (* Build condition from clauses *)
  let condition =
    mk_all_of (List.map (encode_clause ir pol.sp) clauses)
  in

  (* Violation: condition holds AND packet passes (should be blocked) *)
  let pass_expr, _ = encode_decision pol in
  let violation = mk_and condition pass_expr in
  Z3.Solver.add (ctxt ()) solver [ violation ];

  if check_sat solver then
    match get_model solver with
    | Some model ->
        let ce = model_to_ce ir pol.sp model Pass in
        let line = find_matching_rule_line ir pol.sp model in
        Violated { ce with matched_rule_line = line }
    | None -> Holds
  else Holds

let minimize (ir : Ir.t) =
  (* Iterative approach: try removing each rule, check if equivalence holds *)
  let all_rules =
    List.concat_map (fun (a : anchor) -> a.rules) ir.anchors @ ir.rules
  in
  let total = List.length all_rules in
  let removed = ref [] in
  let kept = ref [] in
  List.iteri (fun i rule ->
    let without_rule = {
      ir with
      rules = !kept @ (List.filteri (fun j _ -> j > i) all_rules);
      anchors = [];
    } in
    let pol_full = encode_policy ir in
    let pol_minus = encode_policy without_rule in
    let pass_full, block_full = encode_decision pol_full in
    let pass_minus, block_minus = encode_decision pol_minus in
    let diff = mk_or (mk_not (mk_eq pass_full pass_minus))
                     (mk_not (mk_eq block_full block_minus)) in
    let solver = mk_solver () in
    Z3.Solver.add (ctxt ()) solver [ diff ];
    if check_sat solver then
      (* Rule is needed — keep it *)
      kept := !kept @ [ rule ]
    else
      (* Rule is redundant — skip it *)
      removed := rule.span.line :: !removed)
    all_rules;
  let removed_count = List.length !removed in
  ({ ir with rules = !kept; anchors = [] }, removed_count)
