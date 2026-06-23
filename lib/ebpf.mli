(* eBPF datapath backend.

   lpf compiles the same [Ir.t] used by the nftables backend into an eBPF
   *policy image*: a set of typed BPF maps plus an attach plan for XDP, TC,
   cgroup, and LSM hooks. The eBPF program itself is a fixed, pre-verified
   generic match engine; policy lives entirely in map state, so "apply" is an
   atomic map-version swap rather than a recompile. *)

type verdict = Pass | Drop | Reject
type l4 = L4_any | L4_named of string
type addr_match = Addr_any | Addr_literal of string | Addr_set of string
type port_match = Mport_any | Mport_range of int * int

(* Phase 4: identity / L7-aware selectors derived from reserved table names
   ([cgroup_*]/[cgroup:*], [proc_*]/[proc:*], [dns_*]/[dns:*]). *)
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

val pin_root : string
val state_dir : string

(* Phase 1: compile IR/plan to an eBPF policy image and render it. *)
val of_ir : ?version:int -> Ir.t -> t
val of_plan : ?version:int -> Plan.t -> t
val to_string : t -> string
val render_plan : Plan.t -> string

(* Phase 1/3: deterministic diff of two rendered policy images. *)
type diff_result = { changes_required : bool; text : string }

val diff : intended:string -> observed:string -> diff_result
val diff_text : intended:string -> observed:string -> string

(* Phase 1/2: bpftool loader and atomic version-swap rollback scripts. *)
val loader_script : t -> string
val rollback_script : to_version:int -> string

(* Phase 3: observed per-rule counters from `bpftool map dump`. *)
type counter = { rule_index : int; packets : int; bytes : int }

val parse_counters : string -> counter list
val render_counters : counter list -> string

(* Phase 2/3: runner-injected apply / observe / rollback. *)
type runners = {
  load : string -> (string, Nft.run_error) result;
  dump : string -> (string, Nft.run_error) result;
}

val default_runners : runners

val apply_with_runners : runners -> t -> (unit, Nft.run_error) result
val observe_with_runners : runners -> (counter list, Nft.run_error) result

val rollback_with_runners :
  runners -> to_version:int -> (unit, Nft.run_error) result

(* Version snapshotting for guarded apply / rollback. *)
val active_version_path : string
val read_active_version : unit -> int option
val write_active_version : int -> unit

(* Phase 4 / explain: which hook + rule index handles a packet. *)
val classify : t -> Explain.packet -> string
