(* Z3-powered formal verification for lpf firewall policies.

   Translates the policy IR into Z3 SMT constraints and answers questions
   that concrete testing cannot: equivalence, dead rules, reachability,
   security invariants, and true rule minimization.

   Full packet model encoded in Z3:
   - direction (in/out) as boolean
   - interface as uninterpreted sort (symbolic)
   - protocol as uninterpreted sort (symbolic)
   - IPv4 address as 32-bit bitvector
   - port as 16-bit bitvector
   - NAT/RDR address rewriting in the decision function

   All verification functions return structured, human-readable results. *)

type counterexample = {
  direction : string;
  interface : string;
  protocol : string;
  source : string;
  destination : string;
  port : int option;
  decision : string;
  matched_rule_line : int option;
  nat_applied : int option;
  rdr_applied : int option;
}

type dead_rule = { line : int; action : string; reason : string }

type equiv_result =
  | Equivalent
  | Not_equivalent of {
      counterexample : counterexample;
      decision_in_first : string;
      decision_in_second : string;
    }

type reachable_result = Reachable of counterexample | Unreachable

type invariant_clause =
  | Field of string * string * string (* field, op, value *)
  | And of invariant_clause * invariant_clause
  | Or of invariant_clause * invariant_clause
  | Not of invariant_clause

type invariant_result = Holds | Violated of counterexample

(* Policy consistency: find dead/shadowed rules. *)
val check_consistency : Ir.t -> dead_rule list

(* Prove equivalence of two policies for all packets.
   Returns Not_equivalent with a concrete counterexample. *)
val check_equivalence : Ir.t -> Ir.t -> equiv_result

(* Symbolic reachability: find a packet that satisfies constraints
   and produces a specific action. Constraints are (field, value) pairs. *)
val check_reachable :
  Ir.t ->
  constraints:(string * string) list ->
  target_action:Ir.action ->
  reachable_result

(* Prove an invariant holds for ALL packets. The invariant is a
   tree of field conditions with AND/OR/NOT. *)
val check_invariant : Ir.t -> invariant_clause list -> invariant_result

(* Find the minimal semantically-equivalent rule set. Uses Z3
   to determine which rules are redundant. *)
val minimize : Ir.t -> Ir.t * int

(* Symbolic reverse-explanation: given a rule (identified by its line number),
   find the full set of packets that match it but NOT any earlier rule.
   Returns a Z3 expression characterizing these packets, and optionally
   a concrete example. *)
type rule_coverage = {
  line : int;
  action : string;
  reachable : bool;
  example : counterexample option;
      (* If reachable, example is a concrete packet that hits this rule *)
}

val check_rule_coverage : Ir.t -> rule_coverage list

(* Automated test generation: produce test fixtures that guarantee
   coverage of every rule and every boundary condition (first/last
   packet in CIDR ranges, port boundaries, etc.).
   Returns a list of (packet, expected_decision) pairs suitable
   for use with `lpf test`. *)
type generated_test = {
  test_name : string;
  packet : Explain.packet;
  expected_action : string;
  rule_line : int option;
}

val generate_tests : Ir.t -> generated_test list

(* Prove that the eBPF backend produces semantically identical
   results to the concrete explain engine for a given policy.
   This verifies the eBPF compilation pipeline is correct. *)
val check_backend_equivalence :
  ir:Ir.t -> ebpf_rules:(Ir.rule -> bool) -> equiv_result
