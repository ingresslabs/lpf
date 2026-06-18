val ir_of_policy : Policy.policy -> (Ir.t, Policy.diagnostic list) result
val plan_of_policy : Policy.policy -> (Plan.t, Policy.diagnostic list) result
val check_policy_text : ?file:string -> string -> Policy.check_result

val format_policy_text :
  ?file:string -> string -> (string, Policy.diagnostic list) result

val plan_policy_text :
  ?file:string ->
  string ->
  (Plan.t * Policy.diagnostic list, Policy.diagnostic list) result

val render_nftables_policy_text :
  ?file:string ->
  string ->
  (string * Policy.diagnostic list, Policy.diagnostic list) result

val render_tc_policy_text :
  ?file:string ->
  string ->
  (string * Policy.diagnostic list, Policy.diagnostic list) result

val render_routing_policy_text :
  ?file:string ->
  string ->
  (string * Policy.diagnostic list, Policy.diagnostic list) result

val diff_nftables_policy_text :
  ?file:string ->
  observed:string ->
  string ->
  (string * Policy.diagnostic list, Policy.diagnostic list) result

val diff_nftables_policy :
  ?file:string ->
  observed:string ->
  string ->
  (Nftables.diff_result * Policy.diagnostic list, Policy.diagnostic list) result

val diff_tc_policy :
  ?file:string ->
  observed_qdisc:Tc.observed_qdisc list ->
  observed_class:Tc.observed_class list ->
  string ->
  (Tc.diff_result * Policy.diagnostic list, Policy.diagnostic list) result

val diff_routing_policy :
  ?file:string ->
  observed_rules:Ip.observed_rule list ->
  observed_routes:Ip.observed_route list ->
  string ->
  (Routing.diff_result * Policy.diagnostic list, Policy.diagnostic list) result

val explain_policy_text :
  ?file:string ->
  packet:Explain.packet ->
  string ->
  (Explain.explanation * Policy.diagnostic list, Policy.diagnostic list) result

val run_policy_tests :
  ?file:string ->
  string ->
  ( (Test_engine.test_case * Test_engine.test_result list) list
    * Policy.diagnostic list,
    Policy.diagnostic list )
  result
