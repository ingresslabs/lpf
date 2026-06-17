type scenario_family =
  | Nft_accept
  | Nft_drop
  | Nft_log
  | Routing
  | Traffic_shaping
  | Conntrack

type scenario = {
  id : string;
  family : scenario_family;
  index : int;
  description : string;
}

type scenario_status =
  | Passed
  | Failed of string

type scenario_result = {
  scenario : scenario;
  status : scenario_status;
  stdout : string;
  stderr : string;
  duration_ms : int;
}

type config = {
  scenario_count : int;
  junit_path : string option;
  allure_dir : string option;
  evidence_dir : string option;
  kernel_id : string option;
  dry_run : bool;
}

type suite_result = {
  kernel_id : string;
  kernel_release : string;
  scenario_count : int;
  passed : int;
  failed : int;
  results : scenario_result list;
}

val default_scenario_count : int
val family_name : scenario_family -> string
val scenario_catalog : int -> scenario list
val run : config -> suite_result
val to_junit : suite_result -> string
val evidence_manifest : suite_result -> string
