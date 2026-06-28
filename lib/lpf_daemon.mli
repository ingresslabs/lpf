type config = {
  policy_path : string;
  cni_config_path : string;
  host_cni_bin_dir : string;
  host_cni_net_dir : string;
  cni_binary_source : string;
  bpf_object : string option;
  poll_interval : float;
  listen_address : string;
  port : int;
  install_cni : bool;
  kube_api_watch : bool;
  kube_api_server : string;
  kube_api_token_path : string;
  kube_api_ca_path : string;
}

type status = {
  started_at : float;
  mutable ready : bool;
  mutable last_reload_at : float option;
  mutable last_policy_hash : string option;
  mutable last_error : string option;
  mutable reloads : int;
  mutable failures : int;
}

val default_config : unit -> config
val create_status : unit -> status
val policy_hash : string -> string
val metrics_text : status -> string
val route_response : status -> string -> int * string * string
val items_from_list_json : Json_parse.json -> Json_parse.json list

val effective_policy_of_kubernetes_json :
  cluster_policies:string ->
  namespaced_policies:string ->
  staged_policies:string ->
  network_policies:string ->
  (string, string) result

val install_cni_files : config -> (unit, string) result
val reload_policy : config -> status -> (unit, string) result
val maybe_reload_policy : config -> status -> (unit, string) result
val run : config -> unit
