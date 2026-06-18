type command =
  | Ip_rule_add of { mark : int; table : int }
  | Ip_route_add_default of { gateway : string; device : string option; table : int }

type t = command list

let extract_route_targets (ir : Ir.t) =
  let rec extract_rules acc = function
    | [] -> acc
    | (r : Ir.rule) :: rest ->
        let acc = match r.route_to with Some target -> target :: acc | None -> acc in
        extract_rules acc rest
  in
  let targets = extract_rules [] ir.rules in
  let targets =
    List.fold_left
      (fun acc (a : Ir.anchor) -> extract_rules acc a.rules)
      targets ir.anchors
  in
  List.sort_uniq compare targets

let mark_for_target ir target =
  let targets = extract_route_targets ir in
  let rec find_index idx = function
    | [] -> None
    | t :: _ when t = target -> Some (100 + idx)
    | _ :: rest -> find_index (idx + 1) rest
  in
  find_index 0 targets

let compile (ir : Ir.t) : t =
  let targets = extract_route_targets ir in
  targets
  |> List.mapi (fun idx target -> (idx, target))
  |> List.filter_map
    (fun (idx, (gateway, iface_opt)) ->
      match gateway with
      | Ir.Literal gateway_str ->
          let mark = 100 + idx in
          let table = 100 + idx in
          let device_str = match iface_opt with Some (i : Ir.interface_ref) -> Some i.device | None -> None in
          let cmds = [
            Ip_rule_add { mark; table };
            Ip_route_add_default { gateway = gateway_str; device = device_str; table };
          ] in
          Some cmds
      | _ ->
          Printf.eprintf "routing: skipping non-literal gateway at target %d\n" idx;
          None)
  |> List.flatten

let string_of_command = function
  | Ip_rule_add { mark; table } -> Printf.sprintf "ip rule add fwmark %d table %d" mark table
  | Ip_route_add_default { gateway; device; table } ->
      let dev_str = match device with Some d -> " dev " ^ d | None -> "" in
      Printf.sprintf "ip route add default via %s%s table %d" gateway dev_str table

let to_string t =
  String.concat "\n" (List.map string_of_command t) ^ if t = [] then "" else "\n"

type diff_result = {
  changes_required : bool;
  text : string;
}

let diff ~intended ~observed_rules ~observed_routes =
  let buf = Buffer.create 256 in
  let changes = ref false in
  List.iter (function
    | Ip_rule_add r ->
        let found = List.find_opt (fun (o : Ip.observed_rule) ->
          o.table = r.table && (match o.fwmark with Some m -> m = r.mark | None -> false)
        ) observed_rules in
        (match found with
         | None ->
             changes := true;
             Buffer.add_string buf (Printf.sprintf "-rule fwmark %d table %d: missing\n" r.mark r.table);
             Buffer.add_string buf (Printf.sprintf "+rule fwmark %d table %d\n" r.mark r.table)
         | Some _ -> ())
    | Ip_route_add_default r ->
        let found = List.find_opt (fun (o : Ip.observed_route) ->
          o.table = r.table && String.equal o.gateway r.gateway
        ) observed_routes in
        (match found with
         | None ->
             changes := true;
             Buffer.add_string buf (Printf.sprintf "-route default via %s table %d: missing\n" r.gateway r.table);
             Buffer.add_string buf (Printf.sprintf "+route default via %s table %d\n" r.gateway r.table)
         | Some _ -> ()))
    intended;
  if not !changes then { changes_required = false; text = "routing diff: no changes\n" }
  else { changes_required = true; text = "routing diff: changes required\n" ^ Buffer.contents buf }
