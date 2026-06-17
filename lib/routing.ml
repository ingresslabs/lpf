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

let route_to_mark rules anchors target =
  let rec extract_rules acc = function
    | [] -> acc
    | (r : Ir.rule) :: rest ->
        let acc = match r.route_to with Some target -> target :: acc | None -> acc in
        extract_rules acc rest
  in
  let targets = extract_rules [] rules in
  let targets =
    List.fold_left
      (fun acc (a : Ir.anchor) -> extract_rules acc a.rules)
      targets anchors
  in
  let unique_targets = List.sort_uniq compare targets in
  let rec find_index idx = function
    | [] -> None
    | t :: _ when t = target -> Some (100 + idx)
    | _ :: rest -> find_index (idx + 1) rest
  in
  find_index 0 unique_targets

let compile (ir : Ir.t) : t =
  let targets = extract_route_targets ir in
  List.mapi
    (fun idx target ->
      let mark = 100 + idx in
      let table = 100 + idx in
      let gateway, iface_opt = target in
      let gateway_str = match gateway with Ir.Literal s -> s | _ -> "" (* Handle appropriately *) in
      let device_str = match iface_opt with Some (i : Ir.interface_ref) -> Some i.device | None -> None in
      [
        Ip_rule_add { mark; table };
        Ip_route_add_default { gateway = gateway_str; device = device_str; table };
      ])
    targets
  |> List.flatten

let string_of_command = function
  | Ip_rule_add { mark; table } -> Printf.sprintf "ip rule add fwmark %d table %d" mark table
  | Ip_route_add_default { gateway; device; table } ->
      let dev_str = match device with Some d -> " dev " ^ d | None -> "" in
      Printf.sprintf "ip route add default via %s%s table %d" gateway dev_str table

let to_string t =
  String.concat "\n" (List.map string_of_command t) ^ if t = [] then "" else "\n"
