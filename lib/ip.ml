type invocation = Process.invocation = {
  program : string;
  argv : string list;
}

type run_status = Process.run_status =
  | Exited of int
  | Signaled of int
  | Stopped of int
  | Failed_to_start of string

type run_error = Process.run_error = {
  invocation : invocation;
  status : run_status;
  stderr : string;
}

let rule_list_invocation () = { program = "ip"; argv = [ "ip"; "rule"; "list" ] }
let route_show_invocation table = { program = "ip"; argv = [ "ip"; "route"; "show"; "table"; string_of_int table ] }

let run invocation = Process.run ~temp_prefix:"lpf-ip" invocation

let rule_list_with_runner runner = runner (rule_list_invocation ())
let rule_list () = rule_list_with_runner run

let route_show_with_runner runner table = runner (route_show_invocation table)
let route_show table = route_show_with_runner run table

let string_of_run_error error = Process.string_of_run_error "ip" error

type observed_rule = {
  priority : int;
  fwmark : int option;
  table : int;
}

type observed_route = {
  gateway : string;
  device : string option;
  table : int;
}

let tokens line =
  String.split_on_char ' ' line |> List.filter (fun token -> String.length token > 0)

let int_token token =
  let token =
    match String.split_on_char '/' token with
    | value :: _ -> value
    | [] -> token
  in
  int_of_string_opt token

let rec field_after name = function
  | [] -> None
  | field :: value :: _ when String.equal field name -> Some value
  | _ :: rest -> field_after name rest

let parse_rule_list output =
  String.split_on_char '\n' output
  |> List.filter_map (fun line ->
    let line = String.trim line in
    if String.length line = 0 then None
    else
      match String.split_on_char ':' line with
      | priority_str :: rest ->
          let priority = match int_of_string_opt (String.trim priority_str) with Some p -> p | None -> 0 in
          let rest = String.concat ":" rest in
          let parts = tokens rest in
          let fwmark = Option.bind (field_after "fwmark" parts) int_token in
          let table = Option.bind (field_after "lookup" parts) int_token in
          (match table with
           | Some table -> Some { priority; fwmark; table }
           | None -> None)
      | _ -> None)

let parse_route_show output =
  let find_device parts =
    let rec loop = function
      | "dev" :: d :: _ -> Some d
      | _ :: more -> loop more
      | [] -> None
    in
    loop parts
  in
  let find_via parts =
    let rec loop = function
      | "via" :: gw :: _ -> Some gw
      | _ :: more -> loop more
      | [] -> None
    in
    loop parts
  in
  String.split_on_char '\n' output
  |> List.filter_map (fun line ->
    let line = String.trim line in
    if String.length line = 0 then None
    else
      let parts = tokens line in
      match parts with
      | "default" :: rest ->
          let gateway = find_via rest in
          let device = find_device rest in
          Some { gateway = Option.value gateway ~default:""; device; table = 0 }
      | _ ->
          let gateway = find_via parts in
          let device = find_device parts in
          let subnet = match parts with first :: _ when not (String.equal first "default") -> Some first | _ -> None in
          match (gateway, subnet) with
          | Some gw, _ -> Some { gateway = gw; device; table = 0 }
          | _, Some _net ->
              let gateway = Option.value gateway ~default:"" in
              Some { gateway; device; table = 0 }
          | None, None -> None)
