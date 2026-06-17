type element = string

let add_element_invocation table_name element =
  { Nft.program = "nft"; argv = [ "nft"; "add"; "element"; "inet"; "lpf_filter"; "tbl_" ^ table_name; "{"; element; "}" ] }

let delete_element_invocation table_name element =
  { Nft.program = "nft"; argv = [ "nft"; "delete"; "element"; "inet"; "lpf_filter"; "tbl_" ^ table_name; "{"; element; "}" ] }

let flush_invocation table_name =
  { Nft.program = "nft"; argv = [ "nft"; "flush"; "set"; "inet"; "lpf_filter"; "tbl_" ^ table_name ] }

let counters_invocation table_name =
  { Nft.program = "nft"; argv = [ "nft"; "list"; "set"; "inet"; "lpf_filter"; "tbl_" ^ table_name ] }

let counters_with_runner runner table_name = runner (counters_invocation table_name)
let counters table_name = counters_with_runner Nft.run table_name

let flush_with_runner runner table_name = runner (flush_invocation table_name) |> Result.map ignore
let flush table_name = flush_with_runner Nft.run table_name

let add_with_runner runner table_name element =
  match runner (add_element_invocation table_name element) with
  | Ok _ -> Ok ()
  | Error error -> Error error

let delete_with_runner runner table_name element =
  match runner (delete_element_invocation table_name element) with
  | Ok _ -> Ok ()
  | Error error -> Error error

let replace_with_runner runner table_name elements =
  match runner (flush_invocation table_name) with
  | Ok _ ->
      let rec add_all = function
        | [] -> Ok ()
        | e :: rest ->
            (match runner (add_element_invocation table_name e) with
             | Ok _ -> add_all rest
             | Error error -> Error error)
      in
      add_all elements
  | Error error -> Error error

let add table_name element = add_with_runner Nft.run table_name element
let delete table_name element = delete_with_runner Nft.run table_name element
let replace table_name elements = replace_with_runner Nft.run table_name elements

type table_element = {
  value : string;
  packets : int option;
  bytes : int option;
}

let parse_counters_line line =
  let trimmed = String.trim line in
  if String.length trimmed = 0 || trimmed.[0] = '{' || trimmed.[0] = '}' then None
  else
    let trim_punctuation value =
      let rec right index =
        if index < 0 then ""
        else
          match value.[index] with
          | ',' | '}' -> right (index - 1)
          | _ -> String.sub value 0 (index + 1)
      in
      right (String.length value - 1)
    in
    let parts =
      String.split_on_char ' ' trimmed
      |> List.filter (fun s -> String.length s > 0)
      |> List.map trim_punctuation
    in
    let value =
      match parts with
      | v :: _ when v <> "counter" -> v
      | _ -> ""
    in
    if value = "" then None
    else
      let rec int_after name = function
        | [] -> None
        | key :: value :: _ when String.equal key name -> int_of_string_opt value
        | _ :: rest -> int_after name rest
      in
      let packets = int_after "packets" parts in
      let bytes = int_after "bytes" parts in
      Some { value; packets; bytes }

let parse_counters_output output =
  let lines = String.split_on_char '\n' output in
  let element_fragment line =
    let trimmed = String.trim line in
    if String.starts_with ~prefix:"elements" trimmed then
      match String.split_on_char '{' trimmed with
      | _before :: after -> String.concat "{" after
      | [] -> ""
    else trimmed
  in
  let rec collect in_elements acc = function
    | [] -> List.rev acc
    | line :: rest ->
        let trimmed = String.trim line in
        if in_elements then collect true (element_fragment line :: acc) rest
        else if String.starts_with ~prefix:"elements" trimmed then
          collect true (element_fragment line :: acc) rest
        else collect false acc rest
  in
  let element_lines = collect false [] lines in
  List.filter_map parse_counters_line element_lines

let element_to_json (e : table_element) =
  Json_util.field_object
    ([ ("value", Json_util.string e.value) ]
     @ (match e.packets with Some p -> [ ("packets", Json_util.int p) ] | None -> [])
     @ (match e.bytes with Some b -> [ ("bytes", Json_util.int b) ] | None -> []))

let elements_to_json elements =
  Json_util.list element_to_json elements ^ "\n"
