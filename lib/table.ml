type element = string

let add_element_invocation table_name element =
  { Nft.program = "nft"; argv = [ "nft"; "add"; "element"; "inet"; "lpf_filter"; "tbl_" ^ table_name; "{"; element; "}" ] }

let delete_element_invocation table_name element =
  { Nft.program = "nft"; argv = [ "nft"; "delete"; "element"; "inet"; "lpf_filter"; "tbl_" ^ table_name; "{"; element; "}" ] }

let flush_invocation table_name =
  { Nft.program = "nft"; argv = [ "nft"; "flush"; "set"; "inet"; "lpf_filter"; "tbl_" ^ table_name ] }

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
