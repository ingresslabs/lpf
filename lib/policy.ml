type span = {
  file : string option;
  line : int;
  column : int;
  end_column : int;
}

type severity = Diag_error | Diag_warning

type diagnostic = {
  severity : severity;
  span : span;
  message : string;
}

type default_action = Default_pass | Default_deny
type direction = In | Out
type action = Pass | Block
type protocol = Proto_any | Proto_named of string

type reference =
  | Any
  | Literal of string
  | Table_ref of string
  | Macro_ref of string

type port =
  | Port_any
  | Port_number of int
  | Port_macro of string

type interface_decl = {
  name : string;
  device : string;
  span : span;
}

type macro = {
  name : string;
  value : string;
  span : span;
}

type table = {
  name : string;
  entries : string list;
  span : span;
}

type rule = {
  action : action;
  direction : direction option;
  interface : reference option;
  protocol : protocol;
  source : reference;
  destination : reference;
  port : port;
  keep_state : bool;
  span : span;
}

type nat = {
  interface : reference;
  protocol : protocol;
  source : reference;
  destination : reference;
  translation : reference;
  span : span;
}

type rdr = {
  interface : reference;
  protocol : protocol;
  source : reference;
  destination : reference;
  port : port;
  translation : reference;
  translation_port : port;
  span : span;
}

type policy = {
  default_action : default_action option;
  interfaces : interface_decl list;
  macros : macro list;
  tables : table list;
  nats : nat list;
  rdrs : rdr list;
  rules : rule list;
}

type check_result = {
  policy : policy option;
  diagnostics : diagnostic list;
}

let empty_policy =
  {
    default_action = None;
    interfaces = [];
    macros = [];
    tables = [];
    nats = [];
    rdrs = [];
    rules = [];
  }

let trim = String.trim

let starts_with ~prefix text =
  let prefix_len = String.length prefix in
  String.length text >= prefix_len && String.sub text 0 prefix_len = prefix

let span ?file line column end_column = { file; line; column; end_column }

let line_span ?file line text = span ?file line 1 (max 1 (String.length text + 1))

let diagnostic severity span message = { severity; span; message }

let syntax_error span message = diagnostic Diag_error span message

let strip_comment text =
  match String.index_opt text '#' with
  | None -> text
  | Some index -> String.sub text 0 index

let is_space = function ' ' | '\t' | '\r' | '\n' -> true | _ -> false

let split_words text =
  let rec skip_spaces index =
    if index >= String.length text then index
    else if is_space text.[index] then skip_spaces (index + 1)
    else index
  in
  let rec next_word start index acc =
    if index >= String.length text then
      if start = index then List.rev acc
      else List.rev (String.sub text start (index - start) :: acc)
    else if is_space text.[index] then
      let word = String.sub text start (index - start) in
      loop (index + 1) (word :: acc)
    else next_word start (index + 1) acc
  and loop index acc =
    let index = skip_spaces index in
    if index >= String.length text then List.rev acc else next_word index index acc
  in
  loop 0 []

let strip_quotes text =
  let len = String.length text in
  if len >= 2 && text.[0] = '"' && text.[len - 1] = '"' then String.sub text 1 (len - 2)
  else text

let is_ident_char = function
  | 'a' .. 'z' | 'A' .. 'Z' | '0' .. '9' | '_' | '-' -> true
  | _ -> false

let valid_name name =
  String.length name > 0 && String.for_all is_ident_char name

let parse_table_name token =
  let len = String.length token in
  if len >= 3 && token.[0] = '<' && token.[len - 1] = '>' then
    Some (String.sub token 1 (len - 2))
  else None

let parse_macro_ref token =
  if starts_with ~prefix:"$" token && String.length token > 1 then
    Some (String.sub token 1 (String.length token - 1))
  else None

let parse_reference token =
  match token with
  | "any" -> Any
  | _ -> (
      match parse_table_name token with
      | Some name -> Table_ref name
      | None -> (
          match parse_macro_ref token with
          | Some name -> Macro_ref name
          | None -> Literal token))

let parse_port token =
  match token with
  | "any" -> Ok Port_any
  | _ -> (
      match parse_macro_ref token with
      | Some name -> Ok (Port_macro name)
      | None -> (
          match int_of_string_opt token with
          | Some value when value >= 1 && value <= 65535 -> Ok (Port_number value)
          | _ -> Error ("invalid port `" ^ token ^ "`")))

let parse_action = function "pass" -> Some Pass | "block" -> Some Block | _ -> None

let add_diagnostic diagnostics diag = diag :: diagnostics

let parse_default ?file line original text policy diagnostics =
  match split_words text with
  | [ "set"; "default"; "deny" ] ->
      ({ policy with default_action = Some Default_deny }, diagnostics)
  | [ "set"; "default"; "pass" ] ->
      ({ policy with default_action = Some Default_pass }, diagnostics)
  | _ ->
      ( policy,
        add_diagnostic diagnostics
          (syntax_error (line_span ?file line original)
             "expected `set default deny` or `set default pass`") )

let parse_interface ?file line original text policy diagnostics =
  match split_words text with
  | [ "interface"; name; "="; device ] when valid_name name ->
      let interface = { name; device = strip_quotes device; span = line_span ?file line original } in
      ({ policy with interfaces = interface :: policy.interfaces }, diagnostics)
  | _ ->
      ( policy,
        add_diagnostic diagnostics
          (syntax_error (line_span ?file line original)
             "expected `interface <name> = \"device\"`") )

let parse_macro ?file line original text policy diagnostics =
  match String.index_opt text '=' with
  | None -> (policy, diagnostics)
  | Some index ->
      let name = String.sub text 0 index |> trim in
      let value = String.sub text (index + 1) (String.length text - index - 1) |> trim in
      if not (valid_name name) then
        ( policy,
          add_diagnostic diagnostics
            (syntax_error (line_span ?file line original) ("invalid macro name `" ^ name ^ "`")) )
      else if value = "" then
        ( policy,
          add_diagnostic diagnostics
            (syntax_error (line_span ?file line original) ("macro `" ^ name ^ "` has no value")) )
      else
        let macro = { name; value = strip_quotes value; span = line_span ?file line original } in
        ({ policy with macros = macro :: policy.macros }, diagnostics)

let parse_table ?file line original text policy diagnostics =
  match String.index_opt text '{', String.rindex_opt text '}' with
  | Some open_index, Some close_index when close_index > open_index -> (
      let head = String.sub text 0 open_index |> trim in
      match split_words head with
      | [ "table"; table_token ] -> (
          match parse_table_name table_token with
          | Some name when valid_name name ->
              let body =
                String.sub text (open_index + 1) (close_index - open_index - 1)
                |> String.split_on_char ','
                |> List.map trim
                |> List.filter (fun entry -> entry <> "")
              in
              let table = { name; entries = body; span = line_span ?file line original } in
              ({ policy with tables = table :: policy.tables }, diagnostics)
          | Some name ->
              ( policy,
                add_diagnostic diagnostics
                  (syntax_error (line_span ?file line original)
                     ("invalid table name `" ^ name ^ "`")) )
          | None ->
              ( policy,
                add_diagnostic diagnostics
                  (syntax_error (line_span ?file line original)
                     "expected table name like `<trusted>`") ))
      | _ ->
          ( policy,
            add_diagnostic diagnostics
              (syntax_error (line_span ?file line original)
                 "expected `table <name> { entries }`") ))
  | _ ->
      ( policy,
        add_diagnostic diagnostics
          (syntax_error (line_span ?file line original)
             "expected `table <name> { entries }`") )

let parse_rule ?file line original text policy diagnostics =
  let tokens = split_words text in
  match tokens with
  | action_token :: rest -> (
      match parse_action action_token with
      | None ->
          ( policy,
            add_diagnostic diagnostics
              (syntax_error (line_span ?file line original)
                 "expected rule to start with `pass` or `block`") )
      | Some action ->
          let rule_span = line_span ?file line original in
          let rec loop (state : rule) diagnostics = function
            | [] -> Ok (state, diagnostics)
            | "in" :: rest -> (
                match state.direction with
                | Some _ -> Error "duplicate direction"
                | None -> loop { state with direction = Some In } diagnostics rest)
            | "out" :: rest -> (
                match state.direction with
                | Some _ -> Error "duplicate direction"
                | None -> loop { state with direction = Some Out } diagnostics rest)
            | "on" :: name :: rest -> (
                match state.interface with
                | Some _ -> Error "duplicate interface matcher"
                | None -> loop { state with interface = Some (parse_reference name) } diagnostics rest)
            | "proto" :: proto :: rest -> (
                match state.protocol with
                | Proto_any -> loop { state with protocol = Proto_named proto } diagnostics rest
                | Proto_named _ -> Error "duplicate protocol matcher")
            | "from" :: source :: rest -> (
                match state.source with
                | Any -> loop { state with source = parse_reference source } diagnostics rest
                | _ -> Error "duplicate source matcher")
            | "to" :: destination :: rest -> (
                match state.destination with
                | Any -> loop { state with destination = parse_reference destination } diagnostics rest
                | _ -> Error "duplicate destination matcher")
            | "port" :: value :: rest -> (
                match state.port with
                | Port_any -> (
                    match parse_port value with
                    | Ok port -> loop { state with port } diagnostics rest
                    | Error message -> Error message)
                | _ -> Error "duplicate port matcher")
            | "keep" :: "state" :: rest -> (
                match state.keep_state with
                | false -> loop { state with keep_state = true } diagnostics rest
                | true -> Error "duplicate `keep state`")
            | token :: _ -> Error ("unexpected token `" ^ token ^ "`")
          in
          let initial : rule =
            {
              action;
              direction = None;
              interface = None;
              protocol = Proto_any;
              source = Any;
              destination = Any;
              port = Port_any;
              keep_state = false;
              span = rule_span;
            }
          in
          (match loop initial diagnostics rest with
          | Ok (rule, diagnostics) -> ({ policy with rules = rule :: policy.rules }, diagnostics)
          | Error message ->
              ( policy,
                add_diagnostic diagnostics
                  (syntax_error rule_span ("invalid rule: " ^ message)) )))
  | [] -> (policy, diagnostics)

let parse_nat ?file line original text policy diagnostics =
  let tokens = split_words text in
  match tokens with
  | "nat" :: rest -> (
      let rule_span = line_span ?file line original in
      let rec loop (state : nat) diagnostics = function
        | [] -> Error "missing translation `->`"
        | "->" :: translation :: [] -> Ok ({ state with translation = parse_reference translation }, diagnostics)
        | "on" :: name :: rest -> loop { state with interface = parse_reference name } diagnostics rest
        | "proto" :: proto :: rest -> loop { state with protocol = Proto_named proto } diagnostics rest
        | "from" :: source :: rest -> loop { state with source = parse_reference source } diagnostics rest
        | "to" :: destination :: rest -> loop { state with destination = parse_reference destination } diagnostics rest
        | token :: _ -> Error ("unexpected token `" ^ token ^ "`")
      in
      let initial : nat =
        {
          interface = Any;
          protocol = Proto_any;
          source = Any;
          destination = Any;
          translation = Any;
          span = rule_span;
        }
      in
      match loop initial diagnostics rest with
      | Ok (nat, diagnostics) -> ({ policy with nats = nat :: policy.nats }, diagnostics)
      | Error message ->
          ( policy,
            add_diagnostic diagnostics
              (syntax_error rule_span ("invalid nat: " ^ message)) ))
  | _ -> (policy, diagnostics)

let parse_rdr ?file line original text policy diagnostics =
  let tokens = split_words text in
  match tokens with
  | "rdr" :: rest -> (
      let rule_span = line_span ?file line original in
      let rec loop (state : rdr) diagnostics = function
        | [] -> Error "missing translation `->`"
        | "->" :: translation :: rest -> (
            let state = { state with translation = parse_reference translation } in
            match rest with
            | [] -> Ok (state, diagnostics)
            | [ "port"; port_token ] -> (
                match parse_port port_token with
                | Ok translation_port -> Ok ({ state with translation_port }, diagnostics)
                | Error message -> Error message)
            | _ -> Error "unexpected tokens after translation")
        | "on" :: name :: rest -> loop { state with interface = parse_reference name } diagnostics rest
        | "proto" :: proto :: rest -> loop { state with protocol = Proto_named proto } diagnostics rest
        | "from" :: source :: rest -> loop { state with source = parse_reference source } diagnostics rest
        | "to" :: destination :: rest -> loop { state with destination = parse_reference destination } diagnostics rest
        | "port" :: port_token :: rest -> (
            match parse_port port_token with
            | Ok port -> loop { state with port } diagnostics rest
            | Error message -> Error message)
        | token :: _ -> Error ("unexpected token `" ^ token ^ "`")
      in
      let initial : rdr =
        {
          interface = Any;
          protocol = Proto_any;
          source = Any;
          destination = Any;
          port = Port_any;
          translation = Any;
          translation_port = Port_any;
          span = rule_span;
        }
      in
      match loop initial diagnostics rest with
      | Ok (rdr, diagnostics) -> ({ policy with rdrs = rdr :: policy.rdrs }, diagnostics)
      | Error message ->
          ( policy,
            add_diagnostic diagnostics
              (syntax_error rule_span ("invalid rdr: " ^ message)) ))
  | _ -> (policy, diagnostics)

let parse_line ?file line policy diagnostics original =
  let text = original |> strip_comment |> trim in
  if text = "" then (policy, diagnostics)
  else if starts_with ~prefix:"set " text then parse_default ?file line original text policy diagnostics
  else if starts_with ~prefix:"interface " text then
    parse_interface ?file line original text policy diagnostics
  else if starts_with ~prefix:"table " text then parse_table ?file line original text policy diagnostics
  else if starts_with ~prefix:"nat " text then parse_nat ?file line original text policy diagnostics
  else if starts_with ~prefix:"rdr " text then parse_rdr ?file line original text policy diagnostics
  else if starts_with ~prefix:"pass " text || starts_with ~prefix:"block " text then
    parse_rule ?file line original text policy diagnostics
  else if String.contains text '=' then parse_macro ?file line original text policy diagnostics
  else
    ( policy,
      add_diagnostic diagnostics
        (syntax_error (line_span ?file line original)
           "unrecognized statement; expected set, interface, table, macro, nat, rdr, pass, or block") )

let parse ?file text =
  let lines = String.split_on_char '\n' text in
  let policy, diagnostics, _ =
    List.fold_left
      (fun (policy, diagnostics, line) original ->
        let policy, diagnostics = parse_line ?file line policy diagnostics original in
        (policy, diagnostics, line + 1))
      (empty_policy, [], 1) lines
  in
  let policy =
    {
      policy with
      interfaces = List.rev policy.interfaces;
      macros = List.rev policy.macros;
      tables = List.rev policy.tables;
      nats = List.rev policy.nats;
      rdrs = List.rev policy.rdrs;
      rules = List.rev policy.rules;
    }
  in
  if List.exists (fun (diagnostic : diagnostic) -> diagnostic.severity = Diag_error) diagnostics then
    { policy = None; diagnostics = List.rev diagnostics }
  else { policy = Some policy; diagnostics = List.rev diagnostics }

let has_duplicate names =
  let rec loop seen = function
    | [] -> []
    | (name, span) :: rest ->
        if List.mem name seen then (name, span) :: loop seen rest else loop (name :: seen) rest
  in
  loop [] names

let names_of_tables (policy : policy) =
  List.map (fun (table : table) -> (table.name, table.span)) policy.tables

let names_of_macros (policy : policy) =
  List.map (fun (macro : macro) -> (macro.name, macro.span)) policy.macros

let names_of_interfaces (policy : policy) =
  List.map (fun (interface : interface_decl) -> (interface.name, interface.span)) policy.interfaces

let table_names (policy : policy) = List.map (fun (table : table) -> table.name) policy.tables
let macro_names (policy : policy) = List.map (fun (macro : macro) -> macro.name) policy.macros

let interface_names (policy : policy) =
  List.map (fun (interface : interface_decl) -> interface.name) policy.interfaces

let validate_reference ~tables ~macros span context = function
  | Any | Literal _ -> []
  | Table_ref name ->
      if List.mem name tables then []
      else [ diagnostic Diag_error span (context ^ " references unknown table `<" ^ name ^ ">`") ]
  | Macro_ref name ->
      if List.mem name macros then []
      else [ diagnostic Diag_error span (context ^ " references unknown macro `$" ^ name ^ "`") ]

let validate_interface_reference ~interfaces ~macros span = function
  | None -> []
  | Some Any -> [ diagnostic Diag_error span "`on any` is not a valid interface matcher" ]
  | Some (Literal name) ->
      if List.mem name interfaces then []
      else [ diagnostic Diag_error span ("rule references unknown interface `" ^ name ^ "`") ]
  | Some (Macro_ref name) ->
      if List.mem name macros then []
      else [ diagnostic Diag_error span ("rule references unknown interface macro `$" ^ name ^ "`") ]
  | Some (Table_ref name) ->
      [ diagnostic Diag_error span ("interface matcher cannot use table `<" ^ name ^ ">`") ]

let validate_port ~macros span = function
  | Port_any | Port_number _ -> []
  | Port_macro name ->
      if List.mem name macros then []
      else [ diagnostic Diag_error span ("port references unknown macro `$" ^ name ^ "`") ]

let validate policy =
  let diagnostics = [] in
  let diagnostics =
    match policy.default_action with
    | Some _ -> diagnostics
    | None ->
        diagnostic Diag_warning (span 1 1 1)
          "no default action set; add `set default deny` or `set default pass`"
        :: diagnostics
  in
  let diagnostics =
    has_duplicate (names_of_tables policy)
    |> List.fold_left
         (fun diagnostics (name, span) ->
           diagnostic Diag_error span ("duplicate table `<" ^ name ^ ">`") :: diagnostics)
         diagnostics
  in
  let diagnostics =
    has_duplicate (names_of_macros policy)
    |> List.fold_left
         (fun diagnostics (name, span) ->
           diagnostic Diag_error span ("duplicate macro `" ^ name ^ "`") :: diagnostics)
         diagnostics
  in
  let diagnostics =
    has_duplicate (names_of_interfaces policy)
    |> List.fold_left
         (fun diagnostics (name, span) ->
           diagnostic Diag_error span ("duplicate interface `" ^ name ^ "`") :: diagnostics)
         diagnostics
  in
  let tables = table_names policy in
  let macros = macro_names policy in
  let interfaces = interface_names policy in
  let rule_diagnostics =
    (policy.rules
    |> List.concat_map (fun (rule : rule) ->
           validate_reference ~tables ~macros rule.span "rule source" rule.source
           @ validate_reference ~tables ~macros rule.span "rule destination" rule.destination
           @ validate_interface_reference ~interfaces ~macros rule.span rule.interface
           @ validate_port ~macros rule.span rule.port))
    @ (policy.nats
      |> List.concat_map (fun (nat : nat) ->
             validate_reference ~tables ~macros nat.span "nat source" nat.source
             @ validate_reference ~tables ~macros nat.span "nat destination" nat.destination
             @ validate_interface_reference ~interfaces ~macros nat.span (Some nat.interface)
             @ validate_reference ~tables ~macros nat.span "nat translation" nat.translation))
    @ (policy.rdrs
      |> List.concat_map (fun (rdr : rdr) ->
             validate_reference ~tables ~macros rdr.span "rdr source" rdr.source
             @ validate_reference ~tables ~macros rdr.span "rdr destination" rdr.destination
             @ validate_interface_reference ~interfaces ~macros rdr.span (Some rdr.interface)
             @ validate_reference ~tables ~macros rdr.span "rdr translation" rdr.translation
             @ validate_port ~macros rdr.span rdr.port
             @ validate_port ~macros rdr.span rdr.translation_port))
  in
  List.rev (rule_diagnostics @ diagnostics)

let check ?file text =
  let parsed = parse ?file text in
  match parsed.policy with
  | None -> parsed
  | Some policy ->
      let validation = validate policy in
      let diagnostics = parsed.diagnostics @ validation in
      if List.exists (fun (diagnostic : diagnostic) -> diagnostic.severity = Diag_error) diagnostics then
        { policy = None; diagnostics }
      else { policy = Some policy; diagnostics }

let string_of_default_action = function Default_pass -> "pass" | Default_deny -> "deny"
let string_of_action = function Pass -> "pass" | Block -> "block"
let string_of_direction = function In -> "in" | Out -> "out"

let string_of_reference = function
  | Any -> "any"
  | Literal value -> value
  | Table_ref name -> "<" ^ name ^ ">"
  | Macro_ref name -> "$" ^ name

let string_of_port = function
  | Port_any -> "any"
  | Port_number number -> string_of_int number
  | Port_macro name -> "$" ^ name

let format_policy (policy : policy) =
  let default_lines =
    match policy.default_action with
    | None -> []
    | Some action -> [ "set default " ^ string_of_default_action action ]
  in
  let macro_lines =
    policy.macros
    |> List.sort (fun (a : macro) b -> String.compare a.name b.name)
    |> List.map (fun (macro : macro) -> macro.name ^ " = " ^ macro.value)
  in
  let interface_lines =
    policy.interfaces
    |> List.sort (fun (a : interface_decl) b -> String.compare a.name b.name)
    |> List.map (fun (interface : interface_decl) ->
           "interface " ^ interface.name ^ " = \"" ^ interface.device ^ "\"")
  in
  let table_lines =
    policy.tables
    |> List.sort (fun (a : table) b -> String.compare a.name b.name)
    |> List.map (fun (table : table) ->
           "table <" ^ table.name ^ "> { " ^ String.concat ", " table.entries ^ " }")
  in
  let nat_lines =
    policy.nats
    |> List.map (fun (nat : nat) ->
           let parts = [ "nat" ] in
           let parts = if nat.interface <> Any then parts @ [ "on"; string_of_reference nat.interface ] else parts in
           let parts =
             match nat.protocol with
             | Proto_any -> parts
             | Proto_named name -> parts @ [ "proto"; name ]
           in
           let parts =
             parts @ [ "from"; string_of_reference nat.source; "to"; string_of_reference nat.destination ]
           in
           let parts = parts @ [ "->"; string_of_reference nat.translation ] in
           String.concat " " parts)
  in
  let rdr_lines =
    policy.rdrs
    |> List.map (fun (rdr : rdr) ->
           let parts = [ "rdr" ] in
           let parts = if rdr.interface <> Any then parts @ [ "on"; string_of_reference rdr.interface ] else parts in
           let parts =
             match rdr.protocol with
             | Proto_any -> parts
             | Proto_named name -> parts @ [ "proto"; name ]
           in
           let parts =
             parts @ [ "from"; string_of_reference rdr.source; "to"; string_of_reference rdr.destination ]
           in
           let parts = match rdr.port with Port_any -> parts | port -> parts @ [ "port"; string_of_port port ] in
           let parts = parts @ [ "->"; string_of_reference rdr.translation ] in
           let parts =
             match rdr.translation_port with Port_any -> parts | port -> parts @ [ "port"; string_of_port port ]
           in
           String.concat " " parts)
  in
  let format_rule (rule : rule) =
    let parts = [ string_of_action rule.action ] in
    let parts =
      match rule.direction with None -> parts | Some direction -> parts @ [ string_of_direction direction ]
    in
    let parts =
      match rule.interface with
      | None -> parts
      | Some interface -> parts @ [ "on"; string_of_reference interface ]
    in
    let parts =
      match rule.protocol with
      | Proto_any -> parts
      | Proto_named name -> parts @ [ "proto"; name ]
    in
    let parts = parts @ [ "from"; string_of_reference rule.source; "to"; string_of_reference rule.destination ] in
    let parts = match rule.port with Port_any -> parts | port -> parts @ [ "port"; string_of_port port ] in
    let parts = if rule.keep_state then parts @ [ "keep"; "state" ] else parts in
    String.concat " " parts
  in
  let rule_lines = List.map format_rule policy.rules in
  [ default_lines; macro_lines; interface_lines; table_lines; nat_lines @ rdr_lines; rule_lines ]
  |> List.filter (fun group -> group <> [])
  |> List.map (String.concat "\n")
  |> String.concat "\n\n"
  |> fun formatted -> formatted ^ "\n"

let format = format_policy

let severity_to_string = function Diag_error -> "error" | Diag_warning -> "warning"

let diagnostic_to_string (diagnostic : diagnostic) =
  let location =
    match diagnostic.span.file with
    | None -> Printf.sprintf "%d:%d" diagnostic.span.line diagnostic.span.column
    | Some file -> Printf.sprintf "%s:%d:%d" file diagnostic.span.line diagnostic.span.column
  in
  Printf.sprintf "%s: %s: %s" location (severity_to_string diagnostic.severity)
    diagnostic.message

let format_check_result result =
  let diagnostics = List.map diagnostic_to_string result.diagnostics in
  match result.policy with
  | None -> String.concat "\n" diagnostics
  | Some policy ->
      let summary =
        Printf.sprintf "ok: %d interface(s), %d macro(s), %d table(s), %d rule(s)"
          (List.length policy.interfaces) (List.length policy.macros)
          (List.length policy.tables) (List.length policy.rules)
      in
      String.concat "\n" (summary :: diagnostics)
