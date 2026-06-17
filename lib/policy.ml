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
  interface_span : span option;
  protocol : protocol;
  protocol_span : span option;
  source : reference;
  source_span : span;
  destination : reference;
  destination_span : span;
  port : port;
  port_span : span option;
  keep_state : bool;
  queue : string option;
  queue_span : span option;
  route_to : (reference * reference option) option;
  route_to_span : span option;
  route_to_gateway_span : span option;
  route_to_interface_span : span option;
  span : span;
}

type nat = {
  interface : reference;
  interface_span : span;
  protocol : protocol;
  protocol_span : span option;
  source : reference;
  source_span : span;
  destination : reference;
  destination_span : span;
  translation : reference;
  translation_span : span;
  span : span;
}

type rdr = {
  interface : reference;
  interface_span : span;
  protocol : protocol;
  protocol_span : span option;
  source : reference;
  source_span : span;
  destination : reference;
  destination_span : span;
  port : port;
  port_span : span option;
  translation : reference;
  translation_span : span;
  translation_port : port;
  translation_port_span : span option;
  span : span;
}

type queue = {
  name : string;
  name_span : span;
  interface : reference;
  interface_span : span;
  bandwidth : string;
  bandwidth_span : span option;
  parent : string option;
  parent_span : span option;
  span : span;
}

type policy = {
  default_action : default_action option;
  interfaces : interface_decl list;
  macros : macro list;
  tables : table list;
  nats : nat list;
  rdrs : rdr list;
  queues : queue list;
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
    queues = [];
    rules = [];
  }

let trim = String.trim

let span ?file line column end_column = { file; line; column; end_column }

let line_span ?file line text = span ?file line 1 (max 1 (String.length text + 1))

let diagnostic severity span message = { severity; span; message }

let syntax_error span message = diagnostic Diag_error span message

let starts_with ~prefix text =
  let prefix_len = String.length prefix in
  String.length text >= prefix_len && String.sub text 0 prefix_len = prefix

let is_space = function ' ' | '\t' | '\r' | '\n' -> true | _ -> false

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

type token = {
  text : string;
  span : span;
}

let token ?file line start finish text =
  { text; span = span ?file line (start + 1) (finish + 1) }

let is_punctuation = function '{' | '}' | ',' | '=' | '(' | ')' -> true | _ -> false

let is_token_boundary text index =
  index >= String.length text || is_space text.[index] || text.[index] = '#'
  || is_punctuation text.[index]
  || (text.[index] = '-' && index + 1 < String.length text && text.[index + 1] = '>')

let lex_line ?file line original =
  let len = String.length original in
  let rec loop index tokens diagnostics =
    if index >= len then (List.rev tokens, List.rev diagnostics)
    else
      match original.[index] with
      | '#' -> (List.rev tokens, List.rev diagnostics)
      | c when is_space c -> loop (index + 1) tokens diagnostics
      | '"' ->
          let rec find_quote cursor =
            if cursor >= len then None
            else if original.[cursor] = '"' then Some cursor
            else find_quote (cursor + 1)
          in
          let finish, diagnostics =
            match find_quote (index + 1) with
            | Some close -> (close + 1, diagnostics)
            | None ->
                let diag =
                  syntax_error (span ?file line (index + 1) (len + 1))
                    "unterminated quoted string"
                in
                (len, diag :: diagnostics)
          in
          let text = String.sub original index (finish - index) in
          loop finish (token ?file line index finish text :: tokens) diagnostics
      | '-' when index + 1 < len && original.[index + 1] = '>' ->
          loop (index + 2) (token ?file line index (index + 2) "->" :: tokens) diagnostics
      | c when is_punctuation c ->
          loop (index + 1)
            (token ?file line index (index + 1) (String.make 1 c) :: tokens)
            diagnostics
      | _ ->
          let rec finish_word cursor =
            if is_token_boundary original cursor then cursor else finish_word (cursor + 1)
          in
          let finish = finish_word index in
          let text = String.sub original index (finish - index) in
          loop finish (token ?file line index finish text :: tokens) diagnostics
  in
  loop 0 [] []

let last_token tokens =
  match List.rev tokens with [] -> None | token :: _ -> Some token

let span_of_tokens fallback = function
  | [] -> fallback
  | first :: _ as tokens -> (
      match last_token tokens with
      | None -> fallback
      | Some last -> { first.span with end_column = last.span.end_column })

let text_is expected token = String.equal token.text expected

let has_token expected tokens = List.exists (text_is expected) tokens

let add_diagnostics diagnostics new_diagnostics =
  List.fold_left (fun diagnostics diagnostic -> diagnostic :: diagnostics) diagnostics
    new_diagnostics

let parse_reference_token token = parse_reference token.text

let parse_port_token token =
  match parse_port token.text with
  | Ok port -> Ok (port, token.span)
  | Error message -> Error (token.span, message)

let parse_default original tokens policy diagnostics =
  let statement_span = span_of_tokens (line_span 1 original) tokens in
  match tokens with
  | [ set_token; default_token; action_token ]
    when text_is "set" set_token && text_is "default" default_token -> (
      match action_token.text with
      | "deny" -> ({ policy with default_action = Some Default_deny }, diagnostics)
      | "pass" -> ({ policy with default_action = Some Default_pass }, diagnostics)
      | _ ->
          ( policy,
            add_diagnostic diagnostics
              (syntax_error action_token.span
                 "expected default action `deny` or `pass`") ))
  | _ ->
      ( policy,
        add_diagnostic diagnostics
          (syntax_error statement_span
             "expected `set default deny` or `set default pass`") )

let parse_interface original tokens policy diagnostics =
  let statement_span = span_of_tokens (line_span 1 original) tokens in
  match tokens with
  | [ keyword; name; equals; device ]
    when text_is "interface" keyword && text_is "=" equals ->
      if not (valid_name name.text) then
        ( policy,
          add_diagnostic diagnostics
            (syntax_error name.span ("invalid interface name `" ^ name.text ^ "`")) )
      else
        let interface =
          { name = name.text; device = strip_quotes device.text; span = statement_span }
        in
        ({ policy with interfaces = interface :: policy.interfaces }, diagnostics)
  | _ ->
      ( policy,
        add_diagnostic diagnostics
          (syntax_error statement_span "expected `interface <name> = \"device\"`") )

let split_on_equals tokens =
  let rec loop before = function
    | [] -> None
    | token :: rest when text_is "=" token -> Some (List.rev before, token, rest)
    | token :: rest -> loop (token :: before) rest
  in
  loop [] tokens

let parse_macro original tokens policy diagnostics =
  let statement_span = span_of_tokens (line_span 1 original) tokens in
  match split_on_equals tokens with
  | Some ([ name ], equals, value_tokens) ->
      if not (valid_name name.text) then
        ( policy,
          add_diagnostic diagnostics
            (syntax_error name.span ("invalid macro name `" ^ name.text ^ "`")) )
      else if value_tokens = [] then
        ( policy,
          add_diagnostic diagnostics
            (syntax_error equals.span ("macro `" ^ name.text ^ "` has no value")) )
      else
        let value =
          value_tokens |> List.map (fun token -> token.text) |> String.concat " " |> trim
        in
        let macro = { name = name.text; value = strip_quotes value; span = statement_span } in
        ({ policy with macros = macro :: policy.macros }, diagnostics)
  | _ ->
      ( policy,
        add_diagnostic diagnostics
          (syntax_error statement_span "expected `<name> = <value>`") )

let parse_table_entries tokens =
  let rec loop entries expecting_entry = function
    | [] -> Ok (List.rev entries)
    | token :: rest when text_is "," token ->
        if expecting_entry then Error (token.span, "empty table entry")
        else loop entries true rest
    | token :: rest ->
        if expecting_entry then loop (token.text :: entries) false rest
        else Error (token.span, "expected `,` between table entries")
  in
  loop [] true tokens

let parse_table original tokens policy diagnostics =
  let statement_span = span_of_tokens (line_span 1 original) tokens in
  let error message =
    (policy, add_diagnostic diagnostics (syntax_error statement_span message))
  in
  match tokens with
  | keyword :: name_token :: open_token :: rest
    when text_is "table" keyword && text_is "{" open_token -> (
      match parse_table_name name_token.text with
      | Some name when valid_name name -> (
          let rec collect_body body = function
            | [] -> Error (statement_span, "expected closing `}`")
            | close_token :: after_close when text_is "}" close_token ->
                if after_close = [] then Ok (List.rev body)
                else
                  let extra = List.hd after_close in
                  Error (extra.span, "unexpected token after table declaration")
            | token :: rest -> collect_body (token :: body) rest
          in
          match collect_body [] rest with
          | Error (span, message) ->
              (policy, add_diagnostic diagnostics (syntax_error span message))
          | Ok body -> (
              match parse_table_entries body with
              | Error (span, message) ->
                  (policy, add_diagnostic diagnostics (syntax_error span message))
              | Ok entries ->
                  let table = { name; entries; span = statement_span } in
                  ({ policy with tables = table :: policy.tables }, diagnostics)))
      | Some name ->
          ( policy,
            add_diagnostic diagnostics
              (syntax_error name_token.span ("invalid table name `" ^ name ^ "`")) )
      | None ->
          ( policy,
            add_diagnostic diagnostics
              (syntax_error name_token.span "expected table name like `<trusted>`") ))
  | _ -> error "expected `table <name> { entries }`"

let missing_after keyword token = (token.span, "missing value after `" ^ keyword ^ "`")

let parse_rule original tokens policy diagnostics =
  match tokens with
  | action_token :: rest -> (
      let rule_span = span_of_tokens (line_span 1 original) tokens in
      match parse_action action_token.text with
      | None ->
          ( policy,
            add_diagnostic diagnostics
              (syntax_error action_token.span "expected rule to start with `pass` or `block`") )
      | Some action ->
          let initial : rule =
            {
              action;
              direction = None;
              interface = None;
              interface_span = None;
              protocol = Proto_any;
              protocol_span = None;
              source = Any;
              source_span = action_token.span;
              destination = Any;
              destination_span = action_token.span;
              port = Port_any;
              port_span = None;
              keep_state = false;
              queue = None;
              queue_span = None;
              route_to = None;
              route_to_span = None;
              route_to_gateway_span = None;
              route_to_interface_span = None;
              span = rule_span;
            }
          in
          let rec loop (state : rule) source_seen destination_seen port_seen = function
            | [] -> Ok state
            | token :: rest when text_is "in" token -> (
                match state.direction with
                | Some _ -> Error (token.span, "duplicate direction")
                | None ->
                    loop { state with direction = Some In } source_seen destination_seen
                      port_seen rest)
            | token :: rest when text_is "out" token -> (
                match state.direction with
                | Some _ -> Error (token.span, "duplicate direction")
                | None ->
                    loop { state with direction = Some Out } source_seen destination_seen
                      port_seen rest)
            | token :: [] when text_is "on" token -> Error (missing_after "on" token)
            | token :: value :: rest when text_is "on" token -> (
                match state.interface_span with
                | Some _ -> Error (token.span, "duplicate interface matcher")
                | None ->
                    loop
                      {
                        state with
                        interface = Some (parse_reference_token value);
                        interface_span = Some value.span;
                      }
                      source_seen destination_seen port_seen rest)
            | token :: [] when text_is "proto" token -> Error (missing_after "proto" token)
            | token :: value :: rest when text_is "proto" token -> (
                match state.protocol_span with
                | Some _ -> Error (token.span, "duplicate protocol matcher")
                | None ->
                    loop
                      {
                        state with
                        protocol = Proto_named value.text;
                        protocol_span = Some value.span;
                      }
                      source_seen destination_seen port_seen rest)
            | token :: [] when text_is "from" token -> Error (missing_after "from" token)
            | token :: value :: rest when text_is "from" token ->
                if source_seen then Error (token.span, "duplicate source matcher")
                else
                  loop
                    {
                      state with
                      source = parse_reference_token value;
                      source_span = value.span;
                    }
                    true destination_seen port_seen rest
            | token :: [] when text_is "to" token -> Error (missing_after "to" token)
            | token :: value :: rest when text_is "to" token ->
                if destination_seen then Error (token.span, "duplicate destination matcher")
                else
                  loop
                    {
                      state with
                      destination = parse_reference_token value;
                      destination_span = value.span;
                    }
                    source_seen true port_seen rest
            | token :: [] when text_is "port" token -> Error (missing_after "port" token)
            | token :: value :: rest when text_is "port" token ->
                if port_seen then Error (token.span, "duplicate port matcher")
                else (
                  match parse_port_token value with
                  | Ok (port, port_span) ->
                      loop { state with port; port_span = Some port_span } source_seen
                        destination_seen true rest
                  | Error error -> Error error)
            | token :: [] when text_is "queue" token -> Error (missing_after "queue" token)
            | token :: value :: rest when text_is "queue" token -> (
                match state.queue_span with
                | Some _ -> Error (token.span, "duplicate queue assignment")
                | None ->
                    loop { state with queue = Some value.text; queue_span = Some value.span }
                      source_seen destination_seen port_seen rest)
            | token :: [] when text_is "route-to" token -> Error (missing_after "route-to" token)
            | token :: value :: rest when text_is "route-to" token -> (
                match state.route_to_span with
                | Some _ -> Error (token.span, "duplicate route-to assignment")
                | None ->
                    let gateway = parse_reference_token value in
                    let parse_interface rest =
                      match rest with
                      | [] -> Ok (None, None, [])
                      | close :: _ when text_is ")" close ->
                          Error (close.span, "unexpected `)` after route-to gateway")
                      | open_token :: rest when text_is "(" open_token -> (
                          match rest with
                          | [] -> Error (open_token.span, "missing interface after `(`")
                          | iface :: [] ->
                              Error
                                (iface.span, "expected closing `)` after route-to interface")
                          | iface :: closing :: rest when text_is ")" closing ->
                              Ok (Some (parse_reference_token iface), Some iface.span, rest)
                          | _iface :: unexpected :: _ ->
                              Error
                                ( unexpected.span,
                                  "expected closing `)` after route-to interface" ))
                      | _ -> Ok (None, None, rest)
                    in
                    match parse_interface rest with
                    | Error error -> Error error
                    | Ok (interface, interface_span, rest) ->
                        loop
                          {
                            state with
                            route_to = Some (gateway, interface);
                            route_to_span = Some token.span;
                            route_to_gateway_span = Some value.span;
                            route_to_interface_span = interface_span;
                          }
                          source_seen destination_seen port_seen rest)
            | token :: [] when text_is "keep" token ->
                Error (token.span, "missing `state` after `keep`")
            | token :: value :: rest when text_is "keep" token ->
                if not (text_is "state" value) then
                  Error (value.span, "expected `state` after `keep`")
                else if state.keep_state then Error (token.span, "duplicate `keep state`")
                else
                  loop { state with keep_state = true } source_seen destination_seen port_seen
                    rest
            | token :: _ -> Error (token.span, "unexpected token `" ^ token.text ^ "`")
          in
          (match loop initial false false false rest with
          | Ok rule -> ({ policy with rules = rule :: policy.rules }, diagnostics)
          | Error (span, message) ->
              ( policy,
                add_diagnostic diagnostics (syntax_error span ("invalid rule: " ^ message)) )))
  | [] -> (policy, diagnostics)

let parse_nat original tokens policy diagnostics =
  match tokens with
  | keyword :: rest when text_is "nat" keyword -> (
      let rule_span = span_of_tokens (line_span 1 original) tokens in
      let initial : nat =
        {
          interface = Any;
          interface_span = rule_span;
          protocol = Proto_any;
          protocol_span = None;
          source = Any;
          source_span = rule_span;
          destination = Any;
          destination_span = rule_span;
          translation = Any;
          translation_span = rule_span;
          span = rule_span;
        }
      in
      let rec loop (state : nat) source_seen destination_seen = function
        | [] -> Error (rule_span, "missing translation `->`")
        | token :: [] when text_is "on" token -> Error (missing_after "on" token)
        | token :: value :: rest when text_is "on" token ->
            if state.interface <> Any then Error (token.span, "duplicate interface matcher")
            else
              loop
                {
                  state with
                  interface = parse_reference_token value;
                  interface_span = value.span;
                }
                source_seen destination_seen rest
        | token :: [] when text_is "proto" token -> Error (missing_after "proto" token)
        | token :: value :: rest when text_is "proto" token -> (
            match state.protocol_span with
            | Some _ -> Error (token.span, "duplicate protocol matcher")
            | None ->
                loop
                  { state with protocol = Proto_named value.text; protocol_span = Some value.span }
                  source_seen destination_seen rest)
        | token :: [] when text_is "from" token -> Error (missing_after "from" token)
        | token :: value :: rest when text_is "from" token ->
            if source_seen then Error (token.span, "duplicate source matcher")
            else
              loop
                { state with source = parse_reference_token value; source_span = value.span }
                true destination_seen rest
        | token :: [] when text_is "to" token -> Error (missing_after "to" token)
        | token :: value :: rest when text_is "to" token ->
            if destination_seen then Error (token.span, "duplicate destination matcher")
            else
              loop
                {
                  state with
                  destination = parse_reference_token value;
                  destination_span = value.span;
                }
                source_seen true rest
        | token :: [] when text_is "->" token -> Error (missing_after "->" token)
        | token :: translation :: rest when text_is "->" token ->
            if rest = [] then
              Ok
                {
                  state with
                  translation = parse_reference_token translation;
                  translation_span = translation.span;
                }
            else
              let extra = List.hd rest in
              Error (extra.span, "unexpected token after translation")
        | token :: _ -> Error (token.span, "unexpected token `" ^ token.text ^ "`")
      in
      match loop initial false false rest with
      | Ok nat -> ({ policy with nats = nat :: policy.nats }, diagnostics)
      | Error (span, message) ->
          (policy, add_diagnostic diagnostics (syntax_error span ("invalid nat: " ^ message))))
  | _ -> (policy, diagnostics)

let parse_rdr original tokens policy diagnostics =
  match tokens with
  | keyword :: rest when text_is "rdr" keyword -> (
      let rule_span = span_of_tokens (line_span 1 original) tokens in
      let initial : rdr =
        {
          interface = Any;
          interface_span = rule_span;
          protocol = Proto_any;
          protocol_span = None;
          source = Any;
          source_span = rule_span;
          destination = Any;
          destination_span = rule_span;
          port = Port_any;
          port_span = None;
          translation = Any;
          translation_span = rule_span;
          translation_port = Port_any;
          translation_port_span = None;
          span = rule_span;
        }
      in
      let rec loop (state : rdr) source_seen destination_seen port_seen = function
        | [] -> Error (rule_span, "missing translation `->`")
        | token :: [] when text_is "on" token -> Error (missing_after "on" token)
        | token :: value :: rest when text_is "on" token ->
            if state.interface <> Any then Error (token.span, "duplicate interface matcher")
            else
              loop
                {
                  state with
                  interface = parse_reference_token value;
                  interface_span = value.span;
                }
                source_seen destination_seen port_seen rest
        | token :: [] when text_is "proto" token -> Error (missing_after "proto" token)
        | token :: value :: rest when text_is "proto" token -> (
            match state.protocol_span with
            | Some _ -> Error (token.span, "duplicate protocol matcher")
            | None ->
                loop
                  { state with protocol = Proto_named value.text; protocol_span = Some value.span }
                  source_seen destination_seen port_seen rest)
        | token :: [] when text_is "from" token -> Error (missing_after "from" token)
        | token :: value :: rest when text_is "from" token ->
            if source_seen then Error (token.span, "duplicate source matcher")
            else
              loop
                { state with source = parse_reference_token value; source_span = value.span }
                true destination_seen port_seen rest
        | token :: [] when text_is "to" token -> Error (missing_after "to" token)
        | token :: value :: rest when text_is "to" token ->
            if destination_seen then Error (token.span, "duplicate destination matcher")
            else
              loop
                {
                  state with
                  destination = parse_reference_token value;
                  destination_span = value.span;
                }
                source_seen true port_seen rest
        | token :: [] when text_is "port" token -> Error (missing_after "port" token)
        | token :: value :: rest when text_is "port" token ->
            if port_seen then Error (token.span, "duplicate port matcher")
            else (
              match parse_port_token value with
              | Ok (port, port_span) ->
                  loop { state with port; port_span = Some port_span } source_seen
                    destination_seen true rest
              | Error error -> Error error)
        | token :: [] when text_is "->" token -> Error (missing_after "->" token)
        | token :: translation :: rest when text_is "->" token ->
            let state =
              {
                state with
                translation = parse_reference_token translation;
                translation_span = translation.span;
              }
            in
            (match rest with
            | [] -> Ok state
            | [ port_keyword; port_value ] when text_is "port" port_keyword -> (
                match parse_port_token port_value with
                | Ok (translation_port, translation_port_span) ->
                    Ok { state with translation_port; translation_port_span = Some translation_port_span }
                | Error error -> Error error)
            | [ port_keyword ] when text_is "port" port_keyword ->
                Error (missing_after "port" port_keyword)
            | extra :: _ -> Error (extra.span, "unexpected token after translation"))
        | token :: _ -> Error (token.span, "unexpected token `" ^ token.text ^ "`")
      in
      match loop initial false false false rest with
      | Ok rdr -> ({ policy with rdrs = rdr :: policy.rdrs }, diagnostics)
      | Error (span, message) ->
          (policy, add_diagnostic diagnostics (syntax_error span ("invalid rdr: " ^ message))))
  | _ -> (policy, diagnostics)

let parse_queue original tokens policy diagnostics =
  let statement_span = span_of_tokens (line_span 1 original) tokens in
  match tokens with
  | keyword :: name :: on_keyword :: interface :: rest
    when text_is "queue" keyword && text_is "on" on_keyword -> (
      let initial =
        {
          name = name.text;
          name_span = name.span;
          interface = parse_reference_token interface;
          interface_span = interface.span;
          bandwidth = "";
          bandwidth_span = None;
          parent = None;
          parent_span = None;
          span = statement_span;
        }
      in
      if not (valid_name name.text) then
        ( policy,
          add_diagnostic diagnostics
            (syntax_error name.span ("invalid queue name `" ^ name.text ^ "`")) )
      else
      let rec loop state = function
        | [] ->
            if state.bandwidth = "" then Error (statement_span, "missing bandwidth") else Ok state
        | token :: [] when text_is "bandwidth" token -> Error (missing_after "bandwidth" token)
        | token :: value :: rest when text_is "bandwidth" token ->
            if Option.is_some state.bandwidth_span then
              Error (token.span, "duplicate bandwidth")
            else loop { state with bandwidth = value.text; bandwidth_span = Some value.span } rest
        | token :: [] when text_is "parent" token -> Error (missing_after "parent" token)
        | token :: value :: rest when text_is "parent" token ->
            if Option.is_some state.parent_span then Error (token.span, "duplicate parent")
            else if not (valid_name value.text) then
              Error (value.span, "invalid parent queue name `" ^ value.text ^ "`")
            else loop { state with parent = Some value.text; parent_span = Some value.span } rest
        | token :: _ -> Error (token.span, "unexpected token `" ^ token.text ^ "`")
      in
      match loop initial rest with
      | Ok queue -> ({ policy with queues = queue :: policy.queues }, diagnostics)
      | Error (span, message) ->
          (policy, add_diagnostic diagnostics (syntax_error span ("invalid queue: " ^ message))))
  | _ ->
      ( policy,
        add_diagnostic diagnostics
          (syntax_error statement_span
             "expected `queue <name> on <interface> bandwidth <value> [parent <name>]`") )

let parse_line ?file line policy diagnostics original =
  let tokens, lexical_diagnostics = lex_line ?file line original in
  let diagnostics = add_diagnostics diagnostics lexical_diagnostics in
  match tokens with
  | [] -> (policy, diagnostics)
  | first :: _ when text_is "set" first -> parse_default original tokens policy diagnostics
  | first :: _ when text_is "interface" first -> parse_interface original tokens policy diagnostics
  | first :: _ when text_is "table" first -> parse_table original tokens policy diagnostics
  | first :: _ when text_is "nat" first -> parse_nat original tokens policy diagnostics
  | first :: _ when text_is "rdr" first -> parse_rdr original tokens policy diagnostics
  | first :: _ when text_is "queue" first -> parse_queue original tokens policy diagnostics
  | first :: _ when text_is "pass" first || text_is "block" first ->
      parse_rule original tokens policy diagnostics
  | _ when has_token "=" tokens -> parse_macro original tokens policy diagnostics
  | first :: _ ->
      ( policy,
        add_diagnostic diagnostics
          (syntax_error first.span
             "unrecognized statement; expected set, interface, table, macro, nat, rdr, queue, pass, or block") )

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
      queues = List.rev policy.queues;
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

let names_of_queues (policy : policy) =
  List.map (fun (queue : queue) -> (queue.name, queue.name_span)) policy.queues

let table_names (policy : policy) = List.map (fun (table : table) -> table.name) policy.tables
let macro_names (policy : policy) = List.map (fun (macro : macro) -> macro.name) policy.macros

let interface_names (policy : policy) =
  List.map (fun (interface : interface_decl) -> interface.name) policy.interfaces

let queue_names (policy : policy) = List.map (fun (queue : queue) -> queue.name) policy.queues

let validate_reference ~tables ~macros span context = function
  | Any | Literal _ -> []
  | Table_ref name ->
      if List.mem name tables then []
      else [ diagnostic Diag_error span (context ^ " references unknown table `<" ^ name ^ ">`") ]
  | Macro_ref name ->
      if List.mem name macros then []
      else [ diagnostic Diag_error span (context ^ " references unknown macro `$" ^ name ^ "`") ]

let validate_interface_reference ?(context = "rule") ~interfaces ~macros span = function
  | None -> []
  | Some Any ->
      [ diagnostic Diag_error span (context ^ " cannot use `any` as an interface matcher") ]
  | Some (Literal name) ->
      if List.mem name interfaces then []
      else
        [ diagnostic Diag_error span (context ^ " references unknown interface `" ^ name ^ "`") ]
  | Some (Macro_ref name) ->
      if List.mem name macros then []
      else
        [
          diagnostic Diag_error span
            (context ^ " references unknown interface macro `$" ^ name ^ "`");
        ]
  | Some (Table_ref name) ->
      [ diagnostic Diag_error span (context ^ " interface matcher cannot use table `<" ^ name ^ ">`") ]

let validate_port ~macros span = function
  | Port_any | Port_number _ -> []
  | Port_macro name ->
      if List.mem name macros then []
      else [ diagnostic Diag_error span ("port references unknown macro `$" ^ name ^ "`") ]

let validate_queue_reference ~queues span = function
  | None -> []
  | Some name ->
      if List.mem name queues then []
      else [ diagnostic Diag_error span ("rule references unknown queue `" ^ name ^ "`") ]

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
  let diagnostics =
    has_duplicate (names_of_queues policy)
    |> List.fold_left
         (fun diagnostics (name, span) ->
           diagnostic Diag_error span ("duplicate queue `" ^ name ^ "`") :: diagnostics)
         diagnostics
  in
  let tables = table_names policy in
  let macros = macro_names policy in
  let interfaces = interface_names policy in
  let queues = queue_names policy in
  let rule_diagnostics =
    (policy.rules
    |> List.concat_map (fun (rule : rule) ->
           validate_reference ~tables ~macros rule.source_span "rule source" rule.source
           @ validate_reference ~tables ~macros rule.destination_span "rule destination"
               rule.destination
           @ validate_interface_reference ~interfaces ~macros
               (Option.value rule.interface_span ~default:rule.span)
               rule.interface
           @ validate_port ~macros (Option.value rule.port_span ~default:rule.span) rule.port
           @ validate_queue_reference ~queues
               (Option.value rule.queue_span ~default:rule.span)
               rule.queue
           @ (match rule.route_to with
             | None -> []
             | Some (gateway, interface) ->
                 validate_reference ~tables ~macros
                   (Option.value rule.route_to_gateway_span ~default:rule.span)
                   "route-to gateway" gateway
                 @ validate_interface_reference ~context:"route-to" ~interfaces ~macros
                     (Option.value rule.route_to_interface_span ~default:rule.span)
                     interface)))
    @ (policy.nats
      |> List.concat_map (fun (nat : nat) ->
             validate_reference ~tables ~macros nat.source_span "nat source" nat.source
             @ validate_reference ~tables ~macros nat.destination_span "nat destination"
                 nat.destination
             @ validate_interface_reference ~context:"nat" ~interfaces ~macros nat.interface_span
                 (Some nat.interface)
             @ validate_reference ~tables ~macros nat.translation_span "nat translation"
                 nat.translation))
    @ (policy.rdrs
      |> List.concat_map (fun (rdr : rdr) ->
             validate_reference ~tables ~macros rdr.source_span "rdr source" rdr.source
             @ validate_reference ~tables ~macros rdr.destination_span "rdr destination"
                 rdr.destination
             @ validate_interface_reference ~context:"rdr" ~interfaces ~macros rdr.interface_span
                 (Some rdr.interface)
             @ validate_reference ~tables ~macros rdr.translation_span "rdr translation"
                 rdr.translation
             @ validate_port ~macros (Option.value rdr.port_span ~default:rdr.span) rdr.port
             @ validate_port ~macros
                 (Option.value rdr.translation_port_span ~default:rdr.span)
                 rdr.translation_port))
    @ (policy.queues
      |> List.concat_map (fun (queue : queue) ->
             let parent_diagnostics =
               match queue.parent with
               | None -> []
               | Some parent when String.equal parent queue.name ->
                   [
                     diagnostic Diag_error
                       (Option.value queue.parent_span ~default:queue.span)
                       "queue parent cannot reference itself";
                   ]
               | Some parent ->
                   if List.mem parent queues then []
                   else
                     [
                       diagnostic Diag_error
                         (Option.value queue.parent_span ~default:queue.span)
                         ("queue references unknown parent `" ^ parent ^ "`");
                     ]
             in
             validate_interface_reference ~context:"queue" ~interfaces ~macros
               queue.interface_span (Some queue.interface)
             @ parent_diagnostics))
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
  let queue_lines =
    policy.queues
    |> List.map (fun (queue : queue) ->
           let parts = [ "queue"; queue.name; "on"; string_of_reference queue.interface; "bandwidth"; queue.bandwidth ] in
           let parts =
             match queue.parent with
             | None -> parts
             | Some parent -> parts @ [ "parent"; parent ]
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
    let parts =
      match rule.queue with
      | None -> parts
      | Some name -> parts @ [ "queue"; name ]
    in
    let parts =
      match rule.route_to with
      | None -> parts
      | Some (gateway, interface) ->
          let target =
            match interface with
            | None -> string_of_reference gateway
            | Some iface -> string_of_reference gateway ^ " (" ^ string_of_reference iface ^ ")"
          in
          parts @ [ "route-to"; target ]
    in
    let parts = if rule.keep_state then parts @ [ "keep"; "state" ] else parts in
    String.concat " " parts
  in
  let rule_lines = List.map format_rule policy.rules in
  [ default_lines; macro_lines; interface_lines; table_lines; queue_lines; nat_lines @ rdr_lines; rule_lines ]
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
        Printf.sprintf
          "ok: %d interface(s), %d macro(s), %d table(s), %d queue(s), %d nat(s), %d rdr(s), %d rule(s)"
          (List.length policy.interfaces) (List.length policy.macros)
          (List.length policy.tables) (List.length policy.queues)
          (List.length policy.nats) (List.length policy.rdrs) (List.length policy.rules)
      in
      String.concat "\n" (summary :: diagnostics)
