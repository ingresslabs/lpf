open Test_engine

let parse ?file text =
  let lines = String.split_on_char '\n' text in
  let rec loop suite current_case = function
    | [] ->
        let suite =
          match current_case with
          | Some case -> { suite with cases = suite.cases @ [ case ] }
          | None -> suite
        in
        Ok suite
    | line :: rest ->
        let line = String.trim line in
        if line = "" || String.starts_with ~prefix:"#" line then loop suite current_case rest
        else if String.starts_with ~prefix:"policy:" line then
          let policy_file = String.trim (String.sub line 7 (String.length line - 7)) in
          loop { suite with policy_file } current_case rest
        else if String.starts_with ~prefix:"test:" line then
          let name = String.trim (String.sub line 5 (String.length line - 5)) in
          let suite =
            match current_case with
            | Some case -> { suite with cases = suite.cases @ [ case ] }
            | None -> suite
          in
          loop suite (Some { name; expectations = [] }) rest
        else if String.starts_with ~prefix:"expect" line then
          match current_case with
          | None -> Error [ { Policy.severity = Diag_error; span = { file; line = 0; column = 1; end_column = 1 }; message = "expect outside of test case" } ]
          | Some case ->
              let parts = String.split_on_char ' ' line in
              let rec parse_expect expect = function
                | [] -> expect
                | "expect" :: action :: rest ->
                    let expect_decision = if action = "pass" then Policy.Pass else Policy.Block in
                    parse_expect { expect with expect_decision } rest
                | "in" :: rest -> parse_expect { expect with packet = { expect.packet with direction = Policy.In } } rest
                | "out" :: rest -> parse_expect { expect with packet = { expect.packet with direction = Policy.Out } } rest
                | "on" :: iface :: rest -> parse_expect { expect with packet = { expect.packet with interface = iface } } rest
                | "from" :: addr :: rest -> parse_expect { expect with packet = { expect.packet with source = addr } } rest
                | "to" :: addr :: rest -> parse_expect { expect with packet = { expect.packet with destination = addr } } rest
                | "proto" :: proto :: rest ->
                    let p = if proto = "any" then Policy.Proto_any else Policy.Proto_named proto in
                    parse_expect { expect with packet = { expect.packet with protocol = p } } rest
                | "port" :: port :: rest ->
                    let p = int_of_string_opt port in
                    parse_expect { expect with packet = { expect.packet with port = p } } rest
                | _ :: rest -> parse_expect expect rest
              in
              let initial_expect = {
                packet = {
                  direction = Policy.In;
                  interface = "eth0";
                  protocol = Policy.Proto_any;
                  source = "0.0.0.0";
                  destination = "0.0.0.0";
                  port = None;
                };
                expect_decision = Policy.Pass;
              } in
              let expect = parse_expect initial_expect parts in
              loop suite (Some { case with expectations = case.expectations @ [ expect ] }) rest
        else loop suite current_case rest
  in
  loop { policy_file = ""; cases = [] } None lines
