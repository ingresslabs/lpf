open Explain

type expectation = { packet : packet; expect_decision : Policy.action }
type test_case = { name : string; expectations : expectation list }
type test_suite = { policy_file : string; cases : test_case list }

type test_result =
  | Pass
  | Fail of {
      expected : Policy.action;
      actual : Policy.action;
      explanation : explanation;
    }

let run_suite (ir : Ir.t) (suite : test_suite) =
  List.map
    (fun (case : test_case) ->
      let results =
        List.map
          (fun (expect : expectation) ->
            let explanation = explain ir expect.packet in
            if explanation.decision = expect.expect_decision then Pass
            else
              Fail
                {
                  expected = expect.expect_decision;
                  actual = explanation.decision;
                  explanation;
                })
          case.expectations
      in
      (case, results))
    suite.cases

let to_junit results =
  let escape_xml text =
    let buffer = Buffer.create (String.length text) in
    String.iter
      (function
        | '&' -> Buffer.add_string buffer "&amp;"
        | '<' -> Buffer.add_string buffer "&lt;"
        | '>' -> Buffer.add_string buffer "&gt;"
        | '"' -> Buffer.add_string buffer "&quot;"
        | '\'' -> Buffer.add_string buffer "&apos;"
        | character -> Buffer.add_char buffer character)
      text;
    Buffer.contents buffer
  in
  let buffer = Buffer.create 4096 in
  Buffer.add_string buffer "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
  Buffer.add_string buffer "<testsuites>\n";
  List.iter
    (fun (case, results) ->
      Buffer.add_string buffer
        (Printf.sprintf "  <testsuite name=\"%s\">\n" (escape_xml case.name));
      List.iteri
        (fun i result ->
          Buffer.add_string buffer
            (Printf.sprintf "    <testcase name=\"expectation_%d\">\n" i);
          (match result with
          | Pass -> ()
          | Fail { expected; actual; explanation } ->
              Buffer.add_string buffer
                (Printf.sprintf
                   "      <failure message=\"Expected %s but got %s\">\n"
                   (Policy.string_of_action expected)
                   (Policy.string_of_action actual));
              Buffer.add_string buffer
                (escape_xml (Explain.to_string explanation));
              Buffer.add_string buffer "\n      </failure>\n");
          Buffer.add_string buffer "    </testcase>\n")
        results;
      Buffer.add_string buffer "  </testsuite>\n")
    results;
  Buffer.add_string buffer "</testsuites>\n";
  Buffer.contents buffer
