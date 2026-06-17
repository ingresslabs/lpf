open Explain

type expectation = {
  packet : packet;
  expect_decision : Policy.action;
}

type test_case = {
  name : string;
  expectations : expectation list;
}

type test_suite = {
  policy_file : string;
  cases : test_case list;
}

type test_result =
  | Pass
  | Fail of { actual : Policy.action; explanation : explanation }

let run_suite (ir : Ir.t) (suite : test_suite) =
  List.map (fun (case : test_case) ->
    let results = List.map (fun (expect : expectation) ->
      let explanation = explain ir expect.packet in
      if explanation.decision = expect.expect_decision then Pass
      else Fail { actual = explanation.decision; explanation }
    ) case.expectations in
    (case, results)
  ) suite.cases

let to_junit results =
  (* Basic JUnit XML generation *)
  let buffer = Buffer.create 4096 in
  Buffer.add_string buffer "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
  Buffer.add_string buffer "<testsuites>\n";
  List.iter (fun (case, results) ->
    Buffer.add_string buffer (Printf.sprintf "  <testsuite name=\"%s\">\n" (Json_util.string case.name));
    List.iteri (fun i result ->
      Buffer.add_string buffer (Printf.sprintf "    <testcase name=\"expectation_%d\">\n" i);
      (match result with
       | Pass -> ()
       | Fail { actual; explanation } ->
           Buffer.add_string buffer (Printf.sprintf "      <failure message=\"Expected %s but got %s\">\n"
             (if actual = Pass then "block" else "pass") (if actual = Pass then "pass" else "block"));
           Buffer.add_string buffer (Explain.to_string explanation);
           Buffer.add_string buffer "\n      </failure>\n");
      Buffer.add_string buffer "    </testcase>\n"
    ) results;
    Buffer.add_string buffer "  </testsuite>\n"
  ) results;
  Buffer.add_string buffer "</testsuites>\n";
  Buffer.contents buffer
