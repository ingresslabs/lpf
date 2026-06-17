type expectation = {
  packet : Explain.packet;
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
  | Fail of { actual : Policy.action; explanation : Explain.explanation }

val run_suite : Ir.t -> test_suite -> (test_case * test_result list) list
val to_junit : (test_case * test_result list) list -> string
