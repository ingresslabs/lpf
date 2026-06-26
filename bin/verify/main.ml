let () =
  let usage_msg =
    "lpf-verify - formally verify lpf policy properties with Z3\n\n\
     usage: lpf-verify <command> [options] <policy.lpf>\n\n\
     commands:\n\
     consistency     find dead/shadowed rules\n\
     equivalence     prove two policies are equivalent\n\
     reachable        check if target action is reachable from constraints\n\
     invariant       prove a logical invariant holds\n\
     minimize        find minimal semantically-equivalent rule set\n\
     coverage        symbolic reverse-explanation of rule coverage\n\
     gen-tests       auto-generate test fixtures\n\
     backend-ebpf    prove eBPF backend is semantically equivalent\n\
     check-all       run all checks on a single policy\n\
     options:\n\
     --file, -f      policy file path (alternative to positional arg)\n\
     --second, -s     second policy file (for equivalence)\n\
     --action, -a    target action for reachability (pass/block/reject)\n\
     --constraint, -c constraints (src=ip,dst=ip,port=n,proto=tcp)\n\
     --invariant, -i invariant clause (for invariant command)\n"
  in

  let args = ref [] in
  let policy_file = ref None in
  let second_file = ref None in
  let target_action = ref None in
  let constraints = ref [] in
  let invariants = ref [] in

  let set_policy_file s = policy_file := Some s in
  let set_second_file s = second_file := Some s in
  let set_action s = target_action := Some s in
  let add_constraint s = constraints := s :: !constraints in
  let add_invariant s = invariants := s :: !invariants in

  let speclist =
    [
      ("--file", Arg.String set_policy_file, "FILE Policy file");
      ("-f", Arg.String set_policy_file, "FILE Policy file");
      ( "--second",
        Arg.String set_second_file,
        "FILE Second policy file (for equivalence)" );
      ("-s", Arg.String set_second_file, "FILE Second policy file");
      ( "--action",
        Arg.String set_action,
        "ACTION Target action: pass/block/reject" );
      ("-a", Arg.String set_action, "ACTION Target action");
      ( "--constraint",
        Arg.String add_constraint,
        "K=V Constraint (src=10.0.0.1,dst=10.0.0.2,port=443,proto=tcp)" );
      ("-c", Arg.String add_constraint, "K=V Constraint");
      ("--invariant", Arg.String add_invariant, "K=V Invariant clause");
      ("-i", Arg.String add_invariant, "K=V Invariant clause");
    ]
  in

  Arg.parse speclist (fun a -> args := a :: !args) usage_msg;

  let args = List.rev !args in
  let cmd =
    match args with
    | [] ->
        Printf.eprintf "lpf-verify: no command specified\n%s" usage_msg;
        exit 64
    | cmd :: rest ->
        (if policy_file = None then
           match rest with f :: _ -> policy_file := Some f | _ -> ());
        cmd
  in

  let read_policy path =
    match Lpf.File_util.read_file path with
    | exception _ ->
        Printf.eprintf "lpf-verify: cannot read %s\n" path;
        exit 1
    | text -> text
  in

  let parse_ir text =
    match Lpf.Pipeline.ir_of_policy (Lpf.Policy.parse_exn text) with
    | Ok ir -> ir
    | Error diagnostics ->
        Printf.eprintf "lpf-verify: policy parse error\n";
        List.iter
          (fun (d : Lpf.Policy.diagnostic) -> Printf.eprintf "  %s\n" d.message)
          diagnostics;
        exit 1
  in

  let parse_constraints () =
    let cls = ref [] in
    List.iter
      (fun c ->
        let parts = String.split_on_char ',' c in
        List.iter
          (fun pair ->
            match String.split_on_char '=' pair with
            | [ k; v ] -> cls := (String.trim k, String.trim v) :: !cls
            | _ ->
                Printf.eprintf "warning: ignoring malformed constraint: %s\n"
                  pair)
          parts)
      !constraints;
    List.rev !cls
  in

  let parse_invariants () =
    let invs = ref [] in
    List.iter
      (fun inv ->
        let parts = String.split_on_char ',' inv in
        List.iter
          (fun pair ->
            match String.split_on_char '=' pair with
            | [ field; value ] ->
                let clause =
                  Lpf_z3.Z3_verify.(
                    Field (String.trim field, "==", String.trim value))
                in
                invs := clause :: !invs
            | _ ->
                Printf.eprintf "warning: ignoring malformed invariant: %s\n"
                  pair)
          parts)
      !invariants;
    List.rev !invs
  in

  match cmd with
  | "consistency" ->
      let file =
        match !policy_file with
        | Some f -> f
        | None ->
            Printf.eprintf "no policy file\n";
            exit 64
      in
      let text = read_policy file in
      let ir = parse_ir text in
      Printf.printf "checking consistency for %s...\n%!" file;
      let dead_rules = Lpf_z3.Z3_verify.check_consistency ir in
      if dead_rules = [] then (
        Printf.printf "PASS: no dead or shadowed rules found\n";
        exit 0)
      else (
        Printf.printf "FOUND %d dead/shadowed rule(s):\n"
          (List.length dead_rules);
        List.iter
          (fun (dr : Lpf_z3.Z3_verify.dead_rule) ->
            Printf.printf "  rule at line %d is shadowed: %s\n" dr.line
              dr.reason)
          dead_rules;
        exit 1)
  | "equivalence" -> (
      let file1 =
        match !policy_file with
        | Some f -> f
        | None ->
            Printf.eprintf "no first policy\n";
            exit 64
      in
      let file2 =
        match !second_file with
        | Some f -> f
        | None ->
            Printf.eprintf "no second policy (use -s)\n";
            exit 64
      in
      let ir1 = parse_ir (read_policy file1) in
      let ir2 = parse_ir (read_policy file2) in
      Printf.printf "checking equivalence: %s <=> %s\n%!" file1 file2;
      match Lpf_z3.Z3_verify.check_equivalence ir1 ir2 with
      | Lpf_z3.Z3_verify.Equivalent ->
          Printf.printf "PASS: policies are semantically equivalent\n";
          exit 0
      | Lpf_z3.Z3_verify.Not_equivalent ne ->
          Printf.printf "FAIL: policies are NOT equivalent\n";
          Printf.printf
            "  counterexample: src=%s dst=%s port=%d decision1=%s decision2=%s\n"
            ne.counterexample.source ne.counterexample.destination
            (match ne.counterexample.port with Some p -> p | None -> 0)
            ne.decision_in_first ne.decision_in_second;
          exit 1
      | "reachable" -> (
          let file =
            match !policy_file with
            | Some f -> f
            | None ->
                Printf.eprintf "no policy file\n";
                exit 64
          in
          let action_str =
            match !target_action with
            | Some a -> a
            | None ->
                Printf.eprintf "no target action (use -a)\n";
                exit 64
          in
          let target_action =
            match String.lowercase_ascii action_str with
            | "pass" -> Lpf.Ir.Pass
            | "block" -> Lpf.Ir.Block
            | "reject" -> Lpf.Ir.Reject
            | _ ->
                Printf.eprintf "unknown action: %s (use pass/block/reject)\n"
                  action_str;
                exit 64
          in
          let ir = parse_ir (read_policy file) in
          let cls = parse_constraints () in
          Printf.printf "checking reachability: action=%s constraints=%s\n%!"
            action_str
            (String.concat " " (List.map (fun (k, v) -> k ^ "=" ^ v) cls));
          match
            Lpf_z3.Z3_verify.check_reachable ir ~constraints:cls ~target_action
          with
          | Lpf_z3.Z3_verify.Reachable ce ->
              Printf.printf
                "REACHABLE: packet exists that matches constraints and \
                 produces %s\n"
                action_str;
              Printf.printf "  src=%s dst=%s port=%d\n" ce.source ce.destination
                (match ce.port with Some p -> p | None -> 0);
              exit 0
          | Lpf_z3.Z3_verify.Unreachable ->
              Printf.printf
                "PASS: no packet matches constraints and produces %s \
                 (unreachable)\n"
                action_str;
              exit 0
          | "invariant" -> (
              let file =
                match !policy_file with
                | Some f -> f
                | None ->
                    Printf.eprintf "no policy file\n";
                    exit 64
              in
              let ir = parse_ir (read_policy file) in
              let invs = parse_invariants () in
              if invs = [] then (
                Printf.eprintf
                  "no invariants specified (use -i src=10.0.0.0/8 -i \
                   dst=0.0.0.0/0)\n";
                exit 64);
              Printf.printf "checking invariant for %s...\n%!" file;
              match Lpf_z3.Z3_verify.check_invariant ir invs with
              | Lpf_z3.Z3_verify.Holds ->
                  Printf.printf "PASS: invariant holds for all packets\n";
                  exit 0
              | Lpf_z3.Z3_verify.Violated ce ->
                  Printf.printf "FAIL: invariant violated\n";
                  Printf.printf "  counterexample: src=%s dst=%s port=%d\n"
                    ce.source ce.destination
                    (match ce.port with Some p -> p | None -> 0);
                  exit 1
              | "minimize" ->
                  let file =
                    match !policy_file with
                    | Some f -> f
                    | None ->
                        Printf.eprintf "no policy file\n";
                        exit 64
                  in
                  let ir = parse_ir (read_policy file) in
                  Printf.printf "minimizing rules for %s...\n%!" file;
                  let minimal, removed = Lpf_z3.Z3_verify.minimize ir in
                  Printf.printf "removed %d redundant rules, %d remaining\n"
                    removed
                    (List.length minimal.rules);
                  exit 0
              | "coverage" ->
                  let file =
                    match !policy_file with
                    | Some f -> f
                    | None ->
                        Printf.eprintf "no policy file\n";
                        exit 64
                  in
                  let ir = parse_ir (read_policy file) in
                  Printf.printf "rule coverage for %s:\n%!" file;
                  let coverage = Lpf_z3.Z3_verify.check_rule_coverage ir in
                  List.iter
                    (fun (rc : Lpf_z3.Z3_verify.rule_coverage) ->
                      Printf.printf "  rule at line %d (%s): %s\n" rc.line
                        rc.action
                        (if rc.reachable then "reachable"
                         else "DEAD (never matched)"))
                    coverage
              | "gen-tests" ->
                  let file =
                    match !policy_file with
                    | Some f -> f
                    | None ->
                        Printf.eprintf "no policy file\n";
                        exit 64
                  in
                  let ir = parse_ir (read_policy file) in
                  Printf.printf "generating tests for %s...\n%!" file;
                  let tests = Lpf_z3.Z3_verify.generate_tests ir in
                  List.iter
                    (fun (t : Lpf_z3.Z3_verify.generated_test) ->
                      Printf.printf "test \"%s\" { expect = %s }\n" t.test_name
                        t.expected_action)
                    tests
              | "backend-ebpf" -> (
                  let file =
                    match !policy_file with
                    | Some f -> f
                    | None ->
                        Printf.eprintf "no policy file\n";
                        exit 64
                  in
                  let ir = parse_ir (read_policy file) in
                  Printf.printf
                    "checking eBPF backend equivalence for %s...\n%!" file;
                  let ebpf_filter = Lpf.Ebpf.classify ir in
                  match
                    Lpf_z3.Z3_verify.check_backend_equivalence ~ir
                      ~ebpf_rules:ebpf_filter
                  with
                  | Lpf_z3.Z3_verify.Equivalent ->
                      Printf.printf
                        "PASS: eBPF backend is semantically equivalent to IR\n";
                      exit 0
                  | Lpf_z3.Z3_verify.Not_equivalent ne ->
                      Printf.printf "FAIL: eBPF backend diverges from IR\n";
                      Printf.printf
                        "  counterexample: src=%s dst=%s decision1=%s \
                         decision2=%s\n"
                        ne.counterexample.source ne.counterexample.destination
                        ne.decision_in_first ne.decision_in_second;
                      exit 1
                  | "check-all" ->
                      let file =
                        match !policy_file with
                        | Some f -> f
                        | None ->
                            Printf.eprintf "no policy file\n";
                            exit 64
                      in
                      let ir = parse_ir (read_policy file) in
                      let failed = ref false in
                      Printf.printf "=== lpf-verify check-all: %s ===\n" file;

                      Printf.printf "\n[1/4] consistency check...\n%!";
                      let dead = Lpf_z3.Z3_verify.check_consistency ir in
                      if dead = [] then Printf.printf "  PASS\n"
                      else (
                        failed := true;
                        Printf.printf "  FAIL: %d dead rule(s)\n"
                          (List.length dead);
                        List.iter
                          (fun d ->
                            Printf.printf "    rule at line %d: %s\n"
                              d.Lpf_z3.Z3_verify.line d.Lpf_z3.Z3_verify.action)
                          dead);

                      Printf.printf "\n[2/4] rule coverage...\n%!";
                      let coverage = Lpf_z3.Z3_verify.check_rule_coverage ir in
                      let unreachable =
                        List.filter (fun rc -> not rc.reachable) coverage
                      in
                      if unreachable = [] then
                        Printf.printf "  PASS: all rules reachable\n"
                      else (
                        failed := true;
                        Printf.printf "  FAIL: %d unreachable rule(s)\n"
                          (List.length unreachable));

                      Printf.printf "\n[3/4] minimize...\n%!";
                      let minimal, removed = Lpf_z3.Z3_verify.minimize ir in
                      if removed = 0 then
                        Printf.printf "  PASS: no redundant rules\n"
                      else
                        Printf.printf
                          "  PASS: %d redundant rules can be removed\n" removed;

                      Printf.printf "\n[4/4] backend equivalence (eBPF)...\n%!";
                      let ebpf_filter = Lpf.Ebpf.classify ir in
                      (match
                         Lpf_z3.Z3_verify.check_backend_equivalence ~ir
                           ~ebpf_rules:ebpf_filter
                       with
                      | Lpf_z3.Z3_verify.Equivalent ->
                          Printf.printf "  PASS: eBPF backend matches IR\n"
                      | Lpf_z3.Z3_verify.Not_equivalent ne ->
                          failed := true;
                          Printf.printf "  FAIL: divergence at src=%s dst=%s\n"
                            ne.counterexample.Lpf_z3.Z3_verify.source
                            ne.counterexample.Lpf_z3.Z3_verify.destination);

                      if !failed then (
                        Printf.printf "\n=== VERIFICATION FAILED ===\n";
                        exit 1)
                      else (
                        Printf.printf "\n=== VERIFICATION PASSED ===\n";
                        exit 0)
                  | _ ->
                      Printf.eprintf "lpf-verify: unknown command: %s\n" cmd;
                      Printf.eprintf "%s" usage_msg;
                      exit 64))))
