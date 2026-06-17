let ir_of_policy = Ir.of_policy

let plan_of_policy policy =
  match Ir.of_policy policy with
  | Ok ir -> Ok (Plan.of_ir ir)
  | Error diagnostics -> Error diagnostics

let check_policy_text ?file text =
  let result = Policy.check ?file text in
  match result.policy with
  | None -> result
  | Some policy -> (
      match Ir.of_policy policy with
      | Error ir_diags ->
          { Policy.diagnostics = result.diagnostics @ ir_diags; policy = None }
      | Ok ir ->
          let shadow_diags = Ir.shadow_diagnostics ir in
          { Policy.diagnostics = result.diagnostics @ shadow_diags; policy = Some policy })

let format_policy_text ?file text =
  match Policy.check ?file text with
  | { policy = Some policy; diagnostics = _ } -> Ok (Policy.format policy)
  | { policy = None; diagnostics } -> Error diagnostics

let plan_policy_text ?file text =
  let result = check_policy_text ?file text in
  match result.policy with
  | None -> Error result.diagnostics
  | Some policy -> (
      match plan_of_policy policy with
      | Ok plan -> Ok (plan, result.diagnostics)
      | Error diagnostics -> Error (result.diagnostics @ diagnostics))

let render_nftables_policy_text ?file text =
  match plan_policy_text ?file text with
  | Ok (plan, diagnostics) -> Ok (Nftables.render_plan plan, diagnostics)
  | Error diagnostics -> Error diagnostics

let render_tc_policy_text ?file text =
  match plan_policy_text ?file text with
  | Ok (plan, diagnostics) -> Ok (Tc.to_string (Tc.compile plan.policy), diagnostics)
  | Error diagnostics -> Error diagnostics

let render_routing_policy_text ?file text =
  match plan_policy_text ?file text with
  | Ok (plan, diagnostics) -> Ok (Routing.to_string (Routing.compile plan.policy), diagnostics)
  | Error diagnostics -> Error diagnostics

let diff_nftables_policy_text ?file ~observed text =
  match render_nftables_policy_text ?file text with
  | Ok (intended, diagnostics) -> Ok (Nftables.diff_text ~intended ~observed, diagnostics)
  | Error diagnostics -> Error diagnostics

let diff_nftables_policy ?file ~observed text =
  match render_nftables_policy_text ?file text with
  | Ok (intended, diagnostics) -> Ok (Nftables.diff ~intended ~observed, diagnostics)
  | Error diagnostics -> Error diagnostics

let diff_tc_policy ?file ~observed_qdisc ~observed_class text =
  match plan_policy_text ?file text with
  | Ok (plan, diagnostics) ->
      let intended = Tc.compile plan.policy in
      Ok (Tc.diff ~intended ~observed_qdisc ~observed_class, diagnostics)
  | Error diagnostics -> Error diagnostics

let diff_routing_policy ?file ~observed_rules ~observed_routes text =
  match plan_policy_text ?file text with
  | Ok (plan, diagnostics) ->
      let intended = Routing.compile plan.policy in
      Ok (Routing.diff ~intended ~observed_rules ~observed_routes, diagnostics)
  | Error diagnostics -> Error diagnostics

let explain_policy_text ?file ~packet text =
  let result = check_policy_text ?file text in
  match result.policy with
  | None -> Error result.diagnostics
  | Some policy -> (
      match Ir.of_policy policy with
      | Error diagnostics -> Error (result.diagnostics @ diagnostics)
      | Ok ir -> Ok (Explain.explain ir packet, result.diagnostics))

let run_policy_tests ?file text =
  match Test_parser.parse ?file text with
  | Error diagnostics -> Error diagnostics
  | Ok suite ->
      let policy_path =
        if Filename.is_relative suite.policy_file then
          match file with
          | Some path -> Filename.concat (Filename.dirname path) suite.policy_file
          | None -> suite.policy_file
        else suite.policy_file
      in
      let policy_text =
        let ic = open_in policy_path in
        Fun.protect ~finally:(fun () -> close_in ic) (fun () -> really_input_string ic (in_channel_length ic))
      in
      let result = check_policy_text ~file:policy_path policy_text in
      match result.policy with
      | None -> Error result.diagnostics
      | Some policy -> (
          match Ir.of_policy policy with
          | Error diagnostics -> Error (result.diagnostics @ diagnostics)
          | Ok ir -> Ok (Test_engine.run_suite ir suite, result.diagnostics))
