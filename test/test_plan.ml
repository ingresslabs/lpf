let read_file path =
  let channel = open_in path in
  Fun.protect
    ~finally:(fun () -> close_in channel)
    (fun () ->
      let length = in_channel_length channel in
      really_input_string channel length)

let fixture path = Filename.concat "../fixtures/policies" path

let contains_substring text needle =
  let text_length = String.length text in
  let needle_length = String.length needle in
  if needle_length = 0 then true
  else
    let rec loop index =
      index + needle_length <= text_length
      && (String.equal (String.sub text index needle_length) needle
         || loop (index + 1))
    in
    loop 0

let assert_contains text needle =
  if not (contains_substring text needle) then
    failwith ("expected substring not found: " ^ needle ^ "\n" ^ text)

let checksum_of_text ~file text =
  match Lpf.plan_policy_text ~file text with
  | Ok (plan, diagnostics) ->
      let errors =
        diagnostics
        |> List.filter (fun (diagnostic : Lpf.Policy.diagnostic) ->
               diagnostic.severity = Diag_error)
      in
      if errors <> [] then
        failwith
          (String.concat "\n" (List.map Lpf.Policy.diagnostic_to_string errors));
      Lpf.Plan.checksum plan
  | Error diagnostics ->
      failwith
        (String.concat "\n"
           (List.map Lpf.Policy.diagnostic_to_string diagnostics))

let plan_of_fixture path =
  let path = fixture path in
  match Lpf.plan_policy_text ~file:path (read_file path) with
  | Ok (plan, diagnostics) ->
      let errors =
        diagnostics
        |> List.filter (fun (diagnostic : Lpf.Policy.diagnostic) ->
               diagnostic.severity = Diag_error)
      in
      if errors <> [] then
        failwith
          (String.concat "\n" (List.map Lpf.Policy.diagnostic_to_string errors));
      (plan, diagnostics)
  | Error diagnostics ->
      failwith
        (String.concat "\n"
           (List.map Lpf.Policy.diagnostic_to_string diagnostics))

let () =
  assert (String.equal Lpf.version "0.2.3");
  assert (Lpf.command_of_string "check" = Some Lpf.Check);
  assert (Lpf.command_of_string "man" = Some Lpf.Man);
  assert (Lpf.command_of_string "does-not-exist" = None);
  assert (String.contains (Lpf.help ()) 'c');
  assert (List.length (Lpf.man_pages ()) = 21);
  Lpf.man_pages ()
  |> List.iter (fun page ->
         let path = Filename.concat "../man/generated" page.Lpf.filename in
         assert (Sys.file_exists path);
         assert (String.equal (read_file path) (Lpf.man_page_content page)));
  let plan, diagnostics = plan_of_fixture "queue-route.lpf" in
  assert (diagnostics = []);
  let json = Lpf.Plan.to_json plan in
  assert_contains json "\"schema\":\"lpf.plan.v1\"";
  assert_contains json "\"kind\":\"semantic-policy\"";
  assert_contains json "\"checksum\":\"md5:";
  assert_contains json "\"interfaces\":[";
  assert_contains json "\"queues\":[";
  assert_contains json "\"route_to\":";
  let plan_again, _ = plan_of_fixture "queue-route.lpf" in
  assert (String.equal (Lpf.Plan.checksum plan) (Lpf.Plan.checksum plan_again));
  assert (String.equal json (Lpf.Plan.to_json plan_again));
  let warning_plan, warning_diagnostics =
    plan_of_fixture "warning-shadowed-rule.lpf"
  in
  assert (String.length (Lpf.Plan.checksum warning_plan) > 4);
  assert (
    List.exists
      (fun (diagnostic : Lpf.Policy.diagnostic) ->
        diagnostic.severity = Diag_warning
        && String.equal diagnostic.message
             "rule is completely shadowed by rule at line 3")
      warning_diagnostics);
  let messy_path = fixture "messy-full.lpf" in
  let messy = read_file messy_path in
  let formatted =
    match Lpf.format_policy_text ~file:messy_path messy with
    | Ok formatted -> formatted
    | Error diagnostics ->
        failwith
          (String.concat "\n"
             (List.map Lpf.Policy.diagnostic_to_string diagnostics))
  in
  assert (
    String.equal
      (checksum_of_text ~file:messy_path messy)
      (checksum_of_text ~file:"messy-full-formatted.lpf" formatted))
