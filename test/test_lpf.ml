let read_file path =
  let channel = open_in path in
  Fun.protect
    ~finally:(fun () -> close_in channel)
    (fun () ->
      let length = in_channel_length channel in
      really_input_string channel length)

let fixture path = Filename.concat "../fixtures/policies" path

let assert_check_ok path =
  let path = fixture path in
  match Lpf.check_policy_text ~file:path (read_file path) with
  | { Lpf.Policy.policy = Some _; diagnostics = _ } -> ()
  | result -> failwith (Lpf.Policy.format_check_result result)

let assert_check_fails ~contains path =
  let path = fixture path in
  match Lpf.check_policy_text ~file:path (read_file path) with
  | { Lpf.Policy.policy = None; diagnostics } ->
      let text = String.concat "\n" (List.map Lpf.Policy.diagnostic_to_string diagnostics) in
      assert (String.contains text contains)
  | { policy = Some _; diagnostics = _ } -> failwith (path ^ " unexpectedly passed")

let assert_check_has_diagnostic ~line ~column ~message path =
  let path = fixture path in
  match Lpf.check_policy_text ~file:path (read_file path) with
  | { Lpf.Policy.policy = None; diagnostics } ->
      assert (
        List.exists
          (fun (diagnostic : Lpf.Policy.diagnostic) ->
            diagnostic.span.line = line && diagnostic.span.column = column
            && String.equal diagnostic.message message)
          diagnostics)
  | { policy = Some _; diagnostics = _ } -> failwith (path ^ " unexpectedly passed")

let assert_inline_check_has_diagnostic ~file ~text ~line ~column ~message =
  match Lpf.check_policy_text ~file text with
  | { Lpf.Policy.policy = None; diagnostics } ->
      assert (
        List.exists
          (fun (diagnostic : Lpf.Policy.diagnostic) ->
            diagnostic.span.line = line && diagnostic.span.column = column
            && String.equal diagnostic.message message)
          diagnostics)
  | { policy = Some _; diagnostics = _ } -> failwith (file ^ " unexpectedly passed")

let assert_formats_to ~expected path =
  let path = fixture path in
  match Lpf.format_policy_text ~file:path (read_file path) with
  | Ok formatted ->
      assert (String.equal formatted expected);
      (match Lpf.format_policy_text ~file:path formatted with
       | Ok round_tripped -> assert (String.equal round_tripped expected)
       | Error diagnostics ->
           failwith
             (String.concat "\n" (List.map Lpf.Policy.diagnostic_to_string diagnostics)))
  | Error diagnostics ->
      failwith (String.concat "\n" (List.map Lpf.Policy.diagnostic_to_string diagnostics))

let () =
  assert (String.equal Lpf.version "0.1.0-dev");
  assert (Lpf.command_of_string "check" = Some Lpf.Check);
  assert (Lpf.command_of_string "ui" = Some Lpf.Ui);
  assert (Lpf.command_of_string "man" = Some Lpf.Man);
  assert (Lpf.command_of_string "support-bundle" = Some Lpf.Support_bundle);
  assert (Lpf.command_of_string "does-not-exist" = None);
  assert (String.contains (Lpf.help ()) 'c');
  assert (List.length (Lpf.man_pages ()) >= 20);
  assert (
    List.exists
      (fun page -> String.equal page.Lpf.filename "lpf-ui.8")
      (Lpf.man_pages ()));
  Lpf.man_pages ()
  |> List.iter (fun page ->
         let path = Filename.concat "../man/generated" page.Lpf.filename in
         assert (Sys.file_exists path);
         assert (String.equal (read_file path) (Lpf.man_page_content page)));
  assert_check_ok "basic.lpf";
  assert_check_ok "nat-rdr.lpf";
  assert_check_fails ~contains:'m' "invalid-unknown-table.lpf";
  assert_check_fails ~contains:'e' "invalid-syntax.lpf";
  assert_check_has_diagnostic ~line:5 ~column:14
    ~message:"rule source references unknown table `<missing>`"
    "invalid-unknown-table.lpf";
  assert_inline_check_has_diagnostic ~file:"inline-invalid-port.lpf"
    ~text:"set default deny\npass out proto tcp from any to any port 70000\n"
    ~line:2 ~column:41 ~message:"invalid rule: invalid port `70000`";
  let basic = read_file (fixture "basic.lpf") in
  (match Lpf.format_policy_text ~file:(fixture "basic.lpf") basic with
   | Ok formatted -> assert (String.equal formatted basic)
   | Error diagnostics ->
       failwith
         (String.concat "\n" (List.map Lpf.Policy.diagnostic_to_string diagnostics)));
  let nat_rdr = read_file (fixture "nat-rdr.lpf") in
  (match Lpf.format_policy_text ~file:(fixture "nat-rdr.lpf") nat_rdr with
   | Ok formatted -> assert (String.equal formatted nat_rdr)
   | Error diagnostics ->
       failwith
         (String.concat "\n" (List.map Lpf.Policy.diagnostic_to_string diagnostics)));
  assert_formats_to
    ~expected:
      "set default deny\n\n\
       table <trusted> { 10.0.0.0/8, 192.168.0.0/16 }\n\n\
       pass out proto tcp from any to any port 443 keep state\n"
    "messy.lpf"
