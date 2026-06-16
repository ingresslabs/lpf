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
         (String.concat "\n" (List.map Lpf.Policy.diagnostic_to_string diagnostics)))
