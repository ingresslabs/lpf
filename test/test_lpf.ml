let read_file path =
  let channel = open_in path in
  Fun.protect
    ~finally:(fun () -> close_in channel)
    (fun () ->
      let length = in_channel_length channel in
      really_input_string channel length)

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
         assert (String.equal (read_file path) (Lpf.man_page_content page)))
