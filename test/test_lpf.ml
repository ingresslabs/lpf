let () =
  assert (String.equal Lpf.version "0.1.0-dev");
  assert (Lpf.command_of_string "check" = Some Lpf.Check);
  assert (Lpf.command_of_string "support-bundle" = Some Lpf.Support_bundle);
  assert (Lpf.command_of_string "does-not-exist" = None);
  assert (String.contains (Lpf.help ()) 'c')

