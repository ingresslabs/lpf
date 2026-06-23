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

let () =
  let packet =
    {
      Lpf.Explain.direction = Lpf.Policy.In;
      interface = "eth0";
      protocol = Lpf.Policy.Proto_named "tcp";
      source = "192.0.2.10";
      destination = "198.51.100.20";
      port = Some 443;
    }
  in
  let explanation =
    {
      Lpf.Explain.packet;
      decision = Lpf.Policy.Block;
      matching_rule = None;
      shadowed_by = None;
      nat = None;
      rdr = None;
      route_to = None;
      queue = None;
      log = None;
    }
  in
  let case =
    {
      Lpf.Test_engine.name = "quoted \"suite\" & <xml>";
      expectations = [ { packet; expect_decision = Lpf.Policy.Pass } ];
    }
  in
  let xml =
    Lpf.Test_engine.to_junit
      [
        ( case,
          [
            Lpf.Test_engine.Fail
              {
                expected = Lpf.Policy.Pass;
                actual = Lpf.Policy.Block;
                explanation;
              };
          ] );
      ]
  in
  assert (
    contains_substring xml "name=\"quoted &quot;suite&quot; &amp; &lt;xml&gt;\"");
  assert (not (contains_substring xml "name=\"\""));
  assert (contains_substring xml "Expected pass but got block");
  assert (contains_substring xml "Decision: block");
  Printf.printf "test engine junit tests passed\n"
