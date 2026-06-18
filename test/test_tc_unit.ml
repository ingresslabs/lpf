let () =
  let empty_ir =
    {
      Lpf.Ir.default_action = Lpf.Policy.Default_deny;
      interfaces = [];
      tables = [];
      queues = [];
      nats = [];
      rdrs = [];
      anchors = [];
      rules = [];
    }
  in
  let result = Lpf.Tc.compile empty_ir in
  assert (result = []);

  let ir_with_queue =
    {
      empty_ir with
      queues =
        [
          {
            Lpf.Ir.name = "std";
            interface =
              {
                Lpf.Ir.name = Some "wan";
                device = "eth0";
                span =
                  {
                    Lpf.Policy.file = None;
                    line = 1;
                    column = 1;
                    end_column = 1;
                  };
              };
            bandwidth = "10M";
            parent = None;
            span =
              { Lpf.Policy.file = None; line = 1; column = 1; end_column = 1 };
          };
        ];
    }
  in
  let result = Lpf.Tc.compile ir_with_queue in
  assert (List.length result = 2);
  let rendered = Lpf.Tc.to_string result in
  assert (String.length rendered > 0);
  assert (String.contains rendered ' ');

  let ir_with_child =
    {
      empty_ir with
      queues =
        [
          {
            Lpf.Ir.name = "std";
            interface =
              {
                Lpf.Ir.name = Some "wan";
                device = "eth0";
                span =
                  {
                    Lpf.Policy.file = None;
                    line = 1;
                    column = 1;
                    end_column = 1;
                  };
              };
            bandwidth = "10M";
            parent = None;
            span =
              { Lpf.Policy.file = None; line = 1; column = 1; end_column = 1 };
          };
          {
            Lpf.Ir.name = "voip";
            interface =
              {
                Lpf.Ir.name = Some "wan";
                device = "eth0";
                span =
                  {
                    Lpf.Policy.file = None;
                    line = 2;
                    column = 1;
                    end_column = 1;
                  };
              };
            bandwidth = "1M";
            parent = Some "std";
            span =
              { Lpf.Policy.file = None; line = 2; column = 1; end_column = 1 };
          };
        ];
    }
  in
  let result = Lpf.Tc.compile ir_with_child in
  assert (List.length result = 3);
  let classid = Lpf.Tc.queue_classid ir_with_child.queues "std" in
  assert (classid = Some "1:10");
  let classid = Lpf.Tc.queue_classid ir_with_child.queues "voip" in
  assert (classid = Some "1:20");
  let classid = Lpf.Tc.queue_classid ir_with_child.queues "missing" in
  assert (classid = None);

  Printf.printf "tc tests passed\n"
