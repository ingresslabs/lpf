let () =
  let result =
    Lpf.render_tc_policy_text
      "set default deny\n\
       interface wan = \"eth0\"\n\
       queue std on wan bandwidth 10M\n\
       pass out on wan from any to any queue std"
  in
  (match result with
  | Ok (rendered, diagnostics) ->
      assert (diagnostics = []);
      assert (String.length rendered > 0);
      assert (String.contains rendered 't')
  | _ -> assert false);

  let result =
    Lpf.render_routing_policy_text
      "set default deny\n\
       interface wan = \"eth0\"\n\
       pass out on wan proto tcp from any to any port 443 route-to 1.1.1.1 \
       (wan) keep state"
  in
  (match result with
  | Ok (rendered, diagnostics) ->
      assert (diagnostics = []);
      assert (String.length rendered > 0);
      assert (String.contains rendered 'i')
  | _ -> assert false);

  let policy_text =
    "set default deny\n\
     interface wan = \"eth0\"\n\
     queue std on wan bandwidth 10M\n\
     table <trusted> { 10.0.0.0/8 }\n\
     pass in on wan from <trusted> to any queue std\n\
     pass out proto tcp from any to any port 443 keep state"
  in
  let result = Lpf.check_policy_text policy_text in
  (match result.Lpf.Policy.policy with
  | Some _ -> ()
  | None -> failwith "render_nftables failed to parse policy");

  Printf.printf "pipeline tests passed\n"
