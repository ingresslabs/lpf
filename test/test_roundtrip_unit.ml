let read_file path =
  let channel = open_in path in
  Fun.protect
    ~finally:(fun () -> close_in channel)
    (fun () ->
      let length = in_channel_length channel in
      really_input_string channel length)

let fixtures_dir = "../fixtures/policies"

let fixture_files () =
  Sys.readdir fixtures_dir |> Array.to_list
  |> List.filter (fun path -> Filename.check_suffix path ".lpf")
  |> List.sort String.compare
  |> List.map (Filename.concat fixtures_dir)

let () =
  let fixtures = fixture_files () in
  assert (List.length fixtures > 0);
  List.iter
    (fun path ->
      let text = read_file path in
      let first_parse = Lpf.Policy.check ~file:path text in
      match first_parse.policy with
      | None -> ()
      | Some policy -> (
          let formatted = Lpf.Policy.format policy in
          let second_parse = Lpf.check_policy_text ~file:path formatted in
          match second_parse.Lpf.Policy.policy with
          | None ->
              let msg =
                Printf.sprintf "roundtrip failed for %s:\n%s" path
                  (Lpf.Policy.format_check_result second_parse)
              in
              failwith msg
          | Some policy2 ->
              let formatted2 = Lpf.Policy.format policy2 in
              assert (String.equal formatted formatted2)))
    fixtures;
  Printf.printf "roundtrip tests passed on %d fixture files\n"
    (List.length fixtures)
