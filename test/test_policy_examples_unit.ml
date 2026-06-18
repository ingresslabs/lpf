let read_file path =
  let channel = open_in path in
  Fun.protect
    ~finally:(fun () -> close_in channel)
    (fun () ->
      let length = in_channel_length channel in
      really_input_string channel length)

let examples_dir = "../configs/policies"

let policy_examples () =
  Sys.readdir examples_dir |> Array.to_list
  |> List.filter (fun path -> Filename.check_suffix path ".lpf")
  |> List.sort String.compare
  |> List.map (Filename.concat examples_dir)

let () =
  let examples = policy_examples () in
  if examples = [] then failwith "expected at least one policy example";
  List.iter
    (fun path ->
      match Lpf.check_policy_text ~file:path (read_file path) with
      | { Lpf.Policy.policy = Some _; diagnostics = _ } -> ()
      | result -> failwith (Lpf.Policy.format_check_result result))
    examples;
  Printf.printf "checked %d policy examples\n" (List.length examples)
