let () =
  if Array.length Sys.argv >= 2 && Sys.argv.(1) = "daemon" then
    Lpf.Lpf_daemon.run (Lpf.Lpf_daemon.default_config ())
  else
    let cmd = Sys.getenv_opt "CNI_COMMAND" in
    let netns = Sys.getenv_opt "CNI_NETNS" in
    let container_id = Sys.getenv_opt "CNI_CONTAINERID" in
    let ifname = Sys.getenv_opt "CNI_IFNAME" in

    let read_stdin () =
      let buf = Buffer.create 4096 in
      (try
         while true do
           Buffer.add_string buf (input_line stdin);
           Buffer.add_char buf '\n'
         done
       with End_of_file -> ());
      Buffer.contents buf
    in

    match cmd with
    | Some "VERSION" | None -> Lpf.Cni.handle_version ()
    | Some cmd_str -> (
        let config_text = read_stdin () in
        if config_text = "" then (
          Printf.eprintf
            "{\"cniVersion\":\"1.0.0\",\"code\":4,\"msg\":\"empty network \
             config\",\"details\":\"\"}\n\
             %!";
          exit 3);
        match Lpf.Cni.parse_command cmd_str with
        | Error e ->
            Printf.eprintf "%s\n%!" (Lpf.Cni.error_result 3 e);
            exit 3
        | Ok command -> (
            match Lpf.Cni.parse_network_config config_text with
            | Error e ->
                Printf.eprintf "%s\n%!" (Lpf.Cni.error_result 4 e);
                exit 4
            | Ok cfg -> (
                let netns_path = match netns with Some n -> n | None -> "" in
                let cid =
                  match container_id with Some c -> c | None -> "unknown"
                in
                let ifn = match ifname with Some i -> i | None -> "eth0" in
                match command with
                | Lpf.Cni.Version -> Lpf.Cni.handle_version ()
                | Lpf.Cni.Add -> (
                    match Lpf.Cni.handle_add cfg netns_path cid ifn with
                    | Error e ->
                        Printf.eprintf "%s\n%!" (Lpf.Cni.error_result 7 e);
                        exit 7
                    | Ok result ->
                        Printf.printf "%s\n%!" (Lpf.Cni.result_to_json result))
                | Lpf.Cni.Del -> (
                    match Lpf.Cni.handle_del cfg netns_path cid ifn with
                    | Error e ->
                        Printf.eprintf "%s\n%!" (Lpf.Cni.error_result 7 e);
                        exit 7
                    | Ok () -> ())
                | Lpf.Cni.Check -> (
                    match Lpf.Cni.handle_check cfg netns_path cid ifn with
                    | Error e ->
                        Printf.eprintf "%s\n%!" (Lpf.Cni.error_result 11 e);
                        exit 11
                    | Ok () -> ()))))
