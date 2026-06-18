type invocation = Process.invocation = {
  program : string;
  argv : string list;
}

type run_status = Process.run_status =
  | Exited of int
  | Signaled of int
  | Stopped of int
  | Failed_to_start of string

type run_error = Process.run_error = {
  invocation : invocation;
  status : run_status;
  stderr : string;
}

type conntrack_entry = {
  protocol : string;
  src : string;
  dst : string;
  sport : string;
  dport : string;
  state : string;
  raw : string;
}

let list_invocation () = { program = "conntrack"; argv = [ "conntrack"; "-L"; "-o"; "extended" ] }
let delete_invocation ~src ~dst ?sport ?dport () =
  let args = [ "conntrack"; "-D"; "-s"; src; "-d"; dst ] in
  let args = match sport with Some sp -> args @ [ "-p"; "tcp"; "--orig-port-src"; sp ] | None -> args in
  let args = match dport with Some dp -> args @ [ "-p"; "tcp"; "--orig-port-dst"; dp ] | None -> args in
  { program = "conntrack"; argv = args }
let flush_invocation () = { program = "conntrack"; argv = [ "conntrack"; "-F" ] }

let run invocation = Process.run ~temp_prefix:"lpf-conntrack" invocation

let list_with_runner runner = runner (list_invocation ())
let list () = list_with_runner run

let delete_with_runner runner ~src ~dst ?sport ?dport () = runner (delete_invocation ~src ~dst ?sport ?dport ()) |> Result.map ignore
let delete ~src ~dst ?sport ?dport () = delete_with_runner run ~src ~dst ?sport ?dport ()

let flush_with_runner runner = runner (flush_invocation ()) |> Result.map ignore
let flush () = flush_with_runner run

let string_of_run_error error = Process.string_of_run_error "conntrack" error

let parse_line line =
  let fields = String.split_on_char ' ' line |> List.filter (fun s -> String.length s > 0) in
  let rec find_field key = function
    | field :: value :: _ when String.equal field key -> Some value
    | _ :: rest -> find_field key rest
    | [] -> None
  in
  let rec find_field_starts prefix = function
    | field :: _ when String.starts_with ~prefix field || String.equal field prefix ->
        (match String.split_on_char '=' field with
         | [ _; value ] -> Some value
         | _ -> Some field)
    | _ :: rest -> find_field_starts prefix rest
    | [] -> None
  in
  match fields with
  | proto :: src :: dst :: rest ->
      let sport = Option.value (find_field "sport=" rest) ~default:(Option.value (find_field "sport" rest) ~default:"") in
      let dport = Option.value (find_field "dport=" rest) ~default:(Option.value (find_field "dport" rest) ~default:"") in
      let state = Option.value (find_field_starts "TIME_WAIT" rest) ~default:
                    (Option.value (find_field_starts "ESTABLISHED" rest) ~default:
                      (Option.value (find_field_starts "CLOSE" rest) ~default:
                        (Option.value (find_field_starts "SYN_SENT" rest) ~default:
                          (Option.value (find_field_starts "NONE" rest) ~default:
                            (Option.value (find_field_starts "ASSURED" rest) ~default:
                              (Option.value (find_field_starts "UNREPLIED" rest) ~default:
                                (match find_field "[UNREPLIED]" rest with Some _ -> "UNREPLIED" | None -> ""))))))) in
      Some { protocol = proto; src; dst; sport; dport; state; raw = line }
  | [ _ ] | [] -> None
  | _ ->
      match fields with
      | proto :: rest when String.ends_with ~suffix:"src=" proto ->
          let src = match String.split_on_char '=' proto with [ _; v ] -> v | _ -> proto in
          let dst = Option.value (find_field "dst=" rest) ~default:"" in
          let sport = Option.value (find_field "sport=" rest) ~default:"" in
          let dport = Option.value (find_field "dport=" rest) ~default:"" in
          let state = Option.value (find_field_starts "TIME_WAIT" rest) ~default:
                        (Option.value (find_field_starts "ESTABLISHED" rest) ~default:"") in
          Some { protocol = (match find_field "protonum=" rest with Some p -> p | None -> "unknown");
                 src; dst; sport; dport; state; raw = line }
      | _ -> None

let parse_list output =
  String.split_on_char '\n' output
  |> List.filter_map parse_line

let entry_to_json (e : conntrack_entry) =
  Json_util.field_object
    [
      ("protocol", Json_util.string e.protocol);
      ("src", Json_util.string e.src);
      ("dst", Json_util.string e.dst);
      ("sport", Json_util.string e.sport);
      ("dport", Json_util.string e.dport);
      ("state", Json_util.string e.state);
    ]

let entries_to_json entries =
  Json_util.list entry_to_json entries ^ "\n"
