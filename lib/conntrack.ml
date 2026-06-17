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
let delete_invocation ~src ~dst = { program = "conntrack"; argv = [ "conntrack"; "-D"; "-s"; src; "-d"; dst ] }
let flush_invocation () = { program = "conntrack"; argv = [ "conntrack"; "-F" ] }

let run invocation = Process.run ~temp_prefix:"lpf-conntrack" invocation

let list_with_runner runner = runner (list_invocation ())
let list () = list_with_runner run

let delete_with_runner runner ~src ~dst = runner (delete_invocation ~src ~dst) |> Result.map ignore
let delete ~src ~dst = delete_with_runner run ~src ~dst

let flush_with_runner runner = runner (flush_invocation ()) |> Result.map ignore
let flush () = flush_with_runner run

let string_of_run_error error = Process.string_of_run_error "conntrack" error

let parse_line line =
  let fields = String.split_on_char ' ' line |> List.filter (fun s -> String.length s > 0) in
  match fields with
  | proto :: src :: dst :: rest ->
      let sport = try List.nth rest 0 with _ -> "" in
      let dport = try List.nth rest 2 with _ -> "" in
      let state = try List.nth rest 3 with _ -> "" in
      Some { protocol = proto; src; dst; sport; dport; state; raw = line }
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
