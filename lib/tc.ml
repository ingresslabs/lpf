type command =
  | Qdisc_add of {
      device : string;
      handle : string;
      parent : string;
      kind : string;
      default : int option;
    }
  | Class_add of {
      device : string;
      classid : string;
      parent : string;
      kind : string;
      rate : string;
    }

type t = command list

let queue_index queues name =
  let rec find idx = function
    | [] -> None
    | (q : Ir.queue) :: _ when String.equal q.name name -> Some idx
    | _ :: rest -> find (idx + 1) rest
  in
  find 1 queues

let queue_classid queues name =
  match queue_index queues name with
  | Some idx -> Some (Printf.sprintf "1:%d" (idx * 10))
  | None -> None

let compile (ir : Ir.t) : t =
  let queues_by_device =
    List.fold_left
      (fun acc (q : Ir.queue) ->
        let device = q.interface.device in
        let existing =
          match List.assoc_opt device acc with Some l -> l | None -> []
        in
        (device, existing @ [ q ]) :: List.remove_assoc device acc)
      [] ir.queues
  in
  List.concat_map
    (fun (device, device_queues) ->
      let qdisc =
        Qdisc_add
          {
            device;
            handle = "1:";
            parent = "root";
            kind = "htb";
            default = None;
          }
      in
      let classes =
        List.filter_map
          (fun (q : Ir.queue) ->
            match queue_classid ir.queues q.name with
            | None -> None
            | Some classid -> (
                let parent =
                  match q.parent with
                  | None -> Some "1:"
                  | Some parent_name -> (
                      match queue_classid ir.queues parent_name with
                      | None -> None
                      | Some p -> Some p)
                in
                match parent with
                | None -> None
                | Some parent ->
                    Some
                      (Class_add
                         {
                           device;
                           classid;
                           parent;
                           kind = "htb";
                           rate = q.bandwidth;
                         })))
          device_queues
      in
      qdisc :: classes)
    queues_by_device

let string_of_command = function
  | Qdisc_add { device; handle; parent; kind; default } ->
      let default_str =
        match default with
        | Some d -> Printf.sprintf " default %d" d
        | None -> ""
      in
      Printf.sprintf "tc qdisc add dev %s %s handle %s %s%s" device parent
        handle kind default_str
  | Class_add { device; classid; parent; kind; rate } ->
      Printf.sprintf "tc class add dev %s parent %s classid %s %s rate %s"
        device parent classid kind rate

let batch_string_of_command = function
  | Qdisc_add { device; handle; parent; kind; default } ->
      let default_str =
        match default with
        | Some d -> Printf.sprintf " default %d" d
        | None -> ""
      in
      Printf.sprintf "qdisc replace dev %s %s handle %s %s%s" device parent
        handle kind default_str
  | Class_add { device; classid; parent; kind; rate } ->
      Printf.sprintf "class replace dev %s parent %s classid %s %s rate %s"
        device parent classid kind rate

let to_string t =
  String.concat "\n" (List.map string_of_command t)
  ^ if t = [] then "" else "\n"

let to_batch_string t =
  String.concat "\n" (List.map batch_string_of_command t)
  ^ if t = [] then "" else "\n"

let qdisc_show_invocation device =
  { Process.program = "tc"; argv = [ "tc"; "qdisc"; "show"; "dev"; device ] }

let class_show_invocation device =
  { Process.program = "tc"; argv = [ "tc"; "class"; "show"; "dev"; device ] }

let qdisc_show_with_runner runner device = runner (qdisc_show_invocation device)
let qdisc_show device = qdisc_show_with_runner Nft.run device
let class_show_with_runner runner device = runner (class_show_invocation device)
let class_show device = class_show_with_runner Nft.run device

type diff_result = { changes_required : bool; text : string }
type observed_qdisc = { device : string; handle : string; kind : string }

type observed_class = {
  device : string;
  classid : string;
  parent : string;
  kind : string;
  rate : string;
}

let parse_qdisc_line device line =
  let parts =
    String.split_on_char ' ' line |> List.filter (fun s -> String.length s > 0)
  in
  match parts with
  | "qdisc" :: kind :: handle :: _ -> Some { device; kind; handle }
  | _ -> None

let parse_class_line device line =
  let parts =
    String.split_on_char ' ' line |> List.filter (fun s -> String.length s > 0)
  in
  match parts with
  | "class" :: kind :: classid :: _ :: _ ->
      let rec extract_field key = function
        | [] -> ""
        | k :: v :: _rest when k = key -> v
        | _ :: rest -> extract_field key rest
      in
      let parent =
        match extract_field "parent" parts with
        | "" -> extract_field "root" parts
        | p -> p
      in
      let parent = if parent = "" then "root" else parent in
      let rate =
        match extract_field "rate" parts with
        | "" -> "unknown"
        | r -> ( try String.sub r 0 (String.index r 'M') ^ "M" with _ -> r)
      in
      Some { device; kind; classid; parent; rate }
  | _ -> None

let parse_qdisc_show device output =
  String.split_on_char '\n' output
  |> List.filter_map (fun line -> parse_qdisc_line device line)

let parse_class_show device output =
  String.split_on_char '\n' output
  |> List.filter_map (fun line -> parse_class_line device line)

let diff ~intended ~observed_qdisc ~observed_class =
  let obs_qdisc_map =
    List.fold_left
      (fun acc (q : observed_qdisc) -> (q.device, q) :: acc)
      [] observed_qdisc
  in
  let obs_class_map =
    List.fold_left
      (fun acc (c : observed_class) -> (c.device ^ ":" ^ c.classid, c) :: acc)
      [] observed_class
  in
  let buf = Buffer.create 256 in
  let changes = ref false in
  List.iter
    (function
      | Qdisc_add qd -> (
          let key = qd.device in
          match List.assoc_opt key obs_qdisc_map with
          | None ->
              changes := true;
              Buffer.add_string buf
                (Printf.sprintf "-qdisc dev %s: missing\n" key);
              Buffer.add_string buf
                (Printf.sprintf "+qdisc dev %s %s handle %s %s\n" qd.device
                   qd.parent qd.handle qd.kind)
          | Some obs ->
              if
                not
                  (String.equal qd.kind obs.kind
                  && String.equal qd.handle obs.handle)
              then (
                changes := true;
                Buffer.add_string buf
                  (Printf.sprintf "-qdisc dev %s: %s handle %s\n" qd.device
                     obs.kind obs.handle);
                Buffer.add_string buf
                  (Printf.sprintf "+qdisc dev %s: %s handle %s\n" qd.device
                     qd.kind qd.handle)))
      | Class_add cl -> (
          let key = cl.device ^ ":" ^ cl.classid in
          match List.assoc_opt key obs_class_map with
          | None ->
              changes := true;
              Buffer.add_string buf
                (Printf.sprintf "-class dev %s classid %s: missing\n" cl.device
                   cl.classid);
              Buffer.add_string buf
                (Printf.sprintf
                   "+class dev %s parent %s classid %s %s rate %s\n" cl.device
                   cl.parent cl.classid cl.kind cl.rate)
          | Some obs ->
              if
                not
                  (String.equal cl.kind obs.kind
                  && String.equal cl.classid obs.classid)
              then (
                changes := true;
                Buffer.add_string buf
                  (Printf.sprintf
                     "-class dev %s: %s classid %s parent %s rate %s\n"
                     cl.device obs.kind obs.classid obs.parent obs.rate);
                Buffer.add_string buf
                  (Printf.sprintf
                     "+class dev %s: %s classid %s parent %s rate %s\n"
                     cl.device cl.kind cl.classid cl.parent cl.rate))))
    intended;
  if not !changes then
    { changes_required = false; text = "tc diff: no changes\n" }
  else
    {
      changes_required = true;
      text = "tc diff: changes required\n" ^ Buffer.contents buf;
    }

let delete_invocation device =
  {
    Process.program = "tc";
    argv = [ "tc"; "qdisc"; "delete"; "dev"; device; "root" ];
  }

let delete_with_runner runner device =
  runner (delete_invocation device) |> Result.map ignore

let delete device = delete_with_runner Nft.run device
