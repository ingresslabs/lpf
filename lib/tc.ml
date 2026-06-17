type command =
  | Qdisc_add of { device : string; handle : string; parent : string; kind : string; default : int option }
  | Class_add of { device : string; classid : string; parent : string; kind : string; rate : string }

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
        let existing = match List.assoc_opt device acc with Some l -> l | None -> [] in
        (device, q :: existing) :: List.remove_assoc device acc)
      [] ir.queues
  in
  List.concat_map
    (fun (device, device_queues) ->
      let qdisc =
        Qdisc_add { device; handle = "1:"; parent = "root"; kind = "htb"; default = None }
      in
      let classes =
        List.rev_map
          (fun (q : Ir.queue) ->
            let classid = Option.get (queue_classid ir.queues q.name) in
            let parent =
              match q.parent with
              | None -> "1:"
              | Some parent_name -> Option.get (queue_classid ir.queues parent_name)
            in
            Class_add { device; classid; parent; kind = "htb"; rate = q.bandwidth })
          device_queues
      in
      qdisc :: classes)
    queues_by_device

let string_of_command = function
  | Qdisc_add { device; handle; parent; kind; default } ->
      let default_str = match default with Some d -> Printf.sprintf " default %d" d | None -> "" in
      Printf.sprintf "tc qdisc add dev %s %s handle %s %s%s" device parent handle kind default_str
  | Class_add { device; classid; parent; kind; rate } ->
      Printf.sprintf "tc class add dev %s parent %s classid %s %s rate %s" device parent classid kind rate

let to_string t =
  String.concat "\n" (List.map string_of_command t) ^ if t = [] then "" else "\n"
