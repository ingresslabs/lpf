let of_ruleset ruleset =
  let lines = String.split_on_char '\n' ruleset in
  let rec parse_block acc depth = function
    | [] -> List.rev acc
    | line :: rest ->
        let line = String.trim line in
        if String.starts_with ~prefix:"}" line then List.rev acc
        else if String.contains line '{' then
          let inner = ref [] in
          let rec collect = function
            | [] -> ()
            | l :: rest ->
                let l = String.trim l in
                if String.starts_with ~prefix:"}" l then ()
                else (inner := l :: !inner; collect rest)
          in
          collect rest;
          let inner_lines = List.rev !inner in
          parse_block (acc @ [ line ] @ inner_lines) depth rest
        else parse_block (acc @ [ line ]) depth rest
  in
  let _ = parse_block [] 0 lines in
  "import stub: use lpf import nftables to convert nft ruleset"
