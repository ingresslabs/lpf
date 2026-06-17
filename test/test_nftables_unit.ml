let contains_substring text needle =
  let text_length = String.length text in
  let needle_length = String.length needle in
  if needle_length = 0 then true
  else
    let rec loop index =
      index + needle_length <= text_length
      && (String.equal (String.sub text index needle_length) needle || loop (index + 1))
    in
    loop 0

let () =
  let owned = Lpf.Nftables.owned_ruleset_text
    "table inet non_lpf { chain output { type filter hook output priority 0; policy accept; } }\n\
     table inet lpf_filter {\n\
     \  chain input { type filter hook input priority 0; policy drop; drop comment \"lpf rule 1:1\" }\n\
     \  chain output { type filter hook output priority 0; policy drop; }\n\
     }" in
  assert (contains_substring owned "table inet lpf_filter");
  assert (not (contains_substring owned "non_lpf"));

  let just_ours = {|
flush ruleset

table inet lpf_filter {
  chain input {
    type filter hook input priority 0; policy drop;
    drop comment "lpf rule 1:1"
  }
}
|} in
  let intended = just_ours in
  let diff = Lpf.Nftables.diff ~intended ~observed:just_ours in
  assert (not diff.Lpf.Nftables.changes_required);

  let observed_changed = {|
flush ruleset

table inet lpf_filter {
  chain input {
    type filter hook input priority 0; policy drop;
    drop comment "lpf rule 1:1"
  }
  chain output {
    type filter hook output priority 0; policy drop;
  }
}
|} in
  let diff = Lpf.Nftables.diff ~intended ~observed:observed_changed in
  assert diff.Lpf.Nftables.changes_required;

  let diff_text = Lpf.Nftables.diff_text ~intended ~observed:observed_changed in
  assert (String.length diff_text > 0)
