let contains_substring text needle =
  let text_length = String.length text in
  let needle_length = String.length needle in
  if needle_length = 0 then true
  else
    let rec loop index =
      index + needle_length <= text_length
      && (String.equal (String.sub text index needle_length) needle
         || loop (index + 1))
    in
    loop 0

let () =
  let owned =
    Lpf.Nftables.owned_ruleset_text
      "table inet non_lpf { chain output { type filter hook output priority 0; \
       policy accept; } }\n\
       table inet lpf_filter {\n\
      \  chain input { type filter hook input priority 0; policy drop; drop \
       comment \"lpf rule 1:1\" }\n\
      \  chain output { type filter hook output priority 0; policy drop; }\n\
       }"
  in
  assert (contains_substring owned "table inet lpf_filter");
  assert (not (contains_substring owned "non_lpf"));

  let just_ours =
    {|
flush ruleset

table inet lpf_filter {
  chain input {
    type filter hook input priority 0; policy drop;
    drop comment "lpf rule 1:1"
  }
}
|}
  in
  let intended = just_ours in
  let diff = Lpf.Nftables.diff ~intended ~observed:just_ours in
  assert (not diff.Lpf.Nftables.changes_required);

  let observed_changed =
    {|
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
|}
  in
  let diff = Lpf.Nftables.diff ~intended ~observed:observed_changed in
  assert diff.Lpf.Nftables.changes_required;

  let diff_text = Lpf.Nftables.diff_text ~intended ~observed:observed_changed in
  assert (String.length diff_text > 0);

  let canonical_observed =
    {|
table inet lpf_filter {
	set tbl_trusted {
		type ipv4_addr
		flags interval
		elements = { 10.0.0.1, 10.0.0.2 }
	}

	chain input {
		type filter hook input priority filter; policy drop;
		iifname "eth0" ip saddr @tbl_trusted tcp dport 22 ct state established,related,new accept comment "lpf rule 4:1"
	}
}
|}
  in
  let canonical_intended =
    {|
flush ruleset

table inet lpf_filter {
  set tbl_trusted {
    type ipv4_addr
    flags interval
    elements = { 10.0.0.2, 10.0.0.1 }
  }

  chain input {
    type filter hook input priority 0; policy drop;
    meta iifname "eth0" meta l4proto tcp ip saddr @tbl_trusted tcp dport 22 ct state new,established,related accept comment "lpf rule 4:1"
  }
}
|}
  in
  let diff =
    Lpf.Nftables.diff ~intended:canonical_intended ~observed:canonical_observed
  in
  assert (not diff.Lpf.Nftables.changes_required);

  let mark_observed =
    {|
table inet lpf_filter {
	chain input {
		type filter hook input priority filter; policy drop;
		iifname "lan0" tcp dport 443 ct state established,related,new meta mark set 0x00000064 accept comment "lpf rule 7:1"
	}
}
|}
  in
  let mark_intended =
    {|
flush ruleset

table inet lpf_filter {
  chain input {
    type filter hook input priority 0; policy drop;
    meta iifname "lan0" meta l4proto tcp tcp dport 443 ct state new,established,related meta mark set 100 accept comment "lpf rule 7:1"
  }
}
|}
  in
  let diff =
    Lpf.Nftables.diff ~intended:mark_intended ~observed:mark_observed
  in
  assert (not diff.Lpf.Nftables.changes_required);

  let nat_table_policy =
    "set default deny\n\n\
     interface wan = \"eth0\"\n\
     table <wg_peers> { 10.8.0.0/24 }\n\
     nat on wan from <wg_peers> to any -> wan\n\
     pass out on wan from <wg_peers> to any\n"
  in
  (match Lpf.render_nftables_policy_text nat_table_policy with
  | Ok (rendered, _) ->
      assert (contains_substring rendered "table inet lpf_nat");
      assert (contains_substring rendered "set tbl_wg_peers");
      assert (contains_substring rendered "ip saddr @tbl_wg_peers masquerade")
  | Error diagnostics ->
      failwith
        (String.concat "\n"
           (List.map Lpf.Policy.diagnostic_to_string diagnostics)));

  let rdr_policy =
    "set default deny\n\n\
     interface wan = \"eth0\"\n\
     rdr on wan proto tcp from any to any port 443 -> 10.30.0.10 port 8443\n"
  in
  (match Lpf.render_nftables_policy_text rdr_policy with
  | Ok (rendered, _) ->
      assert (contains_substring rendered "table inet lpf_nat");
      assert (contains_substring rendered "dnat ip to 10.30.0.10:8443")
  | Error diagnostics ->
      failwith
        (String.concat "\n"
           (List.map Lpf.Policy.diagnostic_to_string diagnostics)));

  let overlapping_policy =
    "set default deny\n\n\
     table <lan> { 10.0.0.0/24, 10.0.0.10 }\n\
     pass in from any to <lan>\n"
  in
  (match Lpf.render_nftables_policy_text overlapping_policy with
  | Ok (rendered, _) ->
      assert (contains_substring rendered "elements = { 10.0.0.0/24 }");
      assert (not (contains_substring rendered "10.0.0.10"))
  | Error diagnostics ->
      failwith
        (String.concat "\n"
           (List.map Lpf.Policy.diagnostic_to_string diagnostics)));

  let rollback =
    Lpf.Nftables.rollback_script ~current:"table inet lpf_filter {\n}\n"
      ~preimage:"table inet lpf_filter {\n}\n\ntable inet lpf_nat {\n}\n"
  in
  assert (contains_substring rollback "delete table inet lpf_filter");
  assert (contains_substring rollback "table inet lpf_nat");

  let ipv6_policy =
    "set default deny\n\n\
     pass out proto tcp from 2001:db8::1 to 2001:db8::2 port 443 keep state\n"
  in
  match Lpf.render_nftables_policy_text ipv6_policy with
  | Ok (rendered, _) ->
      assert (contains_substring rendered "ip6 saddr 2001:db8::1");
      assert (contains_substring rendered "ip6 daddr 2001:db8::2")
  | Error diagnostics ->
      failwith
        (String.concat "\n"
           (List.map Lpf.Policy.diagnostic_to_string diagnostics))
