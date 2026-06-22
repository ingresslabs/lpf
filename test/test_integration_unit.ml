let () =
  let require condition message = if not condition then failwith message in

  (* --- ip.ml: parse_rule_list --- *)
  let rules = Lpf.Ip.parse_rule_list "" in
  require (rules = []) "parse_rule_list empty string";

  let rules = Lpf.Ip.parse_rule_list "0: from all lookup local" in
  require (rules = []) "parse_rule_list non-numeric table (local) filtered out";

  let rules = Lpf.Ip.parse_rule_list "32766: from all lookup main" in
  require (rules = []) "parse_rule_list non-numeric table (main) filtered out";

  let rules = Lpf.Ip.parse_rule_list "100: from all fwmark 0x64 lookup 100" in
  require (List.length rules = 1) "parse_rule_list single rule with fwmark";
  (match rules with
  | [ r ] ->
      require (r.Lpf.Ip.priority = 100) "parse_rule_list priority";
      require
        (r.Lpf.Ip.fwmark = Some 100)
        "parse_rule_list fwmark parsed as hex 0x64=100";
      require (r.Lpf.Ip.table = 100) "parse_rule_list table"
  | _ -> assert false);

  let rules = Lpf.Ip.parse_rule_list "0: from all lookup 200" in
  require (List.length rules = 1) "parse_rule_list rule without fwmark";
  (match rules with
  | [ r ] ->
      require (r.Lpf.Ip.priority = 0) "parse_rule_list zero priority";
      require (r.Lpf.Ip.fwmark = None) "parse_rule_list no fwmark";
      require (r.Lpf.Ip.table = 200) "parse_rule_list table 200"
  | _ -> assert false);

  let rules = Lpf.Ip.parse_rule_list "50: from all fwmark 0x1 lookup 300" in
  (match rules with
  | [ r ] ->
      require (r.Lpf.Ip.fwmark = Some 1) "parse_rule_list fwmark 0x1 = 1";
      require (r.Lpf.Ip.table = 300) "parse_rule_list table 300"
  | _ -> assert false);

  let output =
    "0: from all lookup 200\n\
     100: from all fwmark 0x64 lookup 100\n\n\
     32766: from all lookup main\n"
  in
  let rules = Lpf.Ip.parse_rule_list output in
  require
    (List.length rules = 2)
    "parse_rule_list multiple rules (non-numeric filtered, blank line skipped)";
  (match rules with
  | [ a; b ] ->
      require (a.Lpf.Ip.table = 200) "parse_rule_list first rule table";
      require (b.Lpf.Ip.priority = 100) "parse_rule_list second rule priority";
      require (b.Lpf.Ip.fwmark = Some 100) "parse_rule_list second rule fwmark";
      require (b.Lpf.Ip.table = 100) "parse_rule_list second rule table"
  | _ -> assert false);

  let output =
    "100: from all fwmark 0xA lookup 10\n200: from all fwmark 0xFF lookup 255\n"
  in
  let rules = Lpf.Ip.parse_rule_list output in
  require (List.length rules = 2) "parse_rule_list two hex fwmark rules";
  (match rules with
  | [ a; b ] ->
      require (a.Lpf.Ip.fwmark = Some 10) "parse_rule_list 0xA = 10";
      require (b.Lpf.Ip.fwmark = Some 255) "parse_rule_list 0xFF = 255"
  | _ -> assert false);

  Printf.printf "ip parse_rule_list tests passed\n";

  (* --- ip.ml: parse_route_show --- *)
  let routes = Lpf.Ip.parse_route_show "" in
  require (routes = []) "parse_route_show empty string";

  let routes = Lpf.Ip.parse_route_show "default via 10.0.0.1 dev eth0" in
  require (List.length routes = 1) "parse_route_show default route";
  (match routes with
  | [ r ] ->
      require
        (String.equal r.Lpf.Ip.gateway "10.0.0.1")
        "parse_route_show default gateway";
      require (r.Lpf.Ip.device = Some "eth0") "parse_route_show default device";
      require (r.Lpf.Ip.table = 0) "parse_route_show default table"
  | _ -> assert false);

  let routes = Lpf.Ip.parse_route_show "default via 10.0.0.1" in
  (match routes with
  | [ r ] ->
      require
        (String.equal r.Lpf.Ip.gateway "10.0.0.1")
        "parse_route_show default no device gateway";
      require (r.Lpf.Ip.device = None) "parse_route_show default no device"
  | _ -> assert false);

  let routes = Lpf.Ip.parse_route_show "10.0.0.0/24 via 10.0.0.1 dev eth0" in
  (match routes with
  | [ r ] ->
      require
        (String.equal r.Lpf.Ip.gateway "10.0.0.1")
        "parse_route_show subnet gateway";
      require (r.Lpf.Ip.device = Some "eth0") "parse_route_show subnet device"
  | _ -> assert false);

  let routes = Lpf.Ip.parse_route_show "10.0.0.0/24 dev eth0" in
  (match routes with
  | [ r ] ->
      require
        (String.equal r.Lpf.Ip.gateway "")
        "parse_route_show subnet no via (empty gateway)";
      require
        (r.Lpf.Ip.device = Some "eth0")
        "parse_route_show subnet no via device"
  | _ -> assert false);

  let output =
    "default via 10.0.0.1 dev eth0\n10.0.0.0/24 via 10.0.0.1 dev eth0\n\n"
  in
  let routes = Lpf.Ip.parse_route_show output in
  require
    (List.length routes = 2)
    "parse_route_show multiple routes (blank line skipped)";
  (match routes with
  | [ a; b ] ->
      require
        (String.equal a.Lpf.Ip.gateway "10.0.0.1")
        "parse_route_show multi first gateway";
      require
        (String.equal b.Lpf.Ip.gateway "10.0.0.1")
        "parse_route_show multi second gateway"
  | _ -> assert false);

  let routes = Lpf.Ip.parse_route_show "default via 198.51.100.1 dev wan0" in
  (match routes with
  | [ r ] ->
      require
        (String.equal r.Lpf.Ip.gateway "198.51.100.1")
        "parse_route_show wan gateway";
      require (r.Lpf.Ip.device = Some "wan0") "parse_route_show wan device"
  | _ -> assert false);

  Printf.printf "ip parse_route_show tests passed\n";

  (* --- sysctl.ml: to_json / of_json round-trip --- *)
  let entries = [ Lpf.Sysctl.{ key = "net.ipv4.ip_forward"; value = "1" } ] in
  let json = Lpf.Sysctl.to_json entries in
  require (String.length json > 0) "sysctl to_json non-empty";
  let parsed = Lpf.Sysctl.of_json json in
  require (List.length parsed = 1) "sysctl of_json single entry round-trip";
  (match parsed with
  | [ e ] ->
      require
        (String.equal e.Lpf.Sysctl.key "net.ipv4.ip_forward")
        "sysctl round-trip key";
      require (String.equal e.Lpf.Sysctl.value "1") "sysctl round-trip value"
  | _ -> assert false);

  let entries =
    [ Lpf.Sysctl.{ key = "net.ipv6.conf.all.forwarding"; value = "0" } ]
  in
  let json = Lpf.Sysctl.to_json entries in
  let parsed = Lpf.Sysctl.of_json json in
  require (List.length parsed = 1) "sysctl of_json ipv6 round-trip";
  (match parsed with
  | [ e ] ->
      require
        (String.equal e.Lpf.Sysctl.key "net.ipv6.conf.all.forwarding")
        "sysctl ipv6 round-trip key";
      require
        (String.equal e.Lpf.Sysctl.value "0")
        "sysctl ipv6 round-trip value"
  | _ -> assert false);

  let entries = [] in
  let json = Lpf.Sysctl.to_json entries in
  let parsed = Lpf.Sysctl.of_json json in
  require (parsed = []) "sysctl empty list round-trip";

  let entries =
    [
      Lpf.Sysctl.{ key = "k"; value = "v" };
      Lpf.Sysctl.{ key = "a"; value = "b" };
    ]
  in
  let json = Lpf.Sysctl.to_json entries in
  require (String.length json > 0) "sysctl multi-entry to_json";
  let parsed = Lpf.Sysctl.of_json json in
  require
    (List.length parsed = 2)
    "sysctl multi-entry of_json recovers every entry";

  (* snapshot produces real entries on Linux; to_json should always produce valid json *)
  let json = Lpf.Sysctl.to_json (Lpf.Sysctl.snapshot ()) in
  require
    (String.length json >= 2)
    "sysctl snapshot to_json produces valid json";

  Printf.printf "sysctl to_json/of_json round-trip tests passed\n";

  (* --- conntrack.ml: parse_list (exercising parse_line) --- *)
  let entries = Lpf.Conntrack.parse_list "" in
  require (entries = []) "conntrack parse_list empty string";

  let entries = Lpf.Conntrack.parse_list "   " in
  require (entries = []) "conntrack parse_list whitespace only";

  let entries = Lpf.Conntrack.parse_list "tcp" in
  require (entries = []) "conntrack parse_list single field ignored";

  let entries =
    Lpf.Conntrack.parse_list "tcp 10.0.0.1 10.0.0.2 12345 80 ESTABLISHED"
  in
  require (List.length entries = 1) "conntrack parse_list positional format";
  (match entries with
  | [ e ] ->
      require
        (String.equal e.Lpf.Conntrack.protocol "tcp")
        "conntrack positional protocol";
      require
        (String.equal e.Lpf.Conntrack.src "10.0.0.1")
        "conntrack positional src";
      require
        (String.equal e.Lpf.Conntrack.dst "10.0.0.2")
        "conntrack positional dst";
      require
        (String.equal e.Lpf.Conntrack.state "ESTABLISHED")
        "conntrack positional state"
  | _ -> assert false);

  let entries =
    Lpf.Conntrack.parse_list
      "tcp 10.0.0.1 10.0.0.2 sport 12345 dport 80 ESTABLISHED"
  in
  require
    (List.length entries = 1)
    "conntrack parse_list keyword sport/dport tokens";
  (match entries with
  | [ e ] ->
      require
        (String.equal e.Lpf.Conntrack.protocol "tcp")
        "conntrack keyword protocol";
      require
        (String.equal e.Lpf.Conntrack.sport "12345")
        "conntrack keyword sport";
      require
        (String.equal e.Lpf.Conntrack.dport "80")
        "conntrack keyword dport";
      require
        (String.equal e.Lpf.Conntrack.state "ESTABLISHED")
        "conntrack keyword state"
  | _ -> assert false);

  let entries =
    Lpf.Conntrack.parse_list "tcp 10.0.0.1 10.0.0.2 12345 80 TIME_WAIT"
  in
  (match entries with
  | [ e ] ->
      require
        (String.equal e.Lpf.Conntrack.state "TIME_WAIT")
        "conntrack TIME_WAIT state"
  | _ -> assert false);

  let entries =
    Lpf.Conntrack.parse_list "tcp 10.0.0.1 10.0.0.2 12345 80 CLOSE"
  in
  (match entries with
  | [ e ] ->
      require
        (String.equal e.Lpf.Conntrack.state "CLOSE")
        "conntrack CLOSE state"
  | _ -> assert false);

  let entries =
    Lpf.Conntrack.parse_list "tcp 10.0.0.1 10.0.0.2 12345 80 SYN_SENT"
  in
  (match entries with
  | [ e ] ->
      require
        (String.equal e.Lpf.Conntrack.state "SYN_SENT")
        "conntrack SYN_SENT state"
  | _ -> assert false);

  let entries =
    Lpf.Conntrack.parse_list "tcp 10.0.0.1 10.0.0.2 12345 80 NONE"
  in
  (match entries with
  | [ e ] ->
      require (String.equal e.Lpf.Conntrack.state "NONE") "conntrack NONE state"
  | _ -> assert false);

  let entries =
    Lpf.Conntrack.parse_list "tcp 10.0.0.1 10.0.0.2 12345 80 ASSURED"
  in
  (match entries with
  | [ e ] ->
      require
        (String.equal e.Lpf.Conntrack.state "ASSURED")
        "conntrack ASSURED state"
  | _ -> assert false);

  let entries =
    Lpf.Conntrack.parse_list "tcp 10.0.0.1 10.0.0.2 12345 80 UNREPLIED"
  in
  (match entries with
  | [ e ] ->
      require
        (String.equal e.Lpf.Conntrack.state "UNREPLIED")
        "conntrack UNREPLIED state"
  | _ -> assert false);

  let entries =
    Lpf.Conntrack.parse_list "tcp 10.0.0.1 10.0.0.2 12345 80 [UNREPLIED]"
  in
  (match entries with
  | [ e ] ->
      require
        (String.equal e.Lpf.Conntrack.state "")
        "conntrack [UNREPLIED] not matched as state (bracketed, no following \
         token)"
  | _ -> assert false);

  let entries =
    Lpf.Conntrack.parse_list "udp 192.168.1.1 192.168.1.2 53 53 ASSURED"
  in
  (match entries with
  | [ e ] ->
      require
        (String.equal e.Lpf.Conntrack.protocol "udp")
        "conntrack udp protocol";
      require
        (String.equal e.Lpf.Conntrack.src "192.168.1.1")
        "conntrack udp src";
      require
        (String.equal e.Lpf.Conntrack.dst "192.168.1.2")
        "conntrack udp dst";
      require
        (String.equal e.Lpf.Conntrack.state "ASSURED")
        "conntrack udp state"
  | _ -> assert false);

  let output =
    "tcp 10.0.0.1 10.0.0.2 12345 80 ESTABLISHED\n\n\
     udp 192.168.1.1 192.168.1.2 53 53 ASSURED\n"
  in
  let entries = Lpf.Conntrack.parse_list output in
  require
    (List.length entries = 2)
    "conntrack parse_list multiple entries (blank line skipped)";
  (match entries with
  | [ a; b ] ->
      require
        (String.equal a.Lpf.Conntrack.protocol "tcp")
        "conntrack parse_list first proto";
      require
        (String.equal b.Lpf.Conntrack.protocol "udp")
        "conntrack parse_list second proto"
  | _ -> assert false);

  Printf.printf "conntrack parse_list tests passed\n";

  Printf.printf "all integration unit tests passed\n"
