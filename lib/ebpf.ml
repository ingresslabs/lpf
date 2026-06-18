open Ir

let header = "
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

"

let sanitize_identifier name =
  let buffer = Buffer.create (String.length name) in
  String.iter
    (function
      | 'a' .. 'z' | 'A' .. 'Z' | '0' .. '9' | '_' as c -> Buffer.add_char buffer c
      | '-' -> Buffer.add_char buffer '_'
      | _ -> Buffer.add_char buffer '_')
    name;
  let sanitized = Buffer.contents buffer in
  if sanitized = "" then "unnamed" else sanitized

let compile_table (table : table) =
  Printf.sprintf "struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u8);
} table_%s SEC(\".maps\");
" (sanitize_identifier table.name)

let action_to_xdp = function
  | Policy.Pass -> "XDP_PASS"
  | Policy.Block -> "XDP_DROP"
  | Policy.Reject -> "XDP_TX" (* For PoC, just reflect or drop. XDP_TX requires more work, but XDP_DROP is fine for now *)

let compile_address (addr : address) prefix =
  match addr with
  | Any -> ""
  | Literal l ->
      (* Very basic naive conversion for PoC *)
      Printf.sprintf "    if (%saddr != %s) continue;\n" prefix (sanitize_identifier l)
  | Table name ->
      Printf.sprintf "    __u8 *%s_val = bpf_map_lookup_elem(&table_%s, &%saddr);\n    if (!%s_val) continue;\n" prefix (sanitize_identifier name) prefix prefix

let compile_rule (rule : rule) =
  let protocol_check =
    match rule.protocol with
    | Policy.Proto_any -> ""
    | Policy.Proto_named "tcp" -> "    if (ip->protocol != IPPROTO_TCP) continue;\n"
    | Policy.Proto_named "udp" -> "    if (ip->protocol != IPPROTO_UDP) continue;\n"
    | Policy.Proto_named "icmp" -> "    if (ip->protocol != IPPROTO_ICMP) continue;\n"
    | _ -> ""
  in
  let saddr_check = compile_address rule.source "s" in
  let daddr_check = compile_address rule.destination "d" in
  
  let action = action_to_xdp rule.action in
  Printf.sprintf "  do {\n%s%s%s    return %s;\n  } while(0);\n" protocol_check saddr_check daddr_check action

let compile_to_c (ir : Ir.t) =
  let tables = String.concat "\n" (List.map compile_table ir.tables) in
  let rules = String.concat "\n" (List.map compile_rule ir.rules) in
  let default_action =
    match ir.default_action with
    | Policy.Default_pass -> "XDP_PASS"
    | Policy.Default_deny -> "XDP_DROP"
  in
  let prog = Printf.sprintf "
SEC(\"xdp\")
int lpf_xdp_prog(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  struct ethhdr *eth = data;
  if (data + sizeof(*eth) > data_end) return XDP_PASS;

  if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

  struct iphdr *ip = data + sizeof(*eth);
  if (data + sizeof(*eth) + sizeof(*ip) > data_end) return XDP_PASS;

  __u32 saddr = ip->saddr;
  __u32 daddr = ip->daddr;

%s

  return %s;
}

char _license[] SEC(\"license\") = \"GPL\";
" rules default_action in
  header ^ tables ^ prog
