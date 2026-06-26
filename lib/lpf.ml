type command = Command.command =
  | Check
  | Fmt
  | Plan
  | Diff
  | Apply
  | Confirm
  | Rollback
  | Explain
  | Test
  | Table
  | State
  | Rules
  | Ebpf
  | History
  | Man
  | Tools
  | Sysctl
  | Completion
  | Version
  | Help
  | Verify

type command_doc = Command.command_doc = {
  command : command;
  section : int;
  synopsis : string;
  description : string list;
  options : (string * string) list;
  examples : string list;
  files : string list;
  safety_notes : string list;
  see_also : string list;
}

type man_page = Manpage.man_page = {
  filename : string;
  section : int;
  title : string;
  content : string;
}

module Policy = Policy
module Ir = Ir
module Plan = Plan
module Nftables = Nftables
module Tc = Tc
module Routing = Routing
module Nft = Nft
module Ebpf = Ebpf
module Explain = Explain
module Json_util = Json_util
module Test_engine = Test_engine
module Test_parser = Test_parser
module History = History
module Apply_guard = Apply_guard
module Conntrack = Conntrack
module Table = Table
module Ip = Ip
module Sysctl = Sysctl
module Lpf_conf = Lpf_conf
module Process = Process
module File_util = File_util
module Json_parse = Json_parse
module Cni = Cni
module Network_policy_translate = Network_policy_translate
module Nomad_policy_translate = Nomad_policy_translate

let version = Command.version
let all_commands = Command.all_commands
let command_name = Command.command_name
let command_of_string = Command.command_of_string
let command_summary = Command.command_summary
let command_docs = Command.command_docs
let help = Command.help
let command_help = Command.command_help
let man_pages = Manpage.man_pages
let man_page_content = Manpage.man_page_content
let ir_of_policy = Pipeline.ir_of_policy
let plan_of_policy = Pipeline.plan_of_policy
let check_policy_text = Pipeline.check_policy_text
let format_policy_text = Pipeline.format_policy_text
let plan_policy_text = Pipeline.plan_policy_text
let render_nftables_policy_text = Pipeline.render_nftables_policy_text
let render_tc_policy_text = Pipeline.render_tc_policy_text
let render_routing_policy_text = Pipeline.render_routing_policy_text
let render_ebpf_policy_text = Pipeline.render_ebpf_policy_text
let render_ebpf_loader_text = Pipeline.render_ebpf_loader_text
let diff_ebpf_policy = Pipeline.diff_ebpf_policy
let diff_nftables_policy_text = Pipeline.diff_nftables_policy_text
let diff_nftables_policy = Pipeline.diff_nftables_policy
let diff_tc_policy = Pipeline.diff_tc_policy
let diff_routing_policy = Pipeline.diff_routing_policy
let explain_policy_text = Pipeline.explain_policy_text
let run_policy_tests = Pipeline.run_policy_tests
let apply_policy_text = Apply_guard.apply_policy_text
let confirm = Apply_guard.confirm
let rollback_now = Apply_guard.rollback_now
let get_history = Apply_guard.get_history
