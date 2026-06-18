#compdef lpf

_lpf() {
  local curcontext="$curcontext" state line
  typeset -A opt_args

  _arguments -C \
    '1:command:->command' \
    '*::arg:->args'

  case $state in
    command)
      local -a commands
      commands=(
        "check:Parse and validate a policy"
        "fmt:Format policy files"
        "plan:Compile policy to a JSON plan"
        "diff:Compare intended state with live state"
        "apply:Apply policy"
        "confirm:Confirm pending guarded apply"
        "rollback:Restore previous policy"
        "explain:Explain packet handling"
        "test:Run policy assertion tests"
        "table:Manage dynamic tables"
        "state:Inspect conntrack state"
        "rules:Show or diff rendered rules"
        "history:Show policy apply history"
        "sysctl:Check or diff sysctl values"
        "man:Manage man pages"
        "tools:Generate AI tool schemas"
        "version:Print version"
        "help:Print help"
        "completion:Print completion script"
      )
      _describe -t commands 'lpf command' commands
      ;;
    args)
      local cmd="${words[1]}"
      case "$cmd" in
        check)
          _arguments \
            '--json[JSON output]' \
            '*:policy file:_files -g "*.lpf"'
          ;;
        fmt)
          _arguments \
            '--check[check-only mode]' \
            '--json[JSON output]' \
            '*:policy file:_files -g "*.lpf"'
          ;;
        plan)
          _arguments \
            '--json[JSON output]' \
            '--backend[select backend]:backend:(nftables tc routing)' \
            '*:policy file:_files -g "*.lpf"'
          ;;
        diff)
          _arguments \
            '--backend[select backend]:backend:(nftables tc routing)' \
            '--observed[observed ruleset path]:file:_files' \
            '--live[compare against live state]' \
            '--json[JSON output]' \
            '*:policy file:_files -g "*.lpf"'
          ;;
        apply)
          _arguments \
            '--confirm[guarded apply with duration]:duration:(10s 30s 60s 120s 300s)' \
            '--dry-run[validate and plan without applying]' \
            '*:policy file:_files -g "*.lpf"'
          ;;
        confirm)
          ;;
        rollback)
          _arguments \
            '--now[rollback immediately]' \
            '*:policy file:_files -g "*.lpf"'
          ;;
        explain)
          _arguments \
            '--json[JSON output]' \
            '--from[source address]:address:' \
            '--to[destination address]:address:' \
            '--proto[protocol]:protocol:' \
            '--port[destination port]:port:' \
            '*:policy file:_files -g "*.lpf"'
          ;;
        test)
          _arguments \
            '--junit[junit output path]:file:_files' \
            '*:fixture file:_files -g "*.lpf"'
          ;;
        table)
          _arguments \
            '--json[JSON output]' \
            '1:table name:' \
            '2:action:(add delete replace flush counters)'
          ;;
        state)
          _arguments \
            '--json[JSON output]' \
            '1:action:(list flush kill)' \
            '--src[source address]:address:' \
            '--dst[destination address]:address:'
          ;;
        rules)
          _arguments \
            '1:action:(show diff)' \
            '--backend[select backend]:backend:(nftables tc routing)' \
            '--observed[observed ruleset path]:file:_files' \
            '--live[compare against live state]' \
            '*:policy file:_files -g "*.lpf"'
          ;;
        history)
          _arguments \
            '--json[JSON output]'
          ;;
        sysctl)
          _arguments \
            '--json[JSON output]' \
            '1:action:(check diff)'
          ;;
        man)
          _arguments \
            '1:action:(generate check install)' \
            '--dir[output directory]:directory:_files -/' \
            '--prefix[install prefix]:directory:_files -/'
          ;;
        tools)
          _arguments \
            '--format[output format]:format:(openai jsonschema system-prompt)'
          ;;
        version|help)
          ;;
        completion)
          _arguments \
            '1:shell:(bash zsh fish)'
          ;;
      esac
      ;;
  esac
}

_lpf "$@"
