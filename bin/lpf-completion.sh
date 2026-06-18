# lpf bash completion — install via `source bin/lpf-completion.sh` or copy to
# /etc/bash_completion.d/

_lpf_commands() {
  local cur prev words cword
  _init_completion || return

  local cmds="check fmt plan diff apply confirm rollback explain test table state rules history sysctl man tools version help completion"

  # subcommands that take further completions
  local rules_subs="show diff"
  local state_subs="list flush kill"
  local man_subs="generate check install"

  # find the top-level command
  local cmd=""
  local i
  for ((i = 1; i < cword; i++)); do
    if [[ " $cmds " == *" ${words[i]} "* ]]; then
      cmd="${words[i]}"
      break
    fi
  done

  if [[ -z "$cmd" ]]; then
    # completing top-level command
    COMPREPLY=($(compgen -W "$cmds" -- "$cur"))
    return
  fi

  case "$cmd" in
    check)
      COMPREPLY=($(compgen -W "--json" -- "$cur"))
      _filedir lpf
      ;;
    fmt)
      COMPREPLY=($(compgen -W "--check --json" -- "$cur"))
      _filedir lpf
      ;;
    plan)
      case "$prev" in
        --backend)
          COMPREPLY=($(compgen -W "nftables tc routing" -- "$cur"))
          return
          ;;
      esac
      COMPREPLY=($(compgen -W "--json --backend" -- "$cur"))
      _filedir lpf
      ;;
    diff)
      case "$prev" in
        --backend)
          COMPREPLY=($(compgen -W "nftables tc routing" -- "$cur"))
          return
          ;;
        --observed)
          _filedir
          return
          ;;
      esac
      COMPREPLY=($(compgen -W "--backend --observed --live --json" -- "$cur"))
      _filedir lpf
      ;;
    apply)
      case "$prev" in
        --confirm)
          COMPREPLY=($(compgen -W "10s 30s 60s 120s 300s" -- "$cur"))
          return
          ;;
      esac
      COMPREPLY=($(compgen -W "--confirm --dry-run" -- "$cur"))
      _filedir lpf
      ;;
    confirm)
      COMPREPLY=()
      ;;
    rollback)
      case "$prev" in
        --now)
          _filedir lpf
          return
          ;;
      esac
      COMPREPLY=($(compgen -W "--now" -- "$cur"))
      ;;
    explain)
      COMPREPLY=($(compgen -W "--json" -- "$cur"))
      _filedir lpf
      ;;
    test)
      case "$prev" in
        --junit)
          _filedir
          return
          ;;
      esac
      COMPREPLY=($(compgen -W "--junit" -- "$cur"))
      _filedir lpf
      ;;
    table)
      COMPREPLY=($(compgen -W "--json" -- "$cur"))
      ;;
    state)
      local sub=""
      for ((i = 1; i < cword; i++)); do
        if [[ " $state_subs " == *" ${words[i]} "* ]]; then
          sub="${words[i]}"
          break
        fi
      done
      if [[ -z "$sub" ]]; then
        COMPREPLY=($(compgen -W "--json $state_subs" -- "$cur"))
      else
        case "$prev" in
          --src | --dst)
            return
            ;;
        esac
        COMPREPLY=($(compgen -W "--json --src --dst" -- "$cur"))
      fi
      ;;
    rules)
      local sub=""
      for ((i = 1; i < cword; i++)); do
        if [[ " $rules_subs " == *" ${words[i]} "* ]]; then
          sub="${words[i]}"
          break
        fi
      done
      if [[ -z "$sub" ]]; then
        COMPREPLY=($(compgen -W "$rules_subs" -- "$cur"))
        _filedir lpf
      else
        case "$prev" in
          --backend)
            COMPREPLY=($(compgen -W "nftables tc routing" -- "$cur"))
            return
            ;;
          --observed)
            _filedir
            return
            ;;
        esac
        COMPREPLY=($(compgen -W "--backend --observed --live" -- "$cur"))
        _filedir lpf
      fi
      ;;
    history)
      COMPREPLY=($(compgen -W "--json" -- "$cur"))
      ;;
     sysctl)
      local subs="check diff apply"
      local sub=""
      for ((i = 1; i < cword; i++)); do
        if [[ " $subs " == *" ${words[i]} "* ]]; then
          sub="${words[i]}"
          break
        fi
      done
      if [[ -z "$sub" ]]; then
        COMPREPLY=($(compgen -W "$subs" -- "$cur"))
      else
        COMPREPLY=()
      fi
      ;;
    man)
      local sub=""
      for ((i = 1; i < cword; i++)); do
        if [[ " $man_subs " == *" ${words[i]} "* ]]; then
          sub="${words[i]}"
          break
        fi
      done
      if [[ -z "$sub" ]]; then
        COMPREPLY=($(compgen -W "$man_subs" -- "$cur"))
      else
        case "$prev" in
          --dir)
            _filedir -d
            return
            ;;
          --prefix)
            _filedir -d
            return
            ;;
        esac
        COMPREPLY=($(compgen -W "--dir --prefix" -- "$cur"))
      fi
      ;;
    tools)
      case "$prev" in
        --format)
          COMPREPLY=($(compgen -W "openai jsonschema system-prompt" -- "$cur"))
          return
          ;;
      esac
      COMPREPLY=($(compgen -W "--format" -- "$cur"))
      ;;
     version | help)
      COMPREPLY=()
      ;;
    completion)
      COMPREPLY=($(compgen -W "bash zsh fish" -- "$cur"))
      ;;
    *)
      COMPREPLY=()
      ;;
  esac
}

complete -F _lpf_commands lpf
