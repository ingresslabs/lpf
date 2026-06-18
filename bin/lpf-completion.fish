# lpf fish completion

complete -f -c lpf

complete -c lpf -n 'not __fish_seen_subcommand_from check fmt plan diff apply confirm rollback explain test table state rules history sysctl man tools version help completion' -a check -d 'Parse and validate a policy'
complete -c lpf -n 'not __fish_seen_subcommand_from check fmt plan diff apply confirm rollback explain test table state rules history sysctl man tools version help completion' -a fmt -d 'Format policy files'
complete -c lpf -n 'not __fish_seen_subcommand_from check fmt plan diff apply confirm rollback explain test table state rules history sysctl man tools version help completion' -a plan -d 'Compile policy to a JSON plan'
complete -c lpf -n 'not __fish_seen_subcommand_from check fmt plan diff apply confirm rollback explain test table state rules history sysctl man tools version help completion' -a diff -d 'Compare intended state with live state'
complete -c lpf -n 'not __fish_seen_subcommand_from check fmt plan diff apply confirm rollback explain test table state rules history sysctl man tools version help completion' -a apply -d 'Apply policy'
complete -c lpf -n 'not __fish_seen_subcommand_from check fmt plan diff apply confirm rollback explain test table state rules history sysctl man tools version help completion' -a confirm -d 'Confirm pending guarded apply'
complete -c lpf -n 'not __fish_seen_subcommand_from check fmt plan diff apply confirm rollback explain test table state rules history sysctl man tools version help completion' -a rollback -d 'Restore previous policy'
complete -c lpf -n 'not __fish_seen_subcommand_from check fmt plan diff apply confirm rollback explain test table state rules history sysctl man tools version help completion' -a explain -d 'Explain packet handling'
complete -c lpf -n 'not __fish_seen_subcommand_from check fmt plan diff apply confirm rollback explain test table state rules history sysctl man tools version help completion' -a test -d 'Run policy assertion tests'
complete -c lpf -n 'not __fish_seen_subcommand_from check fmt plan diff apply confirm rollback explain test table state rules history sysctl man tools version help completion' -a table -d 'Manage dynamic tables'
complete -c lpf -n 'not __fish_seen_subcommand_from check fmt plan diff apply confirm rollback explain test table state rules history sysctl man tools version help completion' -a state -d 'Inspect conntrack state'
complete -c lpf -n 'not __fish_seen_subcommand_from check fmt plan diff apply confirm rollback explain test table state rules history sysctl man tools version help completion' -a rules -d 'Show or diff rendered rules'
complete -c lpf -n 'not __fish_seen_subcommand_from check fmt plan diff apply confirm rollback explain test table state rules history sysctl man tools version help completion' -a history -d 'Show policy apply history'
complete -c lpf -n 'not __fish_seen_subcommand_from check fmt plan diff apply confirm rollback explain test table state rules history sysctl man tools version help completion' -a sysctl -d 'Check or diff sysctl values'
complete -c lpf -n 'not __fish_seen_subcommand_from check fmt plan diff apply confirm rollback explain test table state rules history sysctl man tools version help completion' -a man -d 'Manage man pages'
complete -c lpf -n 'not __fish_seen_subcommand_from check fmt plan diff apply confirm rollback explain test table state rules history sysctl man tools version help completion' -a tools -d 'Generate AI tool schemas'
complete -c lpf -n 'not __fish_seen_subcommand_from check fmt plan diff apply confirm rollback explain test table state rules history sysctl man tools version help completion' -a version -d 'Print version'
complete -c lpf -n 'not __fish_seen_subcommand_from check fmt plan diff apply confirm rollback explain test table state rules history sysctl man tools version help completion' -a help -d 'Print help'
complete -c lpf -n 'not __fish_seen_subcommand_from check fmt plan diff apply confirm rollback explain test table state rules history sysctl man tools version help completion' -a completion -d 'Print completion script'

# check
complete -c lpf -n '__fish_seen_subcommand_from check' -l json -d 'JSON output'
complete -c lpf -n '__fish_seen_subcommand_from check' -a '(__fish_complete_suffix .lpf)'

# fmt
complete -c lpf -n '__fish_seen_subcommand_from fmt' -l check -d 'Check-only mode'
complete -c lpf -n '__fish_seen_subcommand_from fmt' -l json -d 'JSON output'
complete -c lpf -n '__fish_seen_subcommand_from fmt' -a '(__fish_complete_suffix .lpf)'

# plan
complete -c lpf -n '__fish_seen_subcommand_from plan' -l json -d 'JSON output'
complete -c lpf -n '__fish_seen_subcommand_from plan' -l backend -d 'Select backend' -a 'nftables tc routing'
complete -c lpf -n '__fish_seen_subcommand_from plan' -a '(__fish_complete_suffix .lpf)'

# diff
complete -c lpf -n '__fish_seen_subcommand_from diff' -l backend -d 'Select backend' -a 'nftables tc routing'
complete -c lpf -n '__fish_seen_subcommand_from diff' -l observed -d 'Observed ruleset path' -r
complete -c lpf -n '__fish_seen_subcommand_from diff' -l live -d 'Compare against live state'
complete -c lpf -n '__fish_seen_subcommand_from diff' -l json -d 'JSON output'
complete -c lpf -n '__fish_seen_subcommand_from diff' -a '(__fish_complete_suffix .lpf)'

# apply
complete -c lpf -n '__fish_seen_subcommand_from apply' -l confirm -d 'Guarded apply with duration' -a '10s 30s 60s 120s 300s'
complete -c lpf -n '__fish_seen_subcommand_from apply' -l dry-run -d 'Validate and plan without applying'
complete -c lpf -n '__fish_seen_subcommand_from apply' -a '(__fish_complete_suffix .lpf)'

# rollback
complete -c lpf -n '__fish_seen_subcommand_from rollback' -l now -d 'Rollback immediately'

# explain
complete -c lpf -n '__fish_seen_subcommand_from explain' -l json -d 'JSON output'
complete -c lpf -n '__fish_seen_subcommand_from explain' -a '(__fish_complete_suffix .lpf)'

# test
complete -c lpf -n '__fish_seen_subcommand_from test' -l junit -d 'JUnit output path' -r
complete -c lpf -n '__fish_seen_subcommand_from test' -a '(__fish_complete_suffix .lpf)'

# table
complete -c lpf -n '__fish_seen_subcommand_from table' -l json -d 'JSON output'
complete -c lpf -n '__fish_seen_subcommand_from table' -a 'add delete replace flush counters'

# state
complete -c lpf -n '__fish_seen_subcommand_from state' -l json -d 'JSON output'
complete -c lpf -n '__fish_seen_subcommand_from state' -a 'list flush kill'
complete -c lpf -n '__fish_seen_subcommand_from state' -l src -d 'Source address'
complete -c lpf -n '__fish_seen_subcommand_from state' -l dst -d 'Destination address'

# rules
complete -c lpf -n '__fish_seen_subcommand_from rules' -a 'show diff'
complete -c lpf -n '__fish_seen_subcommand_from rules' -l backend -d 'Select backend' -a 'nftables tc routing'
complete -c lpf -n '__fish_seen_subcommand_from rules' -l observed -d 'Observed ruleset path' -r
complete -c lpf -n '__fish_seen_subcommand_from rules' -l live -d 'Compare against live state'
complete -c lpf -n '__fish_seen_subcommand_from rules' -a '(__fish_complete_suffix .lpf)'

# history
complete -c lpf -n '__fish_seen_subcommand_from history' -l json -d 'JSON output'

# sysctl
complete -c lpf -n '__fish_seen_subcommand_from sysctl' -a 'check diff'
complete -c lpf -n '__fish_seen_subcommand_from sysctl' -l json -d 'JSON output'
complete -c lpf -n '__fish_seen_subcommand_from sysctl; and __fish_seen_subcommand_from diff' -l json -d 'JSON output'

# man
complete -c lpf -n '__fish_seen_subcommand_from man' -a 'generate check install'
complete -c lpf -n '__fish_seen_subcommand_from man' -l dir -d 'Output directory' -r
complete -c lpf -n '__fish_seen_subcommand_from man' -l prefix -d 'Install prefix' -r

# tools
complete -c lpf -n '__fish_seen_subcommand_from tools' -l format -d 'Output format' -a 'openai jsonschema system-prompt'

# completion
complete -c lpf -n '__fish_seen_subcommand_from completion' -a 'bash zsh fish'
