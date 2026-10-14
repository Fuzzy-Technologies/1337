# fuzzy1337.shell

Foreground `ci scan` preserves explicit CLI arguments and predicate/failure exit
statuses. CI input paths and criteria are excluded from persisted/replayed
argument history before the owning consumer executes.

The interactive shell shares the explicit local intelligence commands with the
product CLI. Intelligence command arguments are excluded from persisted history;
the same receipt, scope and model-save boundaries apply in both interfaces.

Foreground `scan config` uses the same explicit five-case configuration adapter
as the CLI. Product command arguments remain excluded from persisted history;
shell selection never supplies source paths, scope or SAFE approval.

::: fuzzy1337.shell
