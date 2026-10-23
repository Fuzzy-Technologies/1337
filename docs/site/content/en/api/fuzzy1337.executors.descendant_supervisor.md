# fuzzy1337.executors.descendant_supervisor

Internal installed isolated Linux supervisor under ADR 0091. It owns only its
kernel-listed direct and adopted children, with bounded cleanup and truthful
failure receipts. It is intended for trusted approved providers and provides no
same-UID containment or general OS sandbox. Invocation through the executor
preserves policy validation and private control-descriptor ownership.

::: fuzzy1337.executors.descendant_supervisor
