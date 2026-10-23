# fuzzy1337.adapters.native_http

Experimental first-party native HTTP sensor adapter, version 1, under ADR 0036.
Preparation accepts a bounded exact literal-IP URL and SAFE capability; it grants
no execution authority. Strict schema-v1 records reject extra fields, changed peers,
malformed output and unverified evidence before normalization. One valid HTTP status
produces canonical sensor envelopes and no vulnerability finding.
Current preparation uses isolated Python imports under ADR 0087. Pure historical
report interpretation preserves its original invocation and grants no authority
to execute a non-isolated worker.

::: fuzzy1337.adapters.native_http
