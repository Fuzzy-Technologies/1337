# fuzzy1337.adapters.native_http

Experimental first-party native HTTP sensor adapter, version 1, under ADR 0036.
Preparation accepts a bounded exact literal-IP URL and SAFE capability; it grants
no execution authority. Strict schema-v1 records reject extra fields, changed peers,
malformed output and unverified evidence before normalization. One valid HTTP status
produces canonical sensor envelopes and no vulnerability finding.

::: fuzzy1337.adapters.native_http
