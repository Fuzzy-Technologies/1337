# fuzzy1337.raw_cli

Experimental SDK for the finite native Nmap argument profiles in ADR 0111.
The supported Experimental interfaces are `RawNmapSelection`, `SelectRawNmap`
and `RawNmapAdapter`. Constants and `ParseNativeNmap` remain Internal helpers.
`SelectRawNmap` accepts explicit native token sequences, and `RawNmapSelection`
retains the original immutable tuple while deriving one literal IP, explicit TCP
ports, timeout and an existing `network.tcp-connect` or
`network.service-discovery` capability. This initial matrix covers Nmap TCP
connect and light service discovery only.

`RawNmapAdapter` delegates semantic validation and original XML normalization to
the existing Nmap adapter. It substitutes only the validated original token tuple
for the canonical invocation. Authorization, invocation digests, evidence
provenance and inherited normalization therefore bind the same actual native argv;
normalization does not attribute original bytes to a reformatted command.

Required native switches are `--unprivileged -n -Pn -sT`, explicit `-p` ports,
`--host-timeout Ns`, `-oX -` and one canonical literal IP. IPv6 requires `-6`;
service discovery requires both `-sV` and `--version-light`. Unknown or duplicate
flags, DNS/CIDR expansion, scripts, credentials, shell commands, caller environment
and output paths are rejected. Selection and invocation preparation confer no
execution permission and do not launch the executable.

See the [raw CLI guide](https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/RAW_CLI.md)
for operator grammar, confirmation, output and acceptance boundaries.

::: fuzzy1337.raw_cli
