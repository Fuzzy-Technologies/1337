# Internal intelligence byte worker

This Internal standard-library worker receives an owning typed acquisition
profile's explicitly selected HTTPS artifact. The shared
`fuzzy1337.intelligence_receiver` process owner clears the environment, fixes
finite byte/deadline limits and owns termination and joining. The worker refuses
redirects, unsupported framing and encoding, and streams only bounded original
bytes with explicit terminal status.

The original default JSON invocation remains supported. An explicit fixed gzip
mode changes the resource preference to `Accept: application/gzip`, retaining
`Accept-Encoding: identity` and original resource bytes. Gzip decoding belongs to
the EPSS profile after receiving the complete pinned source body.

The opt-in internal `zip` mode requests exactly
`Accept: application/zip, application/octet-stream`. After status and framing
checks, it requires one ASCII parsed `Content-Type` value at most 128 bytes,
including retained edge whitespace. Only edge SP/HTAB and ASCII case differences
are allowed for those two media types. Duplicates, parameters, comma joins,
folding, other controls and non-ASCII values fail before any body read. This is
a semantic limit after standard-library header parsing, not a total header
allocation cap. Original ZIP bytes remain compressed. JSON/gzip media behavior
is unchanged, including absent `Content-Type`.

This is a transport prerequisite only: no remote CWE SDK, custody family, CLI
command or genuine HTTPS acceptance is added. See
ADR 0140.

Use the owning `fuzzy1337.intelligence_acquisition` or
`fuzzy1337.intelligence_epss_remote` API. These helpers are not a general scanner,
credential client, publisher-authentication API or independent execution
authorization boundary.

::: fuzzy1337.intelligence_transport
