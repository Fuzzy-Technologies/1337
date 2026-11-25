# External saved SARIF fixture

`external-eslint.sarif` is an unmodified source-data example from Microsoft and
contributors' SARIF tutorials, retained under the upstream CC-BY-4.0 content
license. The original repository, exact commit/blob/SHA-256/size and unchanged
status are recorded in `external-eslint.origin.json`. No endorsement is claimed.

The upstream license text is reproduced in `MICROSOFT_LICENSE.txt` with LF
line endings, no trailing whitespace and no UTF-8 BOM; its wording is unchanged. The upstream README
distinguishes the content license from its MIT code license:
https://github.com/microsoft/sarif-tutorials/tree/819b0f62f47ecde9a8f24dfc387c41926f5edabe .
The content license is https://creativecommons.org/licenses/by/4.0/ .

The handwritten golden projection preserves literal source facts, not canonical
1337 findings, actual tool execution or computed severity/risk. The producer's
`$schema`, help URI and Windows source URI remain inert strings; tests never
fetch them or open the referenced source file.
