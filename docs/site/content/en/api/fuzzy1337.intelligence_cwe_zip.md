# Internal bounded CWE ZIP owner

Internal framing and raw-DEFLATE helper for the selected CWE composition. Its
empty `__all__` grants no supported ZIP SDK. Exact bytes, a fixed supported ASCII
member basename and the owning XML consumer are implementation inputs; the public
decoder exposes no caller callback, path, stream or configurable archive policy.

Admission checks one exact local/central/EOCD chain before feeding the member.
Extraction version 20, Unix creator host 3, regular file, method 8 and flags zero
are required. Matching names, offsets, sizes and CRC fields bind the sole range;
stubs, gaps, trailers, comments, multiple members/disks, ZIP64, encryption,
descriptors and nonregular types refuse. Independently bounded unique opaque
extra TLVs may differ without supplying alternate paths, sizes or encodings.
No member path is extracted.

Original bytes are bounded to four MiB; actual XML output to 32 MiB. Compressed
input and decoded output chunks are each at most 64 KiB, including empty-input
drains. Every iteration consumes input, produces bounded output or finishes;
there is no unlimited flush. Original/expanded SHA-256, actual size and CRC facts
return only after complete raw-DEFLATE EOF with no unused/trailing member bytes
and exact declared/actual size/CRC agreement.

The Internal XML sink receives bounded chunks before final ZIP completion. A
sink failure propagates; no successful completion facts are returned after any
failure. ZIP success alone does not establish XML validity, a selected DTO,
source custody, publisher authenticity or legal rights. This owner performs no
filesystem/network acquisition or model/evidence publication.

::: fuzzy1337.intelligence_cwe_zip
