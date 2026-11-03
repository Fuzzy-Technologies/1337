# Internal CWE XML gate and collector

Internal incremental lexical gate and namespace-aware Expat collector for the
pure selected CWE composition. Its empty `__all__` grants no XML SDK or public
callback interface. It retains bounded parser state, counters, recognized source
IDs and selected fields rather than an expanded XML tree. Complete facts require
`Finish` after the ZIP owner has verified all original member bytes.

Before unfinished markup reaches Expat, the gate caps ordinary tokens and
comments/processing instructions at 64 KiB and live reference spellings at ten
bytes across chunks. Text and CDATA stream with delimiter suffixes. Raw lexical
element/attribute names are bounded to 256 UTF-8 bytes before parser input;
namespace-expanded QNames are independently bounded to 256 UTF-8 bytes at
callbacks. Namespace declarations consume attribute counts and byte budgets.

Strict UTF-8 and XML 1.0 with UTF-8 or omitted encoding declaration are required.
DTD declarations refuse in the lexical gate; DTD/entity/external/skipped-entity
handlers provide independent denial. Parameter entities are disabled. XInclude,
external schema fetching and resolver creation are unsupported. Only bounded XML
builtin/numeric references are admitted; parser checks still enforce XML grammar
and character legality. Reparse deferral remains enabled without unsafe fallback.

Exact namespace-qualified direct paths distinguish Weakness, Category, Grouping
and View. Closed root/collection grammar, consumed fields and cross-kind identity
uniqueness include unselected entries. Rich nested fields are not interpreted,
but every applicable node, depth, text, attribute and per-entry counter includes
ignored content, comments and processing instructions across chunk boundaries.

Only completed immutable Internal observations leave the collector. They do not
establish full XSD validation, publisher completeness/authenticity, legal rights,
applicability, source acquisition/custody or a model projection. The public
composition owns final DTO construction and its selected canonical-byte ceiling.

::: fuzzy1337.intelligence_cwe_xml
