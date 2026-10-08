# fuzzy1337.adapters.nmap

This Experimental optional adapter prepares finite TCP-connect and service-discovery
profiles and normalizes verified raw XML into the existing ToolAdapter SDK envelopes.
`CheckHealth` runs only a bounded local version probe. Target execution remains
behind the separate executor authorization boundary; the adapter never grants it.

`NmapAdapter`, `NmapReportError`, and declared budget constants form the supported
surface. Parsing and health implementation helpers remain Internal. The external
Nmap executable is operator supplied and is not bundled with the base Workbench.

::: fuzzy1337.adapters.nmap
