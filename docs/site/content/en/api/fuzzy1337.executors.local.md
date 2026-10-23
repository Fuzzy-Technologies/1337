# fuzzy1337.executors.local

The Experimental executor supports explicit Linux descendant ownership through
`Execute(..., own_descendants=True)`. The default request, launch and result
contracts remain unchanged. Verified supervisor cleanup precedes terminal
results and observer/caller-abort propagation; unknown cleanup raises
`LocalExecutionError`. This is resource ownership for trusted approved workers,
without additional scope authority or OS sandboxing.

::: fuzzy1337.executors.local
