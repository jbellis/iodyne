Output demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 1200
Set Height 700
Set Theme "Catppuccin Mocha"
Set TypingSpeed 30ms
Set Framerate 18
Set Padding 10

# Boot diskwatch — let the IO ring warm before recording starts.
Hide
Type "./target/release/diskwatch"
Enter
Sleep 5s
Show

# [1] Overview — KPI tiles, device summary, AGG IO sparkline,
# insights strip, segmented capacity bar.
Sleep 5s

# [2] Devices — table with model / firmware / serial, used %, SMART.
Type "2"
Sleep 4s
Down@200ms 1
Sleep 2s

# [3] Volumes — APFS container tree (macOS) / mdraid arrays (Linux).
Type "3"
Sleep 4s

# [4] Filesystems — mounts with inline usage bars + thresholds.
Type "4"
Sleep 4s
Down@200ms 3
Sleep 2s

# [5] IO — per-device throughput sparkline + p50/p99 latency.
Type "5"
Sleep 5s

# [6] SMART — full attrs if smartctl on PATH; degraded banner otherwise.
Type "6"
Sleep 4s

# [7] Hot Files — FSEvents-backed write watcher.
Type "7"
Sleep 4s

# [8] Insights — plain-English anomaly cards.
Type "8"
Sleep 4s

# Back to overview to land the demo.
Type "1"
Sleep 3s

Type "q"
Sleep 500ms
