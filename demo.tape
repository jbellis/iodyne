Output demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 1200
Set Height 700
Set Theme "Catppuccin Mocha"
Set TypingSpeed 30ms
Set Framerate 18
Set Padding 10

# Let histories warm before recording the single-screen workflow.
Hide
Type "./target/release/iodyne"
Enter
Sleep 8s
Show

# Move selected-device detail through the overview.
Down@200ms 2
Sleep 4s
Up@200ms 1
Sleep 3s

# Show the persisted display settings.
Type ","
Sleep 3s
Type ","
Sleep 2s

# Demonstrate the live/paused state.
Type "p"
Sleep 2s
Type "p"
Sleep 3s

Type "q"
Sleep 500ms
