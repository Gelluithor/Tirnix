# Records docs/assets/demo.gif with VHS (https://github.com/charmbracelet/vhs).
# Run docs/demo/record.sh instead of calling this directly.

Output demo.gif

Set Shell "bash"
Set FontFamily "JetBrains Mono"
Set FontSize 14
Set Width 1240
Set Height 720
Set Padding 14
Set Framerate 12
Set Theme "Catppuccin Mocha"
Set WindowBar Colorful
Set TypingSpeed 80ms

Hide
Type "sh ./setup.sh >/dev/null 2>&1; export LANG=C.UTF-8 PATH=$PWD:$PATH; clear" Enter
Sleep 1s
Type "tirnix" Enter
# Collect 30 s of samples so the sustained-condition rules can fire.
Sleep 34s
Show

# Overview
Sleep 4s
# CPU & Memory
Type "2"
Sleep 3s
# Disks
Type "3"
Sleep 3s
# Processes: sort by memory, then filter
Type "4"
Sleep 2.5s
Type "s"
Sleep 1.5s
Type "/"
Sleep 0.5s
Type "burn"
Sleep 2s
Enter
Escape
Sleep 0.5s
# Network
Type "5"
Sleep 2.5s
# Diagnostics: walk through the findings
Type "6"
Sleep 3.5s
Down
Sleep 3s
Down
Sleep 3s
Down
Sleep 2.5s
# History: switch the metric to the 1-minute load average
Type "7"
Sleep 1.5s
Down
Sleep 0.4s
Down
Sleep 0.4s
Down
Sleep 3s
# Settings
Type "8"
Sleep 3s
# Help
Type "?"
Sleep 3s
Type "x"
Sleep 0.5s
Type "q"
Sleep 0.5s
