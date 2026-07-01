# Demo recording for the README. Regenerate with:
#   cargo build --release && vhs docs/demo.tape
Output docs/demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 1280
Set Height 720
Set Padding 12
Set Theme "Dracula"
Set TypingSpeed 35ms
Set Framerate 12

Hide
Type "export PATH=$PWD/target/release:$PATH PS1='$ '; rm -f /tmp/hnids-demo-*.json; clear" Enter
Show

Type "hnids replay tests/fixtures/portscan.pcap --inventory /tmp/hnids-demo-1.json --min-severity high -q | jq -c '{kind, src_ip, message}'"
Sleep 300ms
Enter
Sleep 3s

Type "hnids replay tests/fixtures/mixed.pcapng --inventory /tmp/hnids-demo-2.json --speed 2 --dashboard"
Sleep 300ms
Enter
Sleep 13s
Type "q"
Sleep 1500ms
