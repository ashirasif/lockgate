Output docs/demo.gif
Set Shell zsh
Set FontSize 13
Set Width 1400
Set Height 800
Set Padding 12
Set Theme "Catppuccin Mocha"
Set Framerate 24
Set TypingSpeed 30ms

Hide
Type 'alias lockgate="./target/release/lockgate --data-dir docs/demo/.data --mcp-port 0"' Enter
Type "clear" Enter
Sleep 500ms
Show

Type "lockgate --project acme -p 9080" Enter
Sleep 1800ms

# browse the capture
Type "j" Sleep 350ms
Type "j" Sleep 350ms
Type "j" Sleep 700ms

# sitemap — fold the tree
Type "S" Sleep 1200ms
Enter Sleep 900ms

# back to the history, jump to the 401 and send it to the repeater
Type "P" Sleep 400ms
Type "gg" Sleep 250ms
Type "15j" Sleep 900ms
Space Type "s" Sleep 1200ms

# edit with vim keys, replay
Enter Sleep 400ms
Type "gg" Sleep 250ms
Type "o" Sleep 300ms
Type "authorization: Bearer 8f2b1c9d4a" Sleep 400ms
Escape Sleep 300ms
Escape Sleep 300ms
Space Type "r" Sleep 1800ms

# file it as a finding
Space Type "f" Sleep 500ms
Type "Account API accepts a guessable token" Sleep 300ms
Enter Sleep 700ms
Type "T" Sleep 1600ms
