## Install

These builds are GPG-signed (see below) but **not yet code-signed with
Apple or Microsoft certificates**, so each OS will warn on first launch.

- **macOS** (`.dmg`, universal): drag Saavi to Applications. The build is
  not yet notarized, so on first open macOS says it "could not verify that
  Saavi is free of malware" and offers only *Done* / *Move to Bin*. Click
  *Done*, then *System Settings → Privacy & Security*, scroll to "Saavi was
  blocked", click **Open Anyway**. Or, in Terminal:
  `xattr -d com.apple.quarantine /Applications/Saavi.app`. Either way,
  verify the `.sig` first — that is the check this dialog stands in for.
- **Windows** (`.msi` or `-setup.exe`): SmartScreen will show "Windows
  protected your PC" — click **More info → Run anyway**. The installer
  fetches Microsoft's WebView2 runtime if it is missing (Windows 10/11 ship it).
- **Linux**: `sudo apt install ./saavi_*_amd64.deb`, or
  `chmod +x saavi_*.AppImage && ./saavi_*.AppImage`.

Your keys live in the app's own store (passphrase-locked) — nothing is
uploaded anywhere. Backups are plain text files you save yourself.
