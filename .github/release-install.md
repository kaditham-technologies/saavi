## Install

These builds are GPG-signed (see below) but **not yet code-signed with
Apple or Microsoft certificates**, so each OS will warn on first launch.

- **macOS** (`.dmg`, universal): drag Saavi to Applications. On first open
  macOS will say it cannot verify the developer. Go to *System Settings →
  Privacy & Security*, scroll to the notice about Saavi and click
  **Open Anyway** (or, in Terminal: `xattr -dr com.apple.quarantine /Applications/Saavi.app`).
- **Windows** (`.msi` or `-setup.exe`): SmartScreen will show "Windows
  protected your PC" — click **More info → Run anyway**. The installer
  fetches Microsoft's WebView2 runtime if it is missing (Windows 10/11 ship it).
- **Linux**: `sudo apt install ./saavi_*_amd64.deb`, or
  `chmod +x saavi_*.AppImage && ./saavi_*.AppImage`.

Your keys live in the app's own store (passphrase-locked) — nothing is
uploaded anywhere. Backups are plain text files you save yourself.
