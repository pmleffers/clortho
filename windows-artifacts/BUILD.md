# Building the Windows executables

Builds a real Windows PE `.exe` from Linux via Wine + PyInstaller — no actual
Windows machine or VM needed. PyInstaller doesn't cross-compile; it must run
*under* a Windows Python, which is why Wine is in the loop at all.

## One-time setup

```bash
# Wine, via Flatpak (works on immutable/rpm-ostree systems like Bazzite
# without a reboot — a layered rpm-ostree Wine package would need one)
flatpak install -y flathub org.winehq.Wine//stable-25.08

# Gotcha: the Wine flatpak's sandbox only has filesystem access to
# xdg-download/xdg-documents/xdg-desktop/etc — NOT arbitrary paths like /tmp.
# Anything Wine needs to read/write must go through one of those, e.g. ~/Downloads.
mkdir -p ~/Downloads

# Download the official Windows Python installer and run it silently inside
# the Wine prefix (installs to the Wine "user" profile, not system-wide).
curl -sL -o ~/Downloads/python-installer.exe \
  https://www.python.org/ftp/python/3.12.7/python-3.12.7-amd64.exe
flatpak run org.winehq.Wine "C:\\users\\$(whoami)\\Downloads\\python-installer.exe" \
  /quiet InstallAllUsers=0 PrependPath=1 Include_test=0 SimpleInstall=1
```

This lands Windows Python at:
```
~/.var/app/org.winehq.Wine/data/wine/drive_c/users/<you>/AppData/Local/Programs/Python/Python312/python.exe
```
(referred to as `$WINEPY` below, using its `C:\...` form since that's what Wine expects)

```bash
WINEPY='C:\\users\\matt\\AppData\\Local\\Programs\\Python\\Python312\\python.exe'
flatpak run org.winehq.Wine "$WINEPY" -m pip install --quiet \
  pyinstaller cryptography flask pandas openpyxl beautifulsoup4 requests rich
```

## Build

```bash
mkdir -p ~/Downloads/clortho_build
cp clortho.py clortho_web.py ~/Downloads/clortho_build/
cd ~/Downloads/clortho_build

flatpak run org.winehq.Wine "$WINEPY" -m PyInstaller --onefile --name clortho-cli --console clortho.py
flatpak run org.winehq.Wine "$WINEPY" -m PyInstaller --onefile --name clortho     --console clortho_web.py
```

Output: `~/Downloads/clortho_build/dist/{clortho.exe,clortho-cli.exe}` — copy
these into `windows-artifacts/` in the repo.

## Known issue this build already fixes

Windows consoles default to a legacy codepage (cp1252 etc.) that can't
encode the 🔐 emoji in this project's startup banners — without a fix, both
tools crash immediately with `UnicodeEncodeError` on real Windows before
doing anything. Both `clortho.py` and `clortho_web.py` now force UTF-8 on
`sys.stdout`/`sys.stderr` at the top of the file (via `.reconfigure()`,
Python 3.7+) specifically for this. If you ever see this crash again after
an edit, check that fix wasn't accidentally removed.

## Testing without a real Windows machine

Verified via Wine itself: `clortho.exe` boots, serves real HTTP, unlock and
add-entry both round-trip correctly against a real vault. **Not** reliably
testable this way: `clortho-cli.exe`'s interactive `getpass` password prompt
— Wine's console emulation doesn't handle piped/automated stdin the way a
real terminal does (the process spins at ~100% CPU rather than reading
input cleanly). To create a test vault under Wine without hitting this,
either call `clortho.Clortho`/`derive_key`/`_save()` directly from a small
Python script (bypasses the interactive prompt entirely — see the crypto
round-trip test in the main project `CLAUDE.md`), or just accept that the
CLI's actual interactive prompt needs a real Windows console to fully verify.
