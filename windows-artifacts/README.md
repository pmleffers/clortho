# Clortho for Windows

Two standalone executables — no Python install needed. Built with PyInstaller
(`--onefile`), tested under Wine on Linux since a real Windows machine wasn't
available at build time; the core crypto and the web server were both
verified end-to-end (vault create/save/load round-trip, and a real HTTP
unlock + add-entry + read-back against the packaged `clortho.exe`). The
interactive CLI's password prompt itself was **not** verified against a real
Windows console — Wine's console emulation doesn't handle piped/automated
input the same way a real terminal does, so that one specific path should be
double-checked on an actual Windows machine before relying on it.

## First-time setup

1. Run `clortho-cli.exe` once, in a real terminal (double-click, or from
   `cmd`/PowerShell). It will prompt you to choose and confirm a master
   password (12+ characters) and create your vault at `%USERPROFILE%\.clortho\`.
   Type `exit` to leave the CLI shell once it's created.
2. Run `clortho.exe` to start the local web UI at `http://127.0.0.1:7777` —
   it opens your browser automatically. Use `--no-browser` to skip that.

Both tools share the same vault. `clortho-cli.exe` also works as a normal
interactive shell after unlocking (add/search/edit/delete/import/generate) —
see the main project `CLAUDE.md` for the full command list.

## Notes specific to this build

- Vault file permissions (`chmod 600` on Linux/Mac) have no real equivalent
  on Windows — `os.chmod` there only affects the read-only attribute. The
  vault's actual protection is its AES-256 encryption, not filesystem
  permissions, so this doesn't weaken the security model, but it's worth
  knowing this platform difference exists.
- `--vault <path>` and `--port <n>` work the same as on Linux.
- Rebuild from source: `windows-artifacts/BUILD.md` in this same directory
  has the exact Wine + PyInstaller recipe used to produce these.
