# Clortho — Claude Code Project Guide

## What this project is

A fully local, encrypted password manager built in Python. Three components:

| File | Role |
|---|---|
| `clortho.py` | Core encryption engine + interactive CLI shell |
| `clortho_web.py` | Local Flask web UI (127.0.0.1 only) |
| `clortho_extension/` | Firefox browser extension for autofill |
| `clortho_start.sh` | Bazzite Linux launcher script (server + Firefox) |

Everything runs locally. No cloud, no accounts, no telemetry.

---

## Project structure

```
clortho/
├── CLAUDE.md                        ← you are here
├── clortho.py                   ← core: crypto + CLI
├── clortho_web.py               ← web UI: Flask server
├── clortho_start.sh             ← Bazzite launcher script
├── sample_import.csv                ← example import file
├── Clortho_Documentation.ipynb  ← full project docs (Jupyter)
│
└── clortho_extension/           ← Firefox WebExtension (MV2)
    ├── manifest.json
    ├── background.js                ← service worker: vault API relay
    ├── content.js                   ← page injection: form detection + autofill UI
    ├── popup.html                   ← toolbar popup
    ├── popup.js
    └── icons/
        ├── icon48.png
        └── icon96.png
```

Vault data lives at `~/.clortho/` by default:
```
~/.clortho/
    vault.vk      ← AES-256 encrypted vault (Fernet)
    .vk_salt      ← 32-byte random salt for PBKDF2
```

---

## How to run

### Prerequisites
```bash
pip install cryptography pandas openpyxl beautifulsoup4 requests rich flask
```
Python 3.10+ required.

### CLI only
```bash
python clortho.py
python clortho.py --vault ~/myvault
python clortho.py --import passwords.csv
```

### Web UI
```bash
python clortho_web.py
# Opens http://127.0.0.1:7777
python clortho_web.py --port 8888 --no-browser
```

### Bazzite Linux (Flatpak Firefox) — full launch
```bash
chmod +x clortho_start.sh
./clortho_start.sh
./clortho_start.sh --no-browser
./clortho_start.sh --vault ~/myvault --port 8888
```

---

## Security model

- **Cipher**: AES-256-GCM via Python `cryptography` library (Fernet)
- **Key derivation**: PBKDF2-SHA256, 480,000 iterations (OWASP 2023)
- **Salt**: 32-byte random, unique per vault, stored in `.vk_salt`
- **Network firewall**: Runtime socket guard blocks ALL external connections except:
  - `127.0.0.1` / `localhost` (Flask server binding)
  - Explicit user `webpage` command (user-confirmed, single fetch, always re-locked)
- **No plaintext on disk**: vault is always encrypted; export requires double confirmation
- **Atomic writes**: temp file + `os.replace()` — no partial-write corruption
- **File permissions**: `chmod 600` on vault and salt files
- **Wrong password**: 3 attempts then exit — no brute-force
- **Min master password**: 12 characters enforced

### What NOT to change without understanding the implications
- `ITERATIONS = 480_000` in `clortho.py` — lowering this weakens key derivation
- `debug=False` in `clortho_web.py` — must never be True in production
- `host="127.0.0.1"` in `clortho_web.py` — must never be `0.0.0.0`
- The socket guard (`_guarded_connect`, `_guarded_getaddrinfo`) — don't remove or weaken
- CORS policy in `clortho_web.py` — only `moz-extension://` and localhost allowed, never `*`

---

## Architecture notes

### clortho.py
- `Clortho` class owns all vault operations
- `derive_key(password, salt)` → PBKDF2 → Fernet key
- `encrypt_vault(data, key)` / `decrypt_vault(ciphertext, key)` → JSON ↔ encrypted bytes
- Socket guard is installed at **module import time** — before any third-party library loads
- `_network_allowed = False` global gate; only `read_webpage()` sets it True (briefly)
- `generate_password(length)` uses `secrets` module (CSPRNG), not `random`

### clortho_web.py
- Imports `clortho` as `vk` — reuses all crypto and vault logic, no duplication
- Session cookie: `HttpOnly`, `SameSite=Lax`, random 32-byte key per server start
- All routes require `@require_unlock` decorator (checks `session["unlocked"]`)
- Uploaded import files → system temp dir → `os.unlink()` immediately after parse
- CORS: `after_request` hook allows only `moz-extension://` and `localhost` origins

### clortho_extension/
- Manifest V2 (Firefox)
- `background.js`: fetches `/api/entries`, scores matches by hostname, relays credentials
- `content.js`: shadow DOM prompt, `simulateFill()` triggers React/Vue change detection
- `popup.js`: shows matches for current tab, fill button calls background then content
- Passwords are **never stored** in extension — fetched at fill time, nulled immediately
- Extension ID: `clortho@local` (must match xpi filename for sideloading)

### clortho_start.sh
- Bash, Bazzite/Flatpak-specific
- Auto-detects Firefox profile from `profiles.ini`
- Rebuilds xpi if source files are newer than existing xpi
- Stages xpi to profile extensions folder
- Opens Firefox with `about:debugging` + vault unlock page
- Traps `SIGINT`/`SIGTERM` to cleanly kill the Python server

---

## Known issues / limitations

1. **Firefox extension is temporary** on standard Flatpak Firefox — must reload each session via `about:debugging`. `clortho_start.sh` automates this.
2. **Webpage reader** (`webpage` CLI command) fetches URLs via `requests` — only works on pages that don't require JavaScript rendering.
3. **No mobile support** — web UI is responsive but the vault server must run on the same machine.
4. **No multi-user support** — single vault, single master password by design.
5. **`simulate_fill()` may not work** on all SPAs — some frameworks intercept input differently.

---

## Testing

No formal test suite yet. Manual test checklist:

```bash
# Test crypto round-trip
python -c "
import clortho as vk, tempfile
from pathlib import Path
with tempfile.TemporaryDirectory() as d:
    v = vk.Clortho(d)
    salt = vk.get_or_create_salt(Path(d))
    v._key = vk.derive_key('TestPassword123!', salt)
    v.data['meta']['created'] = 'test'
    v._save()
    v2 = vk.Clortho(d)
    v2._key = vk.derive_key('TestPassword123!', salt)
    data = vk.decrypt_vault((Path(d)/'vault.vk').read_bytes(), v2._key)
    assert data['meta']['created'] == 'test'
    print('Crypto round-trip: OK')
"

# Test socket guard
python -c "
import clortho as vk, socket
try:
    socket.getaddrinfo('google.com', 443)
    print('FAIL: external DNS not blocked')
except PermissionError:
    print('Socket guard: OK')
"

# Test CSV import
python -c "
import clortho as vk, tempfile, os
from pathlib import Path
with tempfile.TemporaryDirectory() as d:
    v = vk.Clortho(d)
    salt = vk.get_or_create_salt(Path(d))
    v._key = vk.derive_key('TestPassword123!', salt)
    v.data['meta']['created'] = 'test'
    csv = os.path.join(d, 'test.csv')
    open(csv,'w').write('site,username,password\nGitHub,user@test.com,secret\n')
    n, skipped, errs = v.import_from_file(csv)
    assert n == 1
    print(f'CSV import: OK ({n} entries)')
"
```

---

## Possible improvements (good Claude Code tasks)

- [ ] Add a formal pytest suite covering crypto, import, and API routes
- [ ] Password strength meter in the web UI
- [ ] TOTP/2FA field support
- [ ] Vault backup reminder (warn if vault hasn't been backed up in N days)
- [ ] Search highlighting in the web UI entry list
- [ ] Keyboard shortcut to copy password without revealing it
- [ ] `simulateFill()` improvements for more SPA frameworks
- [ ] Auto-lock web UI after idle timeout
- [ ] Manifest V3 migration for the Firefox extension
- [ ] `.desktop` file auto-installer in `clortho_start.sh`

---

## Dependencies

| Package | Version | Used for | Network? |
|---|---|---|---|
| cryptography | ≥41.0 | PBKDF2 + AES-256 | Never |
| pandas | ≥2.0 | CSV/Excel import parsing | Never |
| openpyxl | ≥3.1 | Excel file reading (via pandas) | Never |
| rich | ≥13.0 | Terminal UI formatting | Never |
| flask | ≥3.0 | Local web server | localhost only |
| requests | ≥2.31 | webpage command HTTP fetch | User-confirmed only |
| beautifulsoup4 | ≥4.12 | webpage command HTML parsing | Never (parser only) |
