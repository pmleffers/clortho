# AMO listing text — for the Developer Hub "Description" field

Draft only, not auto-submitted. Paste/edit at addons.mozilla.org/developers.

---

**Autofill for your own, fully local password vault. No cloud. No accounts. No tracking.**

Clortho is a self-hosted password manager: your vault is a single AES-256-GCM encrypted file that lives only on your own machine, never on a server you don't control. This extension connects to your local Clortho vault (running at `127.0.0.1:7777`) and offers to autofill your saved credentials whenever it detects a login form.

**Requires the Clortho vault server**, a small local Python app you run yourself. Get it (and setup instructions) at: https://github.com/pmleffers/clortho — the extension does nothing on its own without it.

**How it works**
- Detects login forms on the page and shows a floating autofill prompt
- Fetches the matching credential from your local vault server only when you choose to fill
- Never stores or caches your passwords in the extension itself — nothing persists in browser storage
- Only ever talks to `127.0.0.1:7777` — no other network access, no telemetry, no analytics

**Why local-first**
Your vault is encrypted with PBKDF2-SHA256 (480,000 iterations) and AES-256, and the vault server itself blocks all outbound network connections except localhost. There is no cloud sync, no account, and no password recovery by design — if you lose your master password, the vault stays locked. That's the tradeoff for keeping everything under your own control.

Source code, setup instructions, and the CLI/web UI companion apps: https://github.com/pmleffers/clortho
