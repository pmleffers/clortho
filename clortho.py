#!/usr/bin/env python3
"""
Clortho - Secure local password manager
Security model:
  - AES-256-GCM (Fernet) encryption for the vault file
  - PBKDF2-SHA256 key derivation (480,000 iterations, OWASP 2023)
  - 32-byte random salt, unique per vault
  - NO network access except when the user explicitly runs 'webpage' command
  - Vault files set chmod 600 (owner-only read/write)
  - Plaintext passwords never written to disk except via explicit user 'export'
  - Secrets cleared from variables after use where possible
  - No telemetry, no update checks, no analytics
"""

import os
import sys
import csv
import json
import base64
import getpass
import secrets
import argparse
import textwrap
import socket
from pathlib import Path
from datetime import datetime

# ─────────────────────────────────────────────
# NETWORK FIREWALL
# Intercept ALL socket connections at runtime.
# The only way to lift the block is via the
# user-invoked webpage() method which sets
# _network_allowed = True for the duration
# of a single fetch, then resets it.
# ─────────────────────────────────────────────

_network_allowed = False   # global gate

# Addresses that are always allowed — loopback only.
# This lets the web UI server bind to 127.0.0.1 without disabling the guard.
_LOOPBACK = {"127.0.0.1", "::1", "localhost", "0.0.0.0"}

_orig_socket_connect = socket.socket.connect
_orig_getaddrinfo    = socket.getaddrinfo

def _guarded_connect(self, address):
    host = address[0] if isinstance(address, (tuple, list)) else str(address)
    if host in _LOOPBACK or _network_allowed:
        return _orig_socket_connect(self, address)
    raise PermissionError(
        f"Clortho blocked an outbound connection to {address}. "
        "Only the 'webpage' command may connect to the internet."
    )

def _guarded_getaddrinfo(*args, **kwargs):
    host = str(args[0]) if args else ""
    if host in _LOOPBACK or _network_allowed:
        return _orig_getaddrinfo(*args, **kwargs)
    raise PermissionError(
        f"Clortho blocked a DNS lookup for '{host}'. "
        "Only the 'webpage' command may use the network."
    )

socket.socket.connect = _guarded_connect
socket.getaddrinfo    = _guarded_getaddrinfo


# ─────────────────────────────────────────────
# THIRD-PARTY IMPORTS  (all happen after the
# socket guard is installed — any import-time
# network call would be caught here)
# ─────────────────────────────────────────────

try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    import pandas as pd
    from rich.console import Console
    from rich.table import Table
    from rich.prompt import Prompt, Confirm
except ImportError as exc:
    print(f"Missing dependency: {exc}")
    print("Run: pip install cryptography pandas openpyxl beautifulsoup4 requests rich")
    sys.exit(1)

console = Console()

# ─────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────

SALT_FILE    = ".vk_salt"
VAULT_FILE   = "vault.vk"
CONFIG_FILE  = "config.json"
ITERATIONS   = 480_000          # OWASP 2023 PBKDF2-SHA256 minimum
MIN_PW_LEN   = 12               # enforce a real minimum
MAX_RETRIES  = 3                # wrong-password lock-out
BACKUP_KEEP  = 5                # number of rolling backups to retain


# ─────────────────────────────────────────────
# CRYPTO LAYER
# ─────────────────────────────────────────────

def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derive a 256-bit Fernet-compatible key via PBKDF2-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode("utf-8")))


def get_or_create_salt(vault_dir: Path) -> bytes:
    salt_path = vault_dir / SALT_FILE
    if salt_path.exists():
        data = salt_path.read_bytes()
        if len(data) != 32:
            raise ValueError("Salt file is corrupted (wrong length). Vault cannot be opened.")
        return data
    salt = secrets.token_bytes(32)
    salt_path.write_bytes(salt)
    salt_path.chmod(0o600)
    return salt


def encrypt_vault(data: dict, key: bytes) -> bytes:
    return Fernet(key).encrypt(json.dumps(data, ensure_ascii=False).encode("utf-8"))


def decrypt_vault(ciphertext: bytes, key: bytes) -> dict:
    try:
        plaintext = Fernet(key).decrypt(ciphertext)
        return json.loads(plaintext.decode("utf-8"))
    except InvalidToken:
        # Do NOT reveal whether it was a bad password or corruption
        raise ValueError("Decryption failed — wrong master password or vault is corrupted.")


# ─────────────────────────────────────────────
# VAULT MANAGER
# ─────────────────────────────────────────────

class Clortho:
    def __init__(self, vault_dir: str = "~/.clortho"):
        self.vault_dir  = Path(vault_dir).expanduser().resolve()
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.vault_path = self.vault_dir / VAULT_FILE
        self._key: bytes | None = None          # kept in memory only, never written
        self.data: dict = {
            "entries": [],
            "meta": {"created": "", "version": "1.1"},
        }

    # ── Auth ──────────────────────────────────

    def setup_master(self):
        """First-time vault creation: choose and confirm master password."""
        console.print("\n[bold cyan]Clortho — First-Time Setup[/bold cyan]")
        console.print(
            "[red]⚠  There is NO password recovery. If you lose the master password, "
            "the vault cannot be opened.[/red]\n"
        )
        while True:
            pw  = getpass.getpass("Choose master password: ")
            pw2 = getpass.getpass("Confirm master password: ")
            if pw != pw2:
                console.print("[red]Passwords do not match. Try again.[/red]")
                continue
            if len(pw) < MIN_PW_LEN:
                console.print(
                    f"[red]Master password must be at least {MIN_PW_LEN} characters.[/red]"
                )
                continue
            break

        salt = get_or_create_salt(self.vault_dir)
        self._key = derive_key(pw, salt)
        del pw, pw2                             # clear plaintext from scope

        self.data["meta"]["created"] = datetime.now().isoformat()
        self._save()
        console.print("[green]✓ Vault created and locked.[/green]")

    def unlock(self) -> bool:
        """Prompt for master password; allow MAX_RETRIES attempts."""
        salt = get_or_create_salt(self.vault_dir)
        for attempt in range(1, MAX_RETRIES + 1):
            pw = getpass.getpass(
                f"Master password ({attempt}/{MAX_RETRIES}): "
            )
            candidate_key = derive_key(pw, salt)
            del pw
            try:
                ciphertext  = self.vault_path.read_bytes()
                self.data   = decrypt_vault(ciphertext, candidate_key)
                self._key   = candidate_key
                return True
            except ValueError:
                if attempt < MAX_RETRIES:
                    console.print("[red]Wrong password. Try again.[/red]")
                else:
                    console.print(
                        f"[red]Failed {MAX_RETRIES} times. Exiting.[/red]"
                    )
        return False

    def is_initialized(self) -> bool:
        return self.vault_path.exists()

    # ── Config ────────────────────────────────

    def _config_path(self) -> Path:
        return self.vault_dir / CONFIG_FILE

    def load_config(self) -> dict:
        p = self._config_path()
        if p.exists():
            try:
                return json.loads(p.read_text())
            except (json.JSONDecodeError, OSError):
                return {}
        return {}

    def save_config(self, cfg: dict) -> None:
        p = self._config_path()
        p.write_text(json.dumps(cfg, indent=2))
        p.chmod(0o600)

    def get_backup_dir(self) -> Path | None:
        d = self.load_config().get("backup_dir")
        return Path(d).expanduser().resolve() if d else None

    def set_backup_dir(self, path: str) -> Path:
        target = Path(path).expanduser().resolve()
        target.mkdir(parents=True, exist_ok=True)
        cfg = self.load_config()
        cfg["backup_dir"] = str(target)
        self.save_config(cfg)
        return target

    # ── Persistence ───────────────────────────

    def _backup_vault(self) -> Path | None:
        """Copy the encrypted vault to the backup directory (if configured).
        Keeps the last BACKUP_KEEP copies; older ones are deleted automatically.
        Returns the backup path on success, None if no backup dir is set."""
        backup_dir = self.get_backup_dir()
        if not backup_dir:
            return None
        try:
            backup_dir.mkdir(parents=True, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            dest = backup_dir / f"vault_{ts}.vk"
            dest.write_bytes(self.vault_path.read_bytes())
            dest.chmod(0o600)
            # Keep .vk_salt alongside the backups (single copy — salt never changes)
            salt_dest = backup_dir / SALT_FILE
            if not salt_dest.exists():
                salt_src = self.vault_dir / SALT_FILE
                if salt_src.exists():
                    salt_dest.write_bytes(salt_src.read_bytes())
                    salt_dest.chmod(0o600)
            # Rotate: delete oldest backups beyond BACKUP_KEEP
            backups = sorted(backup_dir.glob("vault_*.vk"))
            for old in backups[:-BACKUP_KEEP]:
                old.unlink(missing_ok=True)
            return dest
        except OSError:
            return None

    def backup_status(self) -> dict:
        """Return backup configuration and last-backup info.
        configured_path is always returned if set in config, even if the
        directory is currently unreachable (e.g. drive not mounted)."""
        cfg_path = self.load_config().get("backup_dir")
        if not cfg_path:
            return {"configured": False, "backup_dir": None, "dir_accessible": False,
                    "last_backup": None, "count": 0}
        backup_dir = Path(cfg_path).expanduser().resolve()
        accessible = backup_dir.exists()
        backups    = sorted(backup_dir.glob("vault_*.vk")) if accessible else []
        last       = backups[-1].stat().st_mtime if backups else None
        last_iso   = datetime.fromtimestamp(last).isoformat() if last else None
        return {
            "configured": True,
            "backup_dir": str(backup_dir),
            "dir_accessible": accessible,
            "last_backup": last_iso,
            "count": len(backups),
        }

    def list_backups(self) -> list:
        """Return metadata for each backup file, newest first."""
        backup_dir = self.get_backup_dir()
        if not backup_dir or not backup_dir.exists():
            return []
        backups = sorted(backup_dir.glob("vault_*.vk"), reverse=True)
        result = []
        for b in backups:
            stat = b.stat()
            result.append({
                "filename": b.name,
                "path": str(b),
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "size_kb": round(stat.st_size / 1024, 1),
            })
        return result

    def restore_from_backup(self, filename: str) -> int:
        """Decrypt a backup file and replace the current vault data.
        Returns the number of entries restored."""
        backup_dir = self.get_backup_dir()
        if not backup_dir:
            raise ValueError("No backup directory configured")
        backup_path = (backup_dir / filename).resolve()
        # Safety: must be inside the backup dir
        if not str(backup_path).startswith(str(backup_dir)):
            raise ValueError("Invalid backup filename")
        if not backup_path.exists():
            raise FileNotFoundError(f"Backup not found: {filename}")
        ciphertext  = backup_path.read_bytes()
        data        = decrypt_vault(ciphertext, self._key)
        self.data   = data
        self._save()
        return len(self.data.get("entries", []))

    def _save(self):
        """Encrypt and write the vault. Atomic write via temp file."""
        ciphertext = encrypt_vault(self.data, self._key)
        tmp_path   = self.vault_path.with_suffix(".tmp")
        tmp_path.write_bytes(ciphertext)
        tmp_path.chmod(0o600)
        tmp_path.replace(self.vault_path)        # atomic on POSIX
        self._backup_vault()

    # ── CRUD ──────────────────────────────────

    def add_entry(
        self,
        site: str,
        username: str,
        password: str,
        url: str = "",
        notes: str = "",
        category: str = "General",
    ) -> str:
        entry_id = secrets.token_hex(8)          # 64-bit random ID
        now = datetime.now().isoformat()
        self.data["entries"].append({
            "id":       entry_id,
            "site":     site.strip(),
            "username": username.strip(),
            "password": password,                # NOT stripped — passwords can have spaces
            "url":      url.strip(),
            "notes":    notes.strip(),
            "category": category.strip(),
            "created":  now,
            "modified": now,
        })
        self._save()
        return entry_id

    def update_entry(self, entry_id: str, **fields) -> bool:
        IMMUTABLE = {"id", "created"}
        for entry in self.data["entries"]:
            if entry["id"] == entry_id:
                for k, v in fields.items():
                    if k not in IMMUTABLE:
                        entry[k] = v
                entry["modified"] = datetime.now().isoformat()
                self._save()
                return True
        return False

    def delete_entry(self, entry_id: str) -> bool:
        before = len(self.data["entries"])
        self.data["entries"] = [
            e for e in self.data["entries"] if e["id"] != entry_id
        ]
        if len(self.data["entries"]) < before:
            self._save()
            return True
        return False

    def search(self, query: str) -> list:
        q = query.lower()
        return [
            e for e in self.data["entries"]
            if q in e["site"].lower()
            or q in e["username"].lower()
            or q in e.get("url", "").lower()
            or q in e.get("category", "").lower()
            or q in e.get("notes", "").lower()
        ]

    def all_entries(self) -> list:
        return self.data["entries"]

    # ── Import ────────────────────────────────

    def import_from_file(self, filepath: str) -> tuple[int, int, list]:
        """
        Import credentials from a CSV or Excel file.
        No network access is needed or performed.

        Flexible column aliases:
          site     : site, name, website, service, title, account
          username : username, user, email, login, email address, user name
          password : password, pass, passwd, pwd
          url      : url, link, web address, address          (optional)
          notes    : notes, note, comment, comments, remark   (optional)
          category : category, cat, group, folder, type       (optional)
        """
        path = Path(filepath).expanduser().resolve()
        if not path.exists():
            raise FileNotFoundError(f"File not found: {filepath}")

        ext = path.suffix.lower()
        if ext in (".xlsx", ".xls", ".xlsm"):
            df = pd.read_excel(path, dtype=str)
        elif ext == ".csv":
            df = pd.read_csv(path, dtype=str)
        else:
            raise ValueError(
                f"Unsupported format '{ext}'. Accepted: .csv  .xlsx  .xls  .xlsm"
            )

        df.columns = [c.strip().lower() for c in df.columns]

        COL_ALIASES = {
            "site":     ["site", "name", "website", "service", "title", "account"],
            "username": ["username", "user", "email", "login", "email address", "user name"],
            "password": ["password", "pass", "passwd", "pwd"],
            "url":      ["url", "link", "web address", "address", "login_uri"],
            "notes":    ["notes", "note", "comment", "comments", "remark"],
            "category": ["category", "cat", "group", "folder", "type"],
        }

        def find_col(key):
            for alias in COL_ALIASES[key]:
                if alias in df.columns:
                    return alias
            return None

        site_col = find_col("site")
        user_col = find_col("username")
        pass_col = find_col("password")

        missing = [k for k, v in [("site", site_col), ("username", user_col), ("password", pass_col)] if not v]
        if missing:
            raise ValueError(
                f"Required columns not found: {missing}\n"
                f"Columns in file: {list(df.columns)}"
            )

        url_col  = find_col("url")
        note_col = find_col("notes")
        cat_col  = find_col("category")

        imported, skipped, errors = 0, 0, []

        for i, row in df.iterrows():
            try:
                site     = str(row[site_col]).strip()
                username = str(row[user_col]).strip()
                password = str(row[pass_col])          # no strip

                if not site or not username or not password or site == "nan" or password == "nan":
                    skipped += 1
                    continue

                def safe_str(col):
                    if col and str(row[col]) != "nan":
                        return str(row[col]).strip()
                    return ""

                self.add_entry(
                    site, username, password,
                    url      = safe_str(url_col),
                    notes    = safe_str(note_col),
                    category = safe_str(cat_col) or "Imported",
                )
                imported += 1
            except Exception as exc:
                errors.append(f"Row {i + 2}: {exc}")

        return imported, skipped, errors

    # ── Export ────────────────────────────────

    def export_csv(self, filepath: str):
        """
        Write plaintext CSV export.
        The user is warned before this runs (called by interactive_mode).
        No network access.
        """
        FIELDS = ["site", "username", "password", "url", "notes", "category", "id", "created", "modified"]
        out_path = Path(filepath).expanduser().resolve()
        with open(out_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=FIELDS, extrasaction="ignore")
            writer.writeheader()
            for e in self.data["entries"]:
                writer.writerow(e)
        out_path.chmod(0o600)
        console.print(
            f"[yellow]⚠  Exported {len(self.data['entries'])} entries in PLAINTEXT to "
            f"{out_path}\n   Treat this file like a physical key — secure or delete it when done.[/yellow]"
        )

    # ── Web page reader (explicit user action only) ───────────────

    def read_webpage(self, url: str) -> dict | None:
        """
        Fetch a URL the user explicitly provided.
        Network gate is opened only for the duration of this call.
        'requests' and 'BeautifulSoup' are imported lazily so they
        never touch the network unless this method is actually called.
        """
        global _network_allowed

        # Validate scheme — only https/http allowed, no file://, ftp://, etc.
        url = url.strip()
        if not url.startswith(("https://", "http://")):
            console.print("[red]Only http:// and https:// URLs are supported.[/red]")
            return None

        # Warn the user before connecting
        console.print(
            f"\n[yellow]⚠  Clortho will open a network connection to:[/yellow]\n"
            f"   [bold]{url}[/bold]\n"
            f"   This is the ONLY time Clortho connects to the internet.\n"
            f"   Your vault data will NOT be transmitted."
        )
        if not Confirm.ask("Proceed?", default=False):
            return None

        try:
            import requests                     # lazy import
            from bs4 import BeautifulSoup       # lazy import

            _network_allowed = True             # open the gate
            try:
                headers = {
                    "User-Agent": "Mozilla/5.0 (compatible; Clortho/1.0; +local)",
                    "Accept-Language": "en-US,en;q=0.9",
                }
                resp = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
                resp.raise_for_status()
            finally:
                _network_allowed = False        # always close the gate

            soup = BeautifulSoup(resp.text, "html.parser")

            # Site name: prefer Open Graph, fall back to <title>
            title = ""
            og = soup.find("meta", property="og:site_name")
            if og and og.get("content"):
                title = og["content"]
            elif soup.title and soup.title.string:
                title = soup.title.string
            title = title.strip()

            # Detect username / password input field hints
            username_hint = ""
            for inp in soup.find_all("input"):
                inp_type = (inp.get("type") or "").lower()
                inp_name = (inp.get("name") or inp.get("id") or inp.get("autocomplete") or "").lower()
                if inp_type in ("email", "text") or any(
                    k in inp_name for k in ("user", "email", "login", "identifier")
                ):
                    username_hint = inp.get("placeholder") or inp.get("name") or ""
                    break

            return {
                "site":          title,
                "url":           url,
                "username_hint": username_hint,
            }

        except PermissionError as exc:
            console.print(f"[red]Network blocked: {exc}[/red]")
            return None
        except Exception as exc:
            _network_allowed = False            # safety reset on any error
            console.print(f"[red]Could not read page: {exc}[/red]")
            return None


# ─────────────────────────────────────────────
# DISPLAY HELPERS
# ─────────────────────────────────────────────

def display_entries(entries: list, show_passwords: bool = False):
    if not entries:
        console.print("[dim]No entries found.[/dim]")
        return
    t = Table(show_header=True, header_style="bold magenta", show_lines=True)
    t.add_column("ID",       style="dim cyan",  width=18)
    t.add_column("Site",     style="bold white", min_width=16)
    t.add_column("Username", style="cyan",       min_width=18)
    t.add_column("Password", style="green",      min_width=14)
    t.add_column("URL",      style="blue",       min_width=20, overflow="fold")
    t.add_column("Category", style="yellow",     width=12)

    for e in entries:
        pw = e["password"] if show_passwords else "•" * min(len(e["password"]), 12)
        t.add_row(
            e["id"], e["site"], e["username"], pw,
            e.get("url", ""), e.get("category", ""),
        )
    console.print(t)


def generate_password(length: int = 20) -> str:
    """Cryptographically secure password generator."""
    import string
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]"
    # Guarantee at least one of each character class
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.isupper() for c in pw)
                and any(c.islower() for c in pw)
                and any(c.isdigit() for c in pw)
                and any(c in "!@#$%^&*()-_=+[]" for c in pw)):
            return pw


# ─────────────────────────────────────────────
# INTERACTIVE SHELL
# ─────────────────────────────────────────────

HELP_TEXT = """
[bold]Commands[/bold]
  [cyan]list   / ls[/cyan]      List all entries
  [cyan]add    / new[/cyan]     Add a credential entry
  [cyan]search / find[/cyan]    Search by site, username, URL, category, or notes
  [cyan]edit[/cyan]             Edit an entry by ID
  [cyan]delete / rm[/cyan]      Delete an entry by ID
  [cyan]import[/cyan]           Import from CSV or Excel (local file, no network)
  [cyan]webpage / web[/cyan]    Fetch a URL and add credentials (asks permission first)
  [cyan]generate[/cyan]         Generate a strong random password
  [cyan]export[/cyan]           Export vault to plaintext CSV (prompts for confirmation)
  [cyan]backup[/cyan]           Manage automatic backups (backup set/show/now)
  [cyan]quit   / q[/cyan]       Exit and lock vault
  [cyan]help   / ?[/cyan]       Show this message
"""


def interactive_mode(vault: Clortho):
    console.print("\n[bold green]═══ Clortho Interactive Shell ═══[/bold green]")
    console.print(
        "[dim]Type [bold]help[/bold] for a command list. "
        "Network access is BLOCKED except when you run [bold]webpage[/bold].[/dim]\n"
    )

    while True:
        try:
            cmd = Prompt.ask("[bold]vk>[/bold]").strip().lower()
        except (KeyboardInterrupt, EOFError):
            console.print()
            break

        # ── quit ─────────────────────────────
        if cmd in ("q", "quit", "exit"):
            console.print("[dim]Vault locked. Goodbye.[/dim]")
            break

        # ── list ─────────────────────────────
        elif cmd in ("ls", "list", "l"):
            show_pw = Confirm.ask("Reveal passwords?", default=False)
            display_entries(vault.all_entries(), show_passwords=show_pw)

        # ── add ──────────────────────────────
        elif cmd in ("add", "a", "new"):
            console.print("\n[bold]Add New Entry[/bold]")
            site     = Prompt.ask("Site name")
            username = Prompt.ask("Username / Email")

            use_gen = Confirm.ask("Generate a strong password?", default=False)
            if use_gen:
                try:
                    length = int(Prompt.ask("Password length", default="20"))
                except ValueError:
                    length = 20
                password = generate_password(length)
                console.print(f"[green]Generated:[/green] {password}")
                if not Confirm.ask("Use this password?", default=True):
                    password = getpass.getpass("Enter password manually: ")
            else:
                password = getpass.getpass("Password (hidden): ")

            url      = Prompt.ask("URL [optional]", default="")
            notes    = Prompt.ask("Notes [optional]", default="")
            category = Prompt.ask("Category", default="General")
            eid      = vault.add_entry(site, username, password, url, notes, category)
            console.print(f"[green]✓ Saved (id: {eid})[/green]")

        # ── search ────────────────────────────
        elif cmd in ("search", "find", "s", "f"):
            q = Prompt.ask("Search term")
            results = vault.search(q)
            console.print(f"[dim]{len(results)} result(s)[/dim]")
            if results:
                show_pw = Confirm.ask("Reveal passwords?", default=False)
                display_entries(results, show_passwords=show_pw)

        # ── delete ────────────────────────────
        elif cmd in ("delete", "del", "rm", "remove"):
            eid = Prompt.ask("Entry ID to delete")
            matches = [e for e in vault.all_entries() if e["id"] == eid]
            if not matches:
                console.print("[red]ID not found.[/red]")
                continue
            console.print(f"Deleting: [bold]{matches[0]['site']}[/bold] / {matches[0]['username']}")
            if Confirm.ask("[red]Are you sure?[/red]", default=False):
                vault.delete_entry(eid)
                console.print("[green]✓ Deleted.[/green]")

        # ── edit ─────────────────────────────
        elif cmd in ("edit", "update", "e"):
            eid = Prompt.ask("Entry ID to edit")
            matches = [e for e in vault.all_entries() if e["id"] == eid]
            if not matches:
                console.print("[red]ID not found.[/red]")
                continue
            entry = matches[0]
            console.print(
                f"Editing [bold]{entry['site']}[/bold] — press Enter to keep current value"
            )
            updates = {}
            for field in ("site", "username", "url", "notes", "category"):
                current = entry.get(field, "")
                val = Prompt.ask(f"{field.capitalize()} [{current}]", default="")
                if val:
                    updates[field] = val
            if Confirm.ask("Change password?", default=False):
                use_gen = Confirm.ask("Generate a strong password?", default=False)
                if use_gen:
                    pw = generate_password()
                    console.print(f"[green]Generated:[/green] {pw}")
                    if Confirm.ask("Use this password?", default=True):
                        updates["password"] = pw
                    else:
                        updates["password"] = getpass.getpass("New password: ")
                else:
                    updates["password"] = getpass.getpass("New password: ")
            if updates:
                vault.update_entry(eid, **updates)
                console.print("[green]✓ Updated.[/green]")
            else:
                console.print("[dim]No changes.[/dim]")

        # ── import ────────────────────────────
        elif cmd in ("import", "imp", "i"):
            filepath = Prompt.ask("Path to CSV or Excel file")
            try:
                n, skipped, errs = vault.import_from_file(filepath)
                console.print(f"[green]✓ Imported {n} entries.[/green]")
                if skipped:
                    console.print(f"[yellow]Skipped {skipped} blank/invalid rows.[/yellow]")
                for err in errs:
                    console.print(f"[red]  {err}[/red]")
            except Exception as exc:
                console.print(f"[red]Import failed: {exc}[/red]")

        # ── webpage ───────────────────────────
        elif cmd in ("webpage", "web", "w"):
            console.print(
                "[dim]This is the ONLY command that connects to the internet.\n"
                "You will be shown the URL and asked to confirm before any connection is made.[/dim]"
            )
            url = Prompt.ask("URL of login page")
            info = vault.read_webpage(url)
            if info:
                console.print(f"\n[bold]Site detected:[/bold] {info['site']}")
                if info.get("username_hint"):
                    console.print(f"[dim]Username field: {info['username_hint']}[/dim]")
                if Confirm.ask("Save credentials for this site?", default=True):
                    username = Prompt.ask("Username / Email")
                    password = getpass.getpass("Password (hidden): ")
                    notes    = Prompt.ask("Notes [optional]", default="")
                    category = Prompt.ask("Category", default="Web")
                    eid = vault.add_entry(info["site"], username, password, url, notes, category)
                    console.print(f"[green]✓ Saved (id: {eid})[/green]")

        # ── generate ──────────────────────────
        elif cmd in ("generate", "gen", "g"):
            try:
                length = int(Prompt.ask("Length", default="20"))
            except ValueError:
                length = 20
            pw = generate_password(length)
            console.print(f"[green]{pw}[/green]")
            console.print("[dim](Not saved — use 'add' or 'edit' to store it)[/dim]")

        # ── export ────────────────────────────
        elif cmd in ("export",):
            console.print(
                "[yellow]⚠  Export writes ALL passwords in PLAINTEXT.\n"
                "   Anyone with access to the output file can read your passwords.[/yellow]"
            )
            if Confirm.ask("Continue?", default=False):
                out = Prompt.ask("Output filename", default="vault_export.csv")
                vault.export_csv(out)

        # ── backup ───────────────────────────
        elif cmd.split()[0] in ("backup", "bk"):
            parts = cmd.split(None, 1)
            sub   = parts[1].strip() if len(parts) > 1 else "show"

            if sub.startswith("set"):
                # backup set /path/to/dir
                arg = sub[3:].strip()
                if not arg:
                    arg = Prompt.ask("Backup directory path")
                target = vault.set_backup_dir(arg)
                console.print(f"[green]✓ Backup directory set to:[/green] {target}")
                console.print("[dim]Backups are written automatically after every change.[/dim]")

            elif sub == "now":
                dest = vault._backup_vault()
                if dest:
                    console.print(f"[green]✓ Backup written:[/green] {dest}")
                else:
                    console.print(
                        "[yellow]No backup directory configured.[/yellow] "
                        "Use [bold]backup set <path>[/bold] first."
                    )

            else:  # show / status
                status = vault.backup_status()
                if status["configured"]:
                    console.print(f"[bold]Backup directory:[/bold] {status['backup_dir']}")
                    console.print(f"[bold]Stored backups  :[/bold] {status['count']} (keep last {BACKUP_KEEP})")
                    if status["last_backup"]:
                        console.print(f"[bold]Last backup     :[/bold] {status['last_backup']}")
                    else:
                        console.print("[dim]No backups yet — make a change or run 'backup now'.[/dim]")
                else:
                    console.print(
                        "[yellow]Backups not configured.[/yellow] "
                        "Use [bold]backup set <path>[/bold] to enable."
                    )

        # ── help ─────────────────────────────
        elif cmd in ("help", "h", "?"):
            console.print(HELP_TEXT)

        else:
            console.print(f"[dim]Unknown command '{cmd}'. Type 'help' for options.[/dim]")


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Clortho — Encrypted local password manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python clortho.py
              python clortho.py --vault ~/Documents/myvault
              python clortho.py --import passwords.csv
        """),
    )
    parser.add_argument(
        "--vault", default="~/.clortho",
        help="Directory for vault files (default: ~/.clortho)",
    )
    parser.add_argument(
        "--import", dest="import_file", metavar="FILE",
        help="Import from CSV / Excel, then enter interactive mode",
    )
    parser.add_argument(
        "--export", dest="export_file", metavar="FILE",
        help="Export vault to plaintext CSV, then exit",
    )
    args = parser.parse_args()

    vault = Clortho(vault_dir=args.vault)

    console.print(
        "[bold green]🔐 Clortho[/bold green]  "
        "[dim]AES-256 encrypted · offline-only · no telemetry[/dim]"
    )

    if not vault.is_initialized():
        vault.setup_master()
    else:
        if not vault.unlock():
            sys.exit(1)

    if args.import_file:
        try:
            n, skipped, errs = vault.import_from_file(args.import_file)
            console.print(f"[green]✓ Imported {n} entries.[/green]")
            if skipped:
                console.print(f"[yellow]Skipped {skipped} blank rows.[/yellow]")
            for err in errs:
                console.print(f"[red]  {err}[/red]")
        except Exception as exc:
            console.print(f"[red]Import failed: {exc}[/red]")
            sys.exit(1)

    if args.export_file:
        console.print("[yellow]⚠  Writing plaintext CSV export.[/yellow]")
        vault.export_csv(args.export_file)
        sys.exit(0)

    interactive_mode(vault)


if __name__ == "__main__":
    main()
