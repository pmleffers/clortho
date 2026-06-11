#!/bin/bash
# ─────────────────────────────────────────────────────────────────────
# Clortho Launcher — Bazzite Linux (Flatpak Firefox)
#
# What this does:
#   1. Starts the Clortho web server (clortho_web.py)
#   2. Stages the extension xpi into the Firefox profile
#   3. Launches Firefox with about:debugging pre-opened so you can
#      load the temporary extension in one click
#
# Usage:
#   ./clortho_start.sh
#   ./clortho_start.sh --no-browser   (server only, no Firefox)
#   ./clortho_start.sh --vault /path  (custom vault directory)
# ─────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Config — edit these if your paths differ ─────────────────────────
VAULT_DIR="${HOME}/.clortho"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WEB_SERVER="${SCRIPT_DIR}/clortho_web.py"
EXTENSION_XPI="${HOME}/.local/share/clortho/clortho.xpi"
EXTENSION_SRC="${SCRIPT_DIR}/clortho_extension"
FF_PROFILE_BASE="${HOME}/.var/app/org.mozilla.firefox/config/mozilla/firefox"
PORT=7777
OPEN_BROWSER=true

# ── Colours ───────────────────────────────────────────────────────────
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

banner() {
    echo -e "\n${BOLD}${GREEN}🔐 Clortho Launcher${NC}"
    echo -e "${CYAN}────────────────────────────────────────${NC}"
}

ok()   { echo -e "  ${GREEN}✓${NC}  $1"; }
warn() { echo -e "  ${YELLOW}⚠${NC}  $1"; }
err()  { echo -e "  ${RED}✗${NC}  $1"; }
info() { echo -e "  ${CYAN}→${NC}  $1"; }

# ── Parse args ────────────────────────────────────────────────────────
for arg in "$@"; do
    case $arg in
        --no-browser)   OPEN_BROWSER=false ;;
        --vault)        shift; VAULT_DIR="$1" ;;
        --vault=*)      VAULT_DIR="${arg#*=}" ;;
        --port=*)       PORT="${arg#*=}" ;;
        --help|-h)
            echo "Usage: $0 [--no-browser] [--vault DIR] [--port PORT]"
            exit 0
            ;;
    esac
done

banner

# ── Step 1: Check Python and clortho_web.py ───────────────────────
info "Checking dependencies..."

if ! command -v python3 &>/dev/null; then
    err "python3 not found. Install it first."
    exit 1
fi

if [ ! -f "${WEB_SERVER}" ]; then
    err "clortho_web.py not found at: ${WEB_SERVER}"
    err "Make sure this script is in the same folder as clortho_web.py"
    exit 1
fi
ok "Python and clortho_web.py found"

# ── Step 2: Check vault exists ────────────────────────────────────────
if [ ! -f "${VAULT_DIR}/vault.vk" ]; then
    warn "No vault found at ${VAULT_DIR}"
    info "Run 'python3 clortho.py' first to create your vault, then re-run this script."
    exit 1
fi
ok "Vault found at ${VAULT_DIR}"

# ── Step 3: Check port not already in use ─────────────────────────────
if ss -tlnp 2>/dev/null | grep -q ":${PORT} "; then
    warn "Port ${PORT} already in use — Clortho server may already be running"
    info "Skipping server start. If it's stale, run: kill \$(lsof -ti:${PORT})"
    SERVER_RUNNING=true
else
    SERVER_RUNNING=false
fi

# ── Step 4: Start the web server ──────────────────────────────────────
if [ "$SERVER_RUNNING" = false ]; then
    info "Starting Clortho web server on port ${PORT}..."
    python3 "${WEB_SERVER}" \
        --vault "${VAULT_DIR}" \
        --port "${PORT}" \
        --no-browser \
        > /tmp/clortho_server.log 2>&1 &
    SERVER_PID=$!
    echo $SERVER_PID > /tmp/clortho_server.pid

    # Wait for server to be ready
    for i in $(seq 1 20); do
        if ss -tlnp 2>/dev/null | grep -q ":${PORT} "; then
            break
        fi
        sleep 0.3
    done

    if ss -tlnp 2>/dev/null | grep -q ":${PORT} "; then
        ok "Server running on http://127.0.0.1:${PORT} (PID: ${SERVER_PID})"
    else
        err "Server failed to start. Check log: /tmp/clortho_server.log"
        cat /tmp/clortho_server.log
        exit 1
    fi
fi

# ── Step 5: Stage the extension ───────────────────────────────────────
if [ "$OPEN_BROWSER" = true ]; then
    info "Staging Firefox extension..."

    # Rebuild xpi if source files are newer than the xpi
    if [ -d "${EXTENSION_SRC}" ]; then
        if [ ! -f "${EXTENSION_XPI}" ] || \
           [ "${EXTENSION_SRC}/manifest.json" -nt "${EXTENSION_XPI}" ]; then
            info "Rebuilding extension xpi..."
            mkdir -p "$(dirname ${EXTENSION_XPI})"
            cd "${EXTENSION_SRC}"
            zip -q -r "${EXTENSION_XPI}" \
                manifest.json background.js content.js \
                popup.html popup.js icons/
            ok "Extension xpi rebuilt"
            cd - > /dev/null
        fi
    fi

    if [ ! -f "${EXTENSION_XPI}" ]; then
        err "Extension xpi not found at: ${EXTENSION_XPI}"
        err "Run the extension setup steps first."
        OPEN_BROWSER=false
    else
        # Find Firefox profile automatically
        FF_PROFILE=$(grep "^Path=" "${FF_PROFILE_BASE}/profiles.ini" 2>/dev/null | \
                     grep "default-release" | head -1 | cut -d= -f2)

        if [ -z "${FF_PROFILE}" ]; then
            warn "Could not detect Firefox profile. Extension not staged."
        else
            FF_EXT_DIR="${FF_PROFILE_BASE}/${FF_PROFILE}/extensions"
            mkdir -p "${FF_EXT_DIR}"
            cp "${EXTENSION_XPI}" "${FF_EXT_DIR}/clortho@local.xpi"
            ok "Extension staged to Firefox profile: ${FF_PROFILE}"
        fi
    fi
fi

# ── Step 6: Launch Firefox ────────────────────────────────────────────
if [ "$OPEN_BROWSER" = true ]; then
    info "Launching Firefox..."

    # Open about:debugging so user can load the extension in one click
    flatpak run org.mozilla.firefox \
        "about:debugging#/runtime/this-firefox" \
        "http://127.0.0.1:${PORT}/unlock" \
        > /dev/null 2>&1 &

    sleep 2
    ok "Firefox launched"
    echo ""
    echo -e "${BOLD}  Next step:${NC}"
    echo -e "  1. In the ${CYAN}about:debugging${NC} tab that opened:"
    echo -e "     Click ${BOLD}Load Temporary Add-on...${NC}"
    echo -e "     Select: ${CYAN}${FF_EXT_DIR}/clortho@local.xpi${NC}"
    echo -e "  2. Unlock your vault in the ${CYAN}Clortho${NC} tab"
    echo -e "  3. The 🔐 icon will appear in your toolbar"
fi

# ── Step 7: Summary ───────────────────────────────────────────────────
echo ""
echo -e "${CYAN}────────────────────────────────────────${NC}"
echo -e "  ${BOLD}Vault server:${NC}  http://127.0.0.1:${PORT}"
echo -e "  ${BOLD}Vault dir:${NC}     ${VAULT_DIR}"
echo -e "  ${BOLD}Server log:${NC}    /tmp/clortho_server.log"
echo -e "  ${BOLD}Stop server:${NC}   kill \$(cat /tmp/clortho_server.pid)"
echo -e "${CYAN}────────────────────────────────────────${NC}"
echo ""
echo -e "  Press ${BOLD}Ctrl+C${NC} to stop the server and exit."
echo ""

# ── Keep running and show server logs ────────────────────────────────
trap 'echo -e "\n${YELLOW}Stopping Clortho server...${NC}"; \
      kill $(cat /tmp/clortho_server.pid 2>/dev/null) 2>/dev/null; \
      echo -e "${GREEN}Server stopped. Goodbye.${NC}"; exit 0' INT TERM

# Tail the server log so user sees vault unlock prompts etc
tail -f /tmp/clortho_server.log
