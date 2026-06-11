#!/bin/bash
# Clortho desktop launcher — generated/installed by install_desktop.sh
# Starts the web server in the background and opens Firefox to the unlock page.

PROJECT_DIR="PLACEHOLDER_PROJECT_DIR"
VAULT_DIR="${HOME}/.clortho"
PORT=7777

notify() {
    command -v notify-send &>/dev/null && \
        notify-send "Clortho" "$1" --icon=clortho --urgency="${2:-normal}"
}

# Warn if vault hasn't been created yet (Flask will also handle this gracefully)
if [ ! -f "${VAULT_DIR}/vault.vk" ]; then
    notify "No vault found at ${VAULT_DIR}. Run 'python3 clortho.py' first." critical
    exit 1
fi

# Start the web server only if not already running on this port
if ! ss -tlnp 2>/dev/null | grep -q ":${PORT} "; then
    python3 "${PROJECT_DIR}/clortho_web.py" \
        --vault "${VAULT_DIR}" \
        --port "${PORT}" \
        --no-browser \
        > /tmp/clortho_server.log 2>&1 &
    echo $! > /tmp/clortho_server.pid

    # Wait up to 6 seconds for the server to bind
    for i in $(seq 1 20); do
        ss -tlnp 2>/dev/null | grep -q ":${PORT} " && break
        sleep 0.3
    done

    if ! ss -tlnp 2>/dev/null | grep -q ":${PORT} "; then
        notify "Server failed to start. Check /tmp/clortho_server.log" critical
        exit 1
    fi
fi

# Open the unlock page — prefer Flatpak Firefox (Bazzite), fall back to system Firefox
if flatpak list 2>/dev/null | grep -q "org.mozilla.firefox"; then
    flatpak run org.mozilla.firefox "http://127.0.0.1:${PORT}/unlock" > /dev/null 2>&1 &
elif command -v firefox &>/dev/null; then
    firefox "http://127.0.0.1:${PORT}/unlock" > /dev/null 2>&1 &
else
    xdg-open "http://127.0.0.1:${PORT}/unlock" > /dev/null 2>&1 &
fi
