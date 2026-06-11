#!/bin/bash
# install_desktop.sh — Installs Clortho as an applications menu entry.
#
# What this does:
#   1. Installs the padlock icon into ~/.local/share/icons/
#   2. Writes a launcher script to ~/.local/bin/clortho
#   3. Writes a .desktop file to ~/.local/share/applications/
#   4. Refreshes the desktop database so the icon appears immediately

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${HOME}/.local/bin"
ICONS_DIR="${HOME}/.local/share/icons/hicolor"
DESKTOP_DIR="${HOME}/.local/share/applications"
LAUNCHER_PATH="${BIN_DIR}/clortho"
DESKTOP_PATH="${DESKTOP_DIR}/clortho.desktop"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}✓${NC}  $1"; }
warn() { echo -e "  ${YELLOW}⚠${NC}  $1"; }
info() { echo -e "  ${CYAN}→${NC}  $1"; }

echo -e "\n${BOLD}Installing Clortho to applications menu...${NC}\n"
echo -e "  Project dir: ${CYAN}${SCRIPT_DIR}${NC}"
echo ""

# ── Create required directories ───────────────────────────────────────
mkdir -p "${BIN_DIR}" \
         "${ICONS_DIR}/scalable/apps" \
         "${ICONS_DIR}/32x32/apps" \
         "${ICONS_DIR}/48x48/apps" \
         "${ICONS_DIR}/96x96/apps" \
         "${ICONS_DIR}/128x128/apps" \
         "${DESKTOP_DIR}"

# ── 1. Install icon ───────────────────────────────────────────────────
info "Installing icon..."
if [ ! -f "${SCRIPT_DIR}/clortho.svg" ]; then
    warn "clortho.svg not found in ${SCRIPT_DIR} — icon will fall back to system theme"
else
    cp "${SCRIPT_DIR}/clortho.svg" "${ICONS_DIR}/scalable/apps/clortho.svg"
    ok "SVG icon installed to ${ICONS_DIR}/scalable/apps/"
fi
for size in 32 48 96 128; do
    png="${SCRIPT_DIR}/clortho_extension/icons/icon${size}.png"
    if [ -f "${png}" ]; then
        cp "${png}" "${ICONS_DIR}/${size}x${size}/apps/clortho.png"
        ok "PNG icon installed at ${size}x${size}"
    fi
done

# ── 2. Write launcher script ──────────────────────────────────────────
info "Writing launcher to ${LAUNCHER_PATH}..."
sed "s|PLACEHOLDER_PROJECT_DIR|${SCRIPT_DIR}|g" \
    "${SCRIPT_DIR}/clortho_desktop_launch.sh" > "${LAUNCHER_PATH}"
chmod +x "${LAUNCHER_PATH}"
ok "Launcher installed"

# ── 3. Write .desktop file ────────────────────────────────────────────
info "Writing desktop entry to ${DESKTOP_PATH}..."
cat > "${DESKTOP_PATH}" << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Clortho
GenericName=Password Manager
Comment=Local encrypted password vault
Exec=${LAUNCHER_PATH}
Icon=clortho
Terminal=false
Categories=Utility;Security;
Keywords=password;vault;security;encrypt;login;
StartupNotify=true
EOF
chmod 644 "${DESKTOP_PATH}"
ok "Desktop entry written"

# ── 4. Refresh desktop databases ──────────────────────────────────────
info "Refreshing desktop database..."
update-desktop-database "${DESKTOP_DIR}" 2>/dev/null && ok "Desktop database updated" || warn "update-desktop-database not found — skipping"
gtk-update-icon-cache -f "${ICONS_DIR}" 2>/dev/null || true

# ── Summary ───────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}  Done!${NC} Clortho should now appear in your applications menu."
echo ""
echo -e "  If it doesn't appear right away:"
echo -e "    ${CYAN}update-desktop-database ~/.local/share/applications${NC}"
echo -e "  Or log out and back in."
echo ""
echo -e "  To uninstall:"
echo -e "    ${CYAN}rm ${LAUNCHER_PATH} ${DESKTOP_PATH} ${ICONS_DIR}/scalable/apps/clortho.svg${NC}"
echo ""

# Warn if ~/.local/bin isn't on PATH
if [[ ":${PATH}:" != *":${BIN_DIR}:"* ]]; then
    warn "${BIN_DIR} is not in your PATH."
    echo -e "  Add this to your ~/.bashrc or ~/.profile:"
    echo -e "    ${CYAN}export PATH=\"\${HOME}/.local/bin:\${PATH}\"${NC}"
    echo ""
fi
