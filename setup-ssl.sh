#!/usr/bin/env bash
# ============================================================
# setup-ssl.sh — Generate local SSL certificates with mkcert
# Run ONCE per developer machine, and again if CLAVIA_ROOT_DOMAIN changes.
# Supported: macOS, Linux (Debian/Ubuntu/Arch)
# ============================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="$REPO_ROOT/certs"

# ── Colours ───────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()    { echo -e "${GREEN}→${NC} $*"; }
warn()    { echo -e "${YELLOW}⚠${NC}  $*"; }
success() { echo -e "${GREEN}✓${NC} $*"; }

# ── 0. Read CLAVIA_ROOT_DOMAIN ────────────────────────────────
# Read line by line rather than sourced, so .env cannot execute code or
# redefine a variable that changes how other tools behave.
load_env_file() {
  local file="$1" line key
  [[ -f "$file" ]] || return 0
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
    key="${line%%=*}"
    [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
    [[ -n "${!key+x}" ]] && continue
    export "${key}=${line#*=}"
  done < "$file"
}
load_env_file "$REPO_ROOT/.env"

if [[ -z "${CLAVIA_ROOT_DOMAIN:-}" ]]; then
  warn "CLAVIA_ROOT_DOMAIN is not set (checked the environment and .env)."
  warn "Copy .env.example to .env and set it, e.g. CLAVIA_ROOT_DOMAIN=acme.com"
  exit 1
fi

DOMAIN="$CLAVIA_ROOT_DOMAIN"
# The two subdomains CLAUDE.md ("Domain configuration") makes non-negotiable,
# plus the apex — every host this script provisions a cert/hosts entry for.
DOMAINS=("$DOMAIN" "auth.$DOMAIN" "management.$DOMAIN")

# ── 1. Install mkcert ─────────────────────────────────────────
install_mkcert() {
  if command -v mkcert &>/dev/null; then
    success "mkcert already installed ($(mkcert --version))"
    return
  fi

  info "Installing mkcert..."

  if [[ "$OSTYPE" == "darwin"* ]]; then
    if ! command -v brew &>/dev/null; then
      warn "Homebrew not found. Install it first: https://brew.sh"
      exit 1
    fi
    brew install mkcert nss

  elif [[ -f /etc/debian_version ]]; then
    sudo apt-get update -qq
    sudo apt-get install -y libnss3-tools curl
    MKCERT_VER=$(curl -s https://api.github.com/repos/FiloSottile/mkcert/releases/latest \
      | grep tag_name | cut -d'"' -f4)
    if [[ -z "$MKCERT_VER" ]]; then
      warn "Could not determine the latest mkcert release."
      exit 1
    fi
    sudo curl -sLo /usr/local/bin/mkcert \
      "https://github.com/FiloSottile/mkcert/releases/download/${MKCERT_VER}/mkcert-${MKCERT_VER}-linux-amd64"
    sudo chmod +x /usr/local/bin/mkcert

  elif [[ -f /etc/arch-release ]]; then
    sudo pacman -Sy --noconfirm mkcert

  else
    warn "Unrecognised OS. Install mkcert manually: https://github.com/FiloSottile/mkcert"
    exit 1
  fi

  success "mkcert installed"
}

# ── 2. Install the local CA into the system trust store ───────
install_ca() {
  info "Installing the mkcert local CA (sudo password may be required)..."
  mkcert -install
  success "Local CA installed — certificates will be trusted by the browser"
}

# ── 3. Update /etc/hosts ──────────────────────────────────────
# Whether a hostname is already mapped, as a whole token on a live line.
# The word boundary matters: a naive grep for the bare domain would be
# satisfied by management.$DOMAIN, so every hostname would look present as
# soon as any one of them was. Comment lines are skipped, since a mapping
# somebody commented out does not resolve.
host_is_mapped() {
  local domain="${1//./\\.}"
  grep -qE "^[[:space:]]*[^#[:space:]].*[[:space:]]${domain}([[:space:]]|$)" /etc/hosts
}

update_hosts() {
  info "Updating /etc/hosts for $DOMAIN..."

  local missing=()
  local domain
  for domain in "${DOMAINS[@]}"; do
    host_is_mapped "$domain" || missing+=("$domain")
  done

  if [ ${#missing[@]} -eq 0 ]; then
    success "/etc/hosts already maps every hostname"
    return
  fi

  # Appended as a new line rather than edited into an existing one:
  # /etc/hosts allows any number of 127.0.0.1 lines, and rewriting a line
  # somebody may have hand-edited is a worse trade than one extra line.
  info "Adding: ${missing[*]}"
  echo "127.0.0.1  ${missing[*]}" | sudo tee -a /etc/hosts > /dev/null
  success "/etc/hosts updated: ${missing[*]}"
}

# ── 4. Generate the certificates ──────────────────────────────
generate_certs() {
  mkdir -p "$CERTS_DIR"
  info "Generating certificates in $CERTS_DIR ..."

  # Wildcard certificate covering every subdomain of $DOMAIN.
  # Filenames must match the Caddyfile's mkcert_tls snippet.
  mkcert \
    -cert-file "$CERTS_DIR/$DOMAIN.pem" \
    -key-file  "$CERTS_DIR/$DOMAIN-key.pem" \
    "$DOMAIN" \
    "*.$DOMAIN" \
    "localhost" \
    "127.0.0.1" \
    "::1"

  # Copy the root CA so it can be injected into containers later if needed.
  CA_ROOT=$(mkcert -CAROOT)
  cp "$CA_ROOT/rootCA.pem" "$CERTS_DIR/rootCA.pem"

  success "Certificates generated:"
  echo "   • $CERTS_DIR/$DOMAIN.pem       (certificate)"
  echo "   • $CERTS_DIR/$DOMAIN-key.pem   (private key)"
  echo "   • $CERTS_DIR/rootCA.pem        (root CA)"
}

# ── 5. Check .gitignore ───────────────────────────────────────
check_gitignore() {
  local GITIGNORE="$REPO_ROOT/.gitignore"
  if [[ -f "$GITIGNORE" ]] && grep -qE '^\s*certs/\*\.pem\s*$' "$GITIGNORE"; then
    success "Private keys are already ignored by git"
    return
  fi
  printf '\n# SSL — never commit private keys\ncerts/*.pem\n' >> "$GITIGNORE"
  warn "Added certs/*.pem to .gitignore — NEVER commit private keys"
}

# ── Main ──────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Local SSL — mkcert setup for $DOMAIN"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

install_mkcert
install_ca
update_hosts
generate_certs
check_gitignore

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
success "SSL setup complete!"
echo ""
echo "  Available hosts:"
echo "   https://auth.$DOMAIN         → OAuth2 / OIDC, sign-in page"
echo "   https://management.$DOMAIN   → Backoffice + Management API (/api/v1/*)"
echo ""
echo "  Next step: docker compose up -d"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
