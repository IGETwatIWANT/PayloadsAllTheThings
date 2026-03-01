#!/usr/bin/env bash
# ============================================================================
# BAS Engine - One-Shot Installer
# ============================================================================
# Downloads, unpacks, installs dependencies, and configures the AI backend.
# Run: curl -sSL <url>/setup.sh | bash
# Or:  ./setup.sh
# ============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

BAS_VERSION="0.1.0"
OLLAMA_MODEL="llama3.2"
MIN_PYTHON="3.10"

print_banner() {
    echo -e "${RED}"
    echo " ██████╗  █████╗ ███████╗    ███████╗███╗   ██╗ ██████╗ ██╗███╗   ██╗███████╗"
    echo " ██╔══██╗██╔══██╗██╔════╝    ██╔════╝████╗  ██║██╔════╝ ██║████╗  ██║██╔════╝"
    echo " ██████╔╝███████║███████╗    █████╗  ██╔██╗ ██║██║  ███╗██║██╔██╗ ██║█████╗  "
    echo " ██╔══██╗██╔══██║╚════██║    ██╔══╝  ██║╚██╗██║██║   ██║██║██║╚██╗██║██╔══╝  "
    echo " ██████╔╝██║  ██║███████║    ███████╗██║ ╚████║╚██████╔╝██║██║ ╚████║███████╗"
    echo " ╚═════╝ ╚═╝  ╚═╝╚══════╝    ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝╚══════╝"
    echo -e "${NC}"
    echo -e "${BOLD}AI-Driven Breach & Attack Simulation Engine v${BAS_VERSION}${NC}"
    echo -e "${CYAN}Installer${NC}"
    echo ""
}

log_info() { echo -e "${GREEN}[+]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[x]${NC} $1"; }
log_step() { echo -e "\n${CYAN}[*]${NC} ${BOLD}$1${NC}"; }

check_os() {
    log_step "Detecting operating system..."
    OS="$(uname -s)"
    ARCH="$(uname -m)"
    case "$OS" in
        Darwin) PLATFORM="macos" ;;
        Linux)  PLATFORM="linux" ;;
        *)      log_error "Unsupported OS: $OS"; exit 1 ;;
    esac
    log_info "Platform: $PLATFORM ($ARCH)"
}

check_python() {
    log_step "Checking Python installation..."
    if command -v python3 &>/dev/null; then
        PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        log_info "Python $PY_VER found"

        # Version check
        PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
        PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)
        if [ "$PY_MAJOR" -lt 3 ] || ([ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 10 ]); then
            log_error "Python >= $MIN_PYTHON required. Found $PY_VER"
            exit 1
        fi
    else
        log_error "Python 3 not found. Install Python >= $MIN_PYTHON first."
        exit 1
    fi
}

create_venv() {
    log_step "Creating virtual environment..."
    BAS_DIR="${BAS_HOME:-$HOME/.bas}"
    VENV_DIR="$BAS_DIR/venv"

    mkdir -p "$BAS_DIR"

    if [ ! -d "$VENV_DIR" ]; then
        python3 -m venv "$VENV_DIR"
        log_info "Virtual environment created at $VENV_DIR"
    else
        log_info "Virtual environment already exists at $VENV_DIR"
    fi

    source "$VENV_DIR/bin/activate"
    pip install --upgrade pip setuptools wheel -q
}

install_bas() {
    log_step "Installing BAS Engine..."
    BAS_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    # Install BAS and dependencies
    pip install -e "$BAS_SRC[ai]" -q 2>/dev/null || {
        log_warn "Full AI install failed, trying core only..."
        pip install -e "$BAS_SRC" -q
    }
    log_info "BAS Engine installed"
}

setup_ollama() {
    log_step "Setting up Ollama (Local AI Backend)..."

    if command -v ollama &>/dev/null; then
        log_info "Ollama already installed"
    else
        log_info "Installing Ollama..."
        if [ "$PLATFORM" = "macos" ]; then
            if command -v brew &>/dev/null; then
                brew install ollama 2>/dev/null || {
                    log_warn "Brew install failed, trying curl installer..."
                    curl -fsSL https://ollama.ai/install.sh | sh
                }
            else
                curl -fsSL https://ollama.ai/install.sh | sh
            fi
        else
            curl -fsSL https://ollama.ai/install.sh | sh
        fi
    fi

    # Start Ollama if not running
    if ! curl -s http://localhost:11434/api/tags &>/dev/null; then
        log_info "Starting Ollama..."
        ollama serve &>/dev/null &
        sleep 3
    fi

    # Pull the model
    log_info "Pulling AI model: $OLLAMA_MODEL (this may take a few minutes)..."
    ollama pull "$OLLAMA_MODEL" || log_warn "Model pull failed - you can pull it later with: ollama pull $OLLAMA_MODEL"
}

load_payloads() {
    log_step "Loading payload database..."
    BAS_DATA="$BAS_DIR/data"
    mkdir -p "$BAS_DATA"

    BAS_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    REPO_PATH="$(dirname "$BAS_SRC")"

    python3 -c "
import asyncio
from bas.payloads.loader import PayloadLoader

async def load():
    loader = PayloadLoader('$REPO_PATH', '$BAS_DATA/payloads.db')
    db = await loader.load_all()
    stats = await db.get_stats()
    print(f'Loaded {stats[\"total_payloads\"]} payloads from {stats[\"categories\"]} categories')
    await db.close()

asyncio.run(load())
" || log_warn "Payload loading will happen on first scan"
}

create_shell_alias() {
    log_step "Creating shell alias..."
    BAS_BIN="$VENV_DIR/bin/bas"

    # Determine shell config file
    SHELL_RC=""
    if [ -n "${ZSH_VERSION:-}" ] || [ -f "$HOME/.zshrc" ]; then
        SHELL_RC="$HOME/.zshrc"
    elif [ -f "$HOME/.bashrc" ]; then
        SHELL_RC="$HOME/.bashrc"
    elif [ -f "$HOME/.bash_profile" ]; then
        SHELL_RC="$HOME/.bash_profile"
    fi

    if [ -n "$SHELL_RC" ]; then
        if ! grep -q "alias bas=" "$SHELL_RC" 2>/dev/null; then
            echo "" >> "$SHELL_RC"
            echo "# BAS Engine" >> "$SHELL_RC"
            echo "alias bas='$BAS_BIN'" >> "$SHELL_RC"
            log_info "Added 'bas' alias to $SHELL_RC"
        else
            log_info "Alias already exists in $SHELL_RC"
        fi
    fi
}

print_success() {
    echo ""
    echo -e "${GREEN}============================================================================${NC}"
    echo -e "${GREEN}  BAS Engine installed successfully!${NC}"
    echo -e "${GREEN}============================================================================${NC}"
    echo ""
    echo -e "  ${BOLD}Quick Start:${NC}"
    echo -e "    ${CYAN}bas scan https://your-target.com --authorized-by 'Your Name' --dry-run${NC}"
    echo ""
    echo -e "  ${BOLD}Commands:${NC}"
    echo -e "    ${CYAN}bas scan <target>${NC}        - Full BAS assessment"
    echo -e "    ${CYAN}bas recon <target>${NC}       - Quick reconnaissance"
    echo -e "    ${CYAN}bas payloads load${NC}        - Reload payload database"
    echo -e "    ${CYAN}bas payloads search <q>${NC}  - Search payloads"
    echo -e "    ${CYAN}bas models${NC}               - List AI models"
    echo -e "    ${CYAN}bas init${NC}                 - Generate config file"
    echo ""
    echo -e "  ${BOLD}Data Locations:${NC}"
    echo -e "    Config:   ${BAS_DIR:-$HOME/.bas}"
    echo -e "    Logs:     ./bas_logs/"
    echo -e "    Reports:  ./bas_output/"
    echo ""
    echo -e "  ${YELLOW}Remember: Only use against systems you are authorized to test.${NC}"
    echo ""
}

# ─── Main ────────────────────────────────────────────────────────────

main() {
    print_banner
    check_os
    check_python
    create_venv
    install_bas
    setup_ollama
    load_payloads
    create_shell_alias
    print_success
}

main "$@"
