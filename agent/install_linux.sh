#!/bin/bash

# ==========================================
# Sentinel Agent Linux Installer
# install_linux.sh
# Run as root:
# sudo bash install_linux.sh
# ==========================================

set -e

echo "====================================="
echo " Sentinel Agent Linux Installer"
echo "====================================="

# ------------------------------------------
# CONFIG
# ------------------------------------------

SERVICE_NAME="sentinel-agent"

INSTALL_DIR="/opt/sentinel-agent"

PYTHON_VERSION="3"

MAIN_MODULE="main"

REQUIREMENTS_FILE="requirements.txt"

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# LOG_DIR="$INSTALL_DIR/logs"

SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

# ------------------------------------------
# CHECK ROOT
# ------------------------------------------

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

echo "[+] Running as root"

# ------------------------------------------
# CREATE INSTALL DIR
# ------------------------------------------

mkdir -p "$INSTALL_DIR"

echo "[+] Install directory ready"

# ------------------------------------------
# COPY FILES
# ------------------------------------------

echo "[+] Copying project files..."

rsync -av \
    --exclude 'venv' \
    --exclude '__pycache__' \
    --exclude '.git' \
    "$SCRIPT_DIR/" \
    "$INSTALL_DIR/"

echo "[+] Files copied"

# ------------------------------------------
# INSTALL PYTHON IF MISSING
# ------------------------------------------
# ------------------------------------------
# INSTALL PYTHON (VERSION CONTROLLED)
# ------------------------------------------

echo "[+] Checking Python version..."

REQUIRED_MAJOR=3
REQUIRED_MINOR=11

PYTHON_BIN=$(command -v python3 || true)

if [ -n "$PYTHON_BIN" ]; then
    PY_VERSION=$($PYTHON_BIN -c "import sys; print(sys.version_info.major, sys.version_info.minor)")
    PY_MAJOR=$(echo $PY_VERSION | awk '{print $1}')
    PY_MINOR=$(echo $PY_VERSION | awk '{print $2}')

    echo "[+] Found Python $PY_MAJOR.$PY_MINOR"

    if [ "$PY_MAJOR" -gt "$REQUIRED_MAJOR" ] || \
       { [ "$PY_MAJOR" -eq "$REQUIRED_MAJOR" ] && [ "$PY_MINOR" -ge "$REQUIRED_MINOR" ]; }; then
        echo "[+] Python version OK"
    else
        echo "[!] Python version too old"
        PYTHON_BIN=""
    fi
fi


# ------------------------------------------
# INSTALL PYTHON 3.11 IF NEEDED
# ------------------------------------------

if [ -z "$PYTHON_BIN" ]; then

    echo "[+] Installing Python 3.11..."

    if command -v apt &> /dev/null; then
        apt update
        apt install -y software-properties-common

        add-apt-repository -y ppa:deadsnakes/ppa
        apt update

        apt install -y python3.11 python3.11-venv python3.11-dev

        PYTHON_BIN=$(command -v python3.11)

    elif command -v yum &> /dev/null; then
        yum install -y python3.11 python3.11-devel

        PYTHON_BIN=$(command -v python3.11)

    elif command -v dnf &> /dev/null; then
        dnf install -y python3.11 python3.11-devel

        PYTHON_BIN=$(command -v python3.11)

    else
        echo "Unsupported package manager"
        exit 1
    fi
fi

echo "[+] Using Python: $PYTHON_BIN"

# ------------------------------------------
# CREATE VENV
# ------------------------------------------

VENV_DIR="$INSTALL_DIR/.venv"


if [ ! -d "$VENV_DIR" ]; then

    echo "[+] Creating virtual environment..."
    "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

VENV_PYTHON="$VENV_DIR/bin/python"

# ------------------------------------------
# VERIFY VENV PYTHON VERSION
# ------------------------------------------

echo "[+] Checking venv Python version..."

VENV_VERSION=$("$VENV_PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")

echo "[+] Venv Python version: $VENV_VERSION"

if [[ "$VENV_VERSION" != 3.11* ]]; then
    echo "[!] ERROR: Venv is not using Python 3.11"
    echo "[+] Recreating venv..."

    rm -rf "$VENV_DIR"

    "$PYTHON_BIN" -m venv "$VENV_DIR"

    VENV_PYTHON="$VENV_DIR/bin/python"

    echo "[+] Fixed venv Python: $($VENV_PYTHON --version)"
fi

# ------------------------------------------
# UPGRADE PIP
# ------------------------------------------

echo "[+] Upgrading pip..."

"$VENV_PYTHON" -m pip install --upgrade pip

# ------------------------------------------
# INSTALL REQUIREMENTS
# ------------------------------------------

REQ_PATH="$INSTALL_DIR/$REQUIREMENTS_FILE"

if [ -f "$REQ_PATH" ]; then

    echo "[+] Installing dependencies..."

    "$VENV_PYTHON" -m pip install -r "$REQ_PATH"

else

    echo "[!] requirements.txt not found"
fi

# ------------------------------------------
# CREATE LOG DIR
# ------------------------------------------

# mkdir -p "$LOG_DIR"

# ------------------------------------------
# REMOVE OLD SERVICE
# ------------------------------------------

if systemctl list-units --full -all | grep -Fq "$SERVICE_NAME.service"; then

    echo "[+] Removing old service..."

    systemctl stop "$SERVICE_NAME" || true

    systemctl disable "$SERVICE_NAME" || true

    rm -f "$SERVICE_FILE"

    systemctl daemon-reload
fi

# ------------------------------------------
# CREATE SYSTEMD SERVICE
# ------------------------------------------

echo "[+] Creating systemd service..."

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Sentinel Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$VENV_PYTHON -m $MAIN_MODULE
Restart=always
RestartSec=5

# StandardOutput=append:$LOG_DIR/stdout.log
# StandardError=append:$LOG_DIR/stderr.log

[Install]
WantedBy=multi-user.target
EOF

# ------------------------------------------
# ENABLE SERVICE
# ------------------------------------------

echo "[+] Enabling service..."

systemctl daemon-reload

systemctl enable "$SERVICE_NAME"

# ------------------------------------------
# START SERVICE
# ------------------------------------------

echo "[+] Starting service..."

systemctl restart "$SERVICE_NAME"

sleep 3

# ------------------------------------------
# VERIFY
# ------------------------------------------

STATUS=$(systemctl is-active "$SERVICE_NAME")

if [ "$STATUS" != "active" ]; then

    echo "[!] Service failed to start"

    # echo "========== STDERR =========="
    # tail -50 "$LOG_DIR/stderr.log" || true

    systemctl status "$SERVICE_NAME" --no-pager
    journalctl -u "$SERVICE_NAME" -n 50 --no-pager

    exit 1
fi

# ------------------------------------------
# COMPLETE
# ------------------------------------------

echo ""
echo "====================================="
echo " INSTALL COMPLETE"
echo "====================================="

echo ""
echo "Service Status:"
systemctl status "$SERVICE_NAME" --no-pager

echo ""
echo "Install Directory:"
echo "$INSTALL_DIR"

# echo ""
# echo "Logs:"
# echo "$LOG_DIR"

echo ""
echo "Useful Commands:"
echo "-----------------------------------"

echo "systemctl status $SERVICE_NAME"

echo "systemctl restart $SERVICE_NAME"

echo "systemctl stop $SERVICE_NAME"

echo "journalctl -u $SERVICE_NAME -f"

echo ""
echo "====================================="