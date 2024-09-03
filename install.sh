#!/bin/bash

set -e  # Stop on error

# Define directories and files
BASE_DIR="/opt/threat-overview-dashboard-demo"
DASHBOARD_DIR="$BASE_DIR/dashboard"
DATA_DIR="$DASHBOARD_DIR/data"
ENV_FILE=".env"

# Ensure the script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root"
    exit 1
fi

# Copy files
cd "$DASHBOARD_DIR" || exit

# Setup python environment
dnf -y install python3.11 python3.11-pip openssl
python3.11 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r $DASHBOARD_DIR/requirements.txt
echo "FlaskDashboardSecretKey=$(openssl rand -hex 20)" >> env
cp env "$ENV_FILE"
rm -f env

# Create dashboard user and setup dashboard app service
getent passwd dashboard > /dev/null && userdel --remove dashboard
useradd -r -s /bin/false dashboard

echo "Installation complete."

