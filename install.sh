#!/usr/bin/env bash
# NetCapture Pro - One-shot installer
# Usage: sudo bash install.sh

set -e

echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║     NetCapture Pro — Installer           ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""

if [ "$EUID" -ne 0 ]; then
  echo "  [!] Please run as root: sudo bash install.sh"
  exit 1
fi

echo "  [*] Updating apt..."
apt-get update -qq

echo "  [*] Installing system dependencies..."
apt-get install -y -qq \
  python3 python3-pip \
  libpcap-dev \
  tshark \
  wireshark-common 2>/dev/null || true

echo "  [*] Installing Python packages..."
pip3 install --break-system-packages -q \
  scapy rich manuf cryptography dpkt requests

echo ""
echo "  [✓] Installation complete!"
echo ""
echo "  Run with:"
echo "    sudo python3 netcapture.py"
echo ""
