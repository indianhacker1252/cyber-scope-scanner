#!/bin/bash

# CyberScope Scanner - Kali Linux Tools Installation Script
# This script installs and configures essential security tools

set -e

echo "🔧 CyberScope Scanner - Kali Linux Setup"
echo "========================================="

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo "❌ This script should not be run as root directly"
   echo "   Run: chmod +x install-kali-tools.sh && ./install-kali-tools.sh"
   exit 1
fi

# Update package lists
echo "📦 Updating package lists..."
sudo apt update

# Essential tools array
declare -a TOOLS=(
    "nmap"
    "nikto" 
    "sqlmap"
    "gobuster"
    "dirb"
    "masscan"
    "hydra"
    "john"
    "hashcat"
    "recon-ng"
    "amass"
    "nuclei"
    "whatweb"
    "wafw00f"
    "curl"
    "wget"
    "git"
)

# Install tools
echo "🛠️  Installing security tools..."
for tool in "${TOOLS[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
        echo "   Installing $tool..."
        sudo apt install -y "$tool" || echo "   ⚠️  Failed to install $tool"
    else
        echo "   ✅ $tool already installed"
    fi
done

# Install additional tools from GitHub
echo "🔧 Installing additional tools..."

# Install subfinder
if ! command -v subfinder &> /dev/null; then
    echo "   Installing subfinder..."
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
fi

# Setup directories
echo "📁 Setting up directories..."
sudo mkdir -p /usr/share/wordlists/custom
sudo mkdir -p /tmp/cyberscan-reports

# Download common wordlists
echo "📝 Downloading wordlists..."
if [ ! -f "/usr/share/wordlists/dirb/common.txt" ]; then
    sudo apt install -y dirb
fi

# Set proper permissions for network tools
echo "🔑 Setting tool permissions..."
sudo setcap cap_net_raw+ep /usr/bin/nmap 2>/dev/null || true
sudo setcap cap_net_raw+ep /usr/bin/masscan 2>/dev/null || true

# Install Node.js if not present
if ! command -v node &> /dev/null; then
    echo "📦 Installing Node.js..."
    curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
    sudo apt install -y nodejs
fi

echo ""
echo "✅ Installation complete!"
echo ""
echo "🚀 Next steps:"
echo "   1. npm install"
echo "   2. npm run dev"
echo "   3. Open http://localhost:8080"
echo ""
echo "📖 Read KALI_DEPLOYMENT_GUIDE.md for detailed instructions"
echo ""
echo "⚠️  Legal Notice: Only use on authorized targets!"