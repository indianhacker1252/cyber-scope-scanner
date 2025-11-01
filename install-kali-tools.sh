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
    "metasploit-framework"
    "zaproxy"
    "burpsuite"
    "wireshark"
    "aircrack-ng"
    "hashid"
    "binwalk"
    "foremost"
    "exiftool"
    "steghide"
    "volatility3"
    "sslyze"
    "testssl.sh"
    "dnsrecon"
    "fierce"
    "theHarvester"
    "spiderfoot"
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
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    sudo apt install -y nodejs
fi

# Install Go if not present (needed for some tools)
if ! command -v go &> /dev/null; then
    echo "📦 Installing Go..."
    wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
    rm go1.21.0.linux-amd64.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    export PATH=$PATH:/usr/local/go/bin
fi

# Install Python3 and pip
echo "📦 Installing Python dependencies..."
sudo apt install -y python3 python3-pip python3-venv

# Install subfinder and other Go tools
if command -v go &> /dev/null; then
    echo "🔧 Installing Go-based security tools..."
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
fi

# Install npm packages for backend
echo "📦 Installing backend dependencies..."
cd server 2>/dev/null || mkdir -p server
npm install express cors ws
cd ..

# Install frontend dependencies
echo "📦 Installing frontend dependencies..."
npm install

echo ""
echo "✅ Installation complete!"
echo ""
echo "🚀 Next steps:"
echo "   1. Run ./start-vapt.sh to start the tool"
echo "   2. Open http://localhost:5173 in your browser"
echo "   3. Default login: username 'kali', password 'kali'"
echo ""
echo "📖 Read ADMIN_GUIDE.md and USER_GUIDE.md for detailed instructions"
echo ""
echo "⚠️  Legal Notice: Only use on authorized targets!"
echo "© 2024 Harsh Malik - All Rights Reserved"