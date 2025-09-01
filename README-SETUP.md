# VAPT Tool - Complete Setup Guide

## 🚀 Quick Start (Kali Linux)

### Method 1: Automatic Setup
```bash
chmod +x start-vapt.sh
./start-vapt.sh
```

### Method 2: Manual Setup

1. **Install Node.js** (if not installed):
```bash
sudo apt update && sudo apt install -y nodejs npm
```

2. **Install Backend Dependencies**:
```bash
cd server
npm install
```

3. **Start Backend Server**:
```bash
node index.js
```

4. **Start Frontend** (in new terminal):
```bash
npm run dev
```

## 🔧 Tool Configuration

### Required Kali Tools
Ensure these tools are installed:
```bash
# Network Scanning
sudo apt install nmap

# Web Vulnerability Scanning  
sudo apt install nikto

# SQL Injection Testing
sudo apt install sqlmap

# Directory Enumeration
sudo apt install gobuster

# Advanced Vulnerability Scanning
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Technology Detection
sudo apt install whatweb

# Subdomain Enumeration
sudo apt install amass sublist3r
```

### Wordlists
```bash
sudo apt install wordlists
```

## 🌐 Access URLs

- **Frontend**: http://localhost:5173
- **Backend API**: http://localhost:8080
- **WebSocket**: ws://localhost:8080

## ✨ Features

### Real-Time Scanning
- ✅ Live output streaming via WebSocket
- ✅ Progress tracking
- ✅ Scan management (pause/stop/skip)

### Supported Tools Integration
- ✅ **Nmap** - Network discovery and port scanning
- ✅ **Nikto** - Web vulnerability scanning  
- ✅ **SQLMap** - SQL injection testing
- ✅ **Gobuster** - Directory enumeration
- ✅ **Nuclei** - Advanced vulnerability detection
- ✅ **WhatWeb** - Technology fingerprinting
- ✅ **Amass** - Subdomain enumeration
- ✅ **Sublist3r** - Subdomain discovery

### Dashboard Features
- 📊 Real-time scan monitoring
- 📋 Comprehensive reporting (HTML/PDF)
- 🎯 Asset exclusion management
- 📱 IoT device security testing
- 🤖 Agent installation and management

### Bug Bounty Features
- 🔍 Subdomain takeover detection
- 🎯 CVE auto-matching
- 💉 Payload injection testing
- 📝 Wordlist generation
- 🔄 Burp Suite integration
- 💰 Bounty program validation

## 🐞 Troubleshooting

### Backend Connection Issues
1. Ensure backend server is running on port 8080
2. Check firewall settings
3. Verify Node.js installation

### Tool Not Found Errors
```bash
# Check if tool is installed
which nmap
which nikto
which sqlmap

# Install missing tools
sudo apt install <tool-name>
```

### Permission Issues
```bash
# Run with appropriate permissions
sudo ./start-vapt.sh
```

## 🔒 Security Notes

- Run scans only on authorized targets
- Follow responsible disclosure practices
- Respect rate limits and terms of service
- Use VPN when appropriate for bug bounty hunting

## 📞 Support

If you encounter issues:
1. Check console logs in browser developer tools
2. Verify backend server logs  
3. Ensure all required tools are installed
4. Test with simple targets first (localhost, local network)

---

**Ready to hunt bugs? Launch the tool and start scanning! 🎯**