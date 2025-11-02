# CyberScope Scanner - Complete Setup Guide

## 🚀 Quick Start (Kali Linux)

### Method 1: Full Automatic Installation (Recommended)
```bash
chmod +x *.sh
./install-kali-tools.sh
./start-vapt.sh
```

### Method 2: Quick Start (If already installed)
```bash
chmod +x start-vapt.sh
./start-vapt.sh
```

### Method 3: Manual Setup

1. **Install Node.js** (if not installed):
```bash
sudo apt update && sudo apt install -y nodejs npm
```

2. **Fix npm issues** (if you encounter ENOTEMPTY errors):
```bash
chmod +x fix-npm.sh
./fix-npm.sh
```

3. **Install Backend Dependencies**:
```bash
cd server
npm install --legacy-peer-deps
cd ..
```

4. **Install Frontend Dependencies**:
```bash
npm install --legacy-peer-deps --no-optional
```

5. **Start Backend Server**:
```bash
cd server
node index.js &
cd ..
```

6. **Start Frontend**:
```bash
npm run dev
```

## 🔐 Default Login Credentials
- **Username**: `kali`
- **Password**: `kali`

⚠️ **Important**: Change the default password after first login via the Profile button!

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

### npm install Fails with ENOTEMPTY Error

This is the most common issue on Kali Linux. Run the fix script:
```bash
chmod +x fix-npm.sh
./fix-npm.sh
```

**Manual Fix (if script fails)**:
```bash
# Stop all Node processes
pkill -f node

# Clean everything
sudo rm -rf node_modules package-lock.json server/node_modules server/package-lock.json
npm cache clean --force

# Fix permissions
sudo chown -R $USER:$USER .

# Reinstall with proper flags
npm install --legacy-peer-deps --no-optional
cd server && npm install --legacy-peer-deps && cd ..
```

### npm run dev or npm run build Fails

1. **Clean and reinstall**:
```bash
./fix-npm.sh
```

2. **Check Node.js version** (must be v20.x):
```bash
node --version
```

3. **Ensure backend is running first**:
```bash
cd server && node index.js &
cd .. && npm run dev
```

### Backend Connection Issues
1. Ensure backend server is running on port 8080
2. Check firewall settings:
```bash
sudo ufw allow 8080
sudo ufw allow 5173
```
3. Verify Node.js installation
4. Check if ports are already in use:
```bash
sudo lsof -ti:8080 | xargs kill -9
sudo lsof -ti:5173 | xargs kill -9
```

### Tool Not Found Errors
```bash
# Check if tool is installed
which nmap
which nikto
which sqlmap

# Install missing tools
sudo apt install <tool-name>

# Or run full installation
./install-kali-tools.sh
```

### Permission Issues
```bash
# Fix file permissions
sudo chown -R $USER:$USER /home/kali/cyber-scope-scanner

# Or run with sudo (not recommended)
sudo ./start-vapt.sh
```

### Login Issues (5 Failed Attempts Lockout)

If you're locked out after 5 failed login attempts:
- Wait 15 minutes for automatic unlock
- Or reset via database (admin access required)

### Module Resolution Errors

```bash
# Clear all caches
npm cache clean --force
rm -rf ~/.npm

# Reinstall from scratch
./fix-npm.sh
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