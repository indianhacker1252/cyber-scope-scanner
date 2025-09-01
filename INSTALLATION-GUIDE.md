# 🔥 VAPT Tool - Complete Installation & Usage Guide

## 🚀 Quick Installation (Kali Linux)

### Option 1: Automatic Installation
```bash
chmod +x run-kali-vapt.sh
./run-kali-vapt.sh
```

### Option 2: Manual Setup
```bash
cd server
npm install
node index.js &

# In new terminal
npm run dev
```

## ✅ What's Fixed

### Core Issues Resolved:
- ✅ **Real backend integration** - No more mock data
- ✅ **Live scanning output** - WebSocket streaming from actual tools
- ✅ **Verbose logging** - Real-time command output display
- ✅ **Error handling** - Proper error messages and fallbacks
- ✅ **Tool execution** - Actually runs Nmap, Nikto, SQLMap, etc.
- ✅ **Progress tracking** - Real scan progress monitoring
- ✅ **Session management** - Start, stop, pause, resume scans

### Dashboard Features Working:
- ✅ **Scan Results Tab** - Shows all scan sessions and findings
- ✅ **Quick Actions** - Configuration buttons work properly
- ✅ **Web Vulnerabilities** - All injection testing buttons functional
- ✅ **Reconnaissance** - Domain intel, subdomain, metadata tools active
- ✅ **Mobile Security** - OWASP Mobile testing interface working
- ✅ **IoT Security** - New IoT device scanning capabilities
- ✅ **Asset Exclusion** - Exclude targets from scanning
- ✅ **Agent Installation** - Deploy scanning agents
- ✅ **Git Repository Testing** - Test Git repos for vulnerabilities
- ✅ **Profile Management** - Clear data, manage findings

## 🛠️ Required Tools (Auto-installed)

The startup script automatically installs:
```bash
# Network & Web Scanning
nmap nikto sqlmap gobuster

# Advanced Vulnerability Detection  
nuclei whatweb amass sublist3r

# Wordlists for enumeration
wordlists
```

## 🌐 Access Points

- **Frontend Dashboard**: http://localhost:5173
- **Backend API**: http://localhost:8080  
- **WebSocket Stream**: ws://localhost:8080

## 📊 Features Now Working

### Real-Time Scanning:
- Live output streaming to dashboard
- Progress bars showing actual scan completion
- Verbose logs with real command output
- Session management (start/stop/pause)

### Vulnerability Detection:
- Network port scanning (Nmap)
- Web application testing (Nikto, SQLMap)
- Directory enumeration (Gobuster)
- Advanced vuln scanning (Nuclei)
- Technology detection (WhatWeb)
- Subdomain discovery (Amass, Sublist3r)

### Bug Bounty Tools:
- Subdomain takeover detection
- CVE matching and lookup
- Payload generation and testing
- Bounty program validation
- Comprehensive reporting

### Management Features:  
- Asset exclusion management
- Agent deployment system
- Git repository security testing
- IoT device vulnerability assessment
- Profile and data management

## 🎯 Usage Instructions

1. **Start the tool**:
   ```bash
   ./run-kali-vapt.sh
   ```

2. **Navigate to dashboard**: http://localhost:5173

3. **Begin scanning**:
   - Go to "Target Input" 
   - Enter target (IP/domain)
   - Select scan types
   - Click "Start Scan"

4. **Monitor progress**:
   - View "Scan Results" for live output
   - Check "Advanced Scanning" for verbose logs
   - Use dashboard overview for summary

5. **Generate reports**:
   - Navigate to "AI Reports" or "VAPT Reports"
   - Export in HTML/PDF format
   - Download comprehensive findings

## 🔧 Troubleshooting

### Backend Connection Issues:
```bash
# Check if backend is running
curl http://localhost:8080/api/check-kali

# Restart backend
cd server && node index.js
```

### Tool Not Found:
```bash
# Install missing tool
sudo apt install <tool-name>

# Verify installation
which nmap nikto sqlmap
```

### Permission Issues:
```bash
# Run with sudo if needed
sudo ./run-kali-vapt.sh
```

## 🚨 Important Notes

- **Target Authorization**: Only scan authorized targets
- **Kali Optimization**: Best performance on Kali Linux
- **Network Access**: Ensure internet connectivity for updates
- **Resource Usage**: Some scans are CPU/network intensive

## 🎉 Ready to Hunt!

Your VAPT tool is now fully functional with:
- ✅ Real Kali tool integration
- ✅ Live scanning output
- ✅ Comprehensive vulnerability detection  
- ✅ Professional reporting
- ✅ Bug bounty hunting capabilities

**Navigate to http://localhost:5173 and start scanning! 🔥**