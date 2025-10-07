# VAPT Tool - Professional Vulnerability Assessment Platform

## 🚀 Quick Start (Two Terminals Required)

### Terminal 1: Start Backend (Port 8080)
```bash
cd server
npm install
node index.js
```

### Terminal 2: Start Frontend (Port 5173)
```bash
npm run dev
```

Access at: **http://localhost:5173**

---

## ✅ Verify Connection

1. Click **Diagnostics** button in sidebar
2. All checks should show **PASS**:
   - ✅ Backend URL: `http://localhost:8080`
   - ✅ API Reachable
   - ✅ Tools Endpoint
   - ✅ WebSocket URL: `ws://localhost:8080`

---

## 🎯 How to Use Each Button

### Target Input Section

**🔍 Network Scan** - Nmap port scanner
- Enter IP (e.g., `192.168.1.1`) or domain
- Select scan type: Basic, Comprehensive, Stealth, Quick, Intense
- Duration: 30s - 5 minutes

**🌐 Web Scan** - Nikto web vulnerability scanner
- Detects web misconfigurations, outdated software
- Duration: 2-10 minutes

**💉 SQL Injection Test** - SQLMap database security tester
- Requires URL with parameters (e.g., `http://site.com/page?id=1`)
- Duration: 5-15 minutes

**📁 Directory Enum** - Gobuster directory brute-forcer
- Discovers hidden directories and files
- Duration: 2-10 minutes

**🔎 Subdomain Enum** - Amass subdomain discovery
- Enter domain only (e.g., `example.com`)
- Duration: 5-20 minutes

**⚡ Vulnerability Scan** - Nuclei template-based scanner
- Checks for known CVEs and vulnerabilities
- Duration: 2-5 minutes

**🚀 Run Automated Scan** - Sequential execution of all tools
- Comprehensive assessment (all tools run in order)
- Duration: 30-60 minutes

---

## 🔍 View Results

- **Live Output** tab: Real-time command output
- **Detailed Findings** tab: Parsed vulnerabilities with severity
- **Scan Results** tab: Filterable history of all scans

Results persist across browser sessions (saved to localStorage).

---

## 🛠️ Troubleshooting

### ❌ Backend Connection Failed
**Solution**: Ensure backend is running on port 8080
```bash
cd server && node index.js
```

### ❌ WebSocket Timeout
**Solution**: Check Settings → API Configuration
- Backend URL: `http://localhost:8080`
- WebSocket URL: `ws://localhost:8080`

### ❌ Scan Starts But No Output
1. Check **Diagnostics** - all should be PASS
2. Open browser console (F12) for debug logs
3. Verify tool is installed (Kali Linux): `which nmap nikto sqlmap`

### ❌ Permission Denied (Nmap Stealth)
**Solution**: Use "Basic" scan type or run backend with sudo:
```bash
cd server && sudo node index.js
```

---

## 📋 Installation (First Time Setup)

```bash
# Install frontend dependencies
npm install

# Install backend dependencies
cd server
npm install
cd ..

# Install Kali tools (Kali Linux only)
sudo apt install nmap nikto sqlmap gobuster nuclei amass sublist3r whatweb
```

---

## 🔐 Security Notice

⚠️ **Legal Warning**: Only scan systems you own or have explicit written permission to test. Unauthorized scanning is illegal.

---

## 📚 Full Documentation

See project files for detailed guides:
- `INSTALLATION-GUIDE.md` - Detailed setup instructions
- `KALI_DEPLOYMENT_GUIDE.md` - Kali Linux specific deployment
- Check browser console (F12) for debug logs with `[WS]`, `[Nmap]` prefixes

---

**Version**: 1.0.0 | **License**: MIT
