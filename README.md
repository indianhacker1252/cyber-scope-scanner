# CyberScope Scanner - Professional Vulnerability Assessment Platform

🔐 **Secure Login Required** | Default: **kali/kali** (Change password after first login!)

## 🚀 Quick Start for Kali Linux

### One-Command Installation & Start
```bash
chmod +x *.sh && ./install-kali-tools.sh && ./start-vapt.sh
```

### If npm install fails (ENOTEMPTY error):
```bash
./fix-npm.sh
```

### Manual Start (Two Terminals Required)

**Terminal 1: Backend (Port 8080)**
```bash
cd server
npm install --legacy-peer-deps
node index.js
```

**Terminal 2: Frontend (Port 5173)**
```bash
npm install --legacy-peer-deps --no-optional
npm run dev
```

Access at: **http://localhost:5173**

---

## 🔐 Authentication & Security

- **5-attempt login lockout** (15-minute cooldown)
- **Default credentials**: `kali` / `kali`
- **Change password**: Click Profile button after login
- **User roles**: Admin and User with different permissions
- **Session management**: Secure logout functionality

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

### 🚨 npm install fails with ENOTEMPTY Error (Most Common!)
**Quick Fix:**
```bash
chmod +x fix-npm.sh && ./fix-npm.sh
```

See `QUICK-FIX.md` for more solutions.

### ❌ Backend Connection Failed
**Solution**: Ensure backend is running on port 8080
```bash
cd server && node index.js
```

### ❌ Login Issues
- Default: `kali` / `kali`
- Locked out? Wait 15 minutes after 5 failed attempts
- Change password via Profile button after login

### ❌ WebSocket Timeout (30s → 10min)
**Solution**: Scans now have 10-minute timeout. Check Settings → API Configuration
- Backend URL: `http://localhost:8080`
- WebSocket URL: `ws://localhost:8080`
- Long scans (Nikto, Amass) can take 5-10 minutes - be patient!

### ❌ Scan Starts But No Output
1. Check **Diagnostics** - all should be PASS
2. Open browser console (F12) for debug logs
3. Verify tool is installed (Kali Linux): `which nmap nikto sqlmap`

### ❌ Permission Denied (Nmap Stealth)
**Solution**: Use "Basic" scan type or run backend with sudo:
```bash
cd server && sudo node index.js
```

### ❌ Port Already in Use
```bash
sudo lsof -ti:8080 | xargs kill -9
sudo lsof -ti:5173 | xargs kill -9
```

---

## 📋 Installation (First Time Setup)

### Automatic Installation (Recommended)
```bash
chmod +x install-kali-tools.sh
./install-kali-tools.sh
```

This installs:
- All required npm packages (with proper flags)
- Security tools (nmap, nikto, sqlmap, etc.)
- Go-based tools (subfinder, httpx, nuclei)
- Python dependencies
- Proper file permissions

### Manual Installation
```bash
# Install frontend dependencies
npm install --legacy-peer-deps --no-optional

# Install backend dependencies
cd server
npm install --legacy-peer-deps
cd ..

# Install Kali tools (Kali Linux only)
sudo apt install nmap nikto sqlmap gobuster nuclei amass sublist3r whatweb \
  metasploit-framework zaproxy burpsuite wireshark
```

---

## 🔐 Security Notice

⚠️ **Legal Warning**: Only scan systems you own or have explicit written permission to test. Unauthorized scanning is illegal.

---

## 📚 Full Documentation

Comprehensive guides available:
- **`QUICK-FIX.md`** - Fast solutions for common npm/installation issues ⚡
- **`README-SETUP.md`** - Detailed setup and troubleshooting guide
- **`ADMIN_GUIDE.md`** - System administration and user management
- **`USER_GUIDE.md`** - Complete usage instructions and best practices
- **`INSTALLATION-GUIDE.md`** - Detailed installation instructions
- **`KALI_DEPLOYMENT_GUIDE.md`** - Production deployment on Kali Linux

### Key Features

✅ **Authentication System**
- Secure login with 5-attempt lockout
- User and admin roles
- Profile management

✅ **Comprehensive Scanning**
- Network scanning (Nmap)
- Web vulnerability scanning (Nikto)
- SQL injection testing (SQLMap)
- Directory enumeration (Gobuster)
- Subdomain discovery (Amass)
- CVE detection (Nuclei)

✅ **Advanced Reporting**
- POC (Proof of Concept) generation
- Request/Response logging
- Vulnerability assessment reports
- Export to multiple formats

✅ **Real-time Monitoring**
- Live scan output
- WebSocket communication
- Progress tracking
- Scan history

---

**Version**: 2.0.0 | **License**: MIT | © 2024 Harsh Malik - All Rights Reserved
