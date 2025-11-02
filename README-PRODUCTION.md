# CyberScope Scanner - Production Deployment Guide

**Copyright © 2024 Harsh Malik. All Rights Reserved.**

## 🔐 Enterprise-Grade Security Testing Platform

This tool is a professional Vulnerability Assessment and Penetration Testing (VAPT) platform that integrates real Kali Linux tools with AI-powered analysis and secure cloud-based authentication.

### ✨ Key Features

- ✅ **Secure Authentication** - 5-attempt lockout, role-based access (Admin/User)
- ✅ **Real Kali Linux Integration** - 30+ actual security tools, no demo data
- ✅ **Database-Backed Reports** - POC, Request/Response data storage
- ✅ **AI-Powered Analysis** - ChatGPT and Exa.ai integration
- ✅ **Real-time Scanning** - WebSocket streaming of scan output
- ✅ **Row-Level Security** - User data isolation via RLS policies

### ⚠️ CRITICAL: NO DEMO MODE

This application **DOES NOT USE FAKE OR DEMO DATA**. All scans are real-time and connect to actual Kali Linux backend tools. Authentication is required before use.

---

## 🏗️ Architecture

### Frontend (React + TypeScript + Lovable Cloud)
- Real-time WebSocket streaming from backend
- Secure authentication with session management
- User and admin role support
- Comprehensive error logging
- AI-powered recommendations via Exa.ai and ChatGPT
- Database-backed scan reports with POC storage

### Backend (Node.js + Kali Linux)
- Direct integration with Kali Linux security tools
- WebSocket streaming for real-time output
- Session management and timeout handling
- Tool execution with proper privilege handling

### Database (Lovable Cloud/Supabase)
- User authentication and profiles
- Role-based access control (RBAC)
- Scan reports with POC and request/response data
- Login attempt tracking for security
- Row-Level Security (RLS) policies for data isolation

---

## 🚀 Production Deployment Steps

### Prerequisites
1. **Kali Linux Environment** (Required)
   - Latest Kali Linux 2024.x
   - Root/sudo access for tool execution
   - All required tools installed (see tool list below)

2. **Node.js Backend**
   - Node.js v18+ 
   - npm or yarn
   - Port 8080 available

3. **Frontend Hosting**
   - Any static hosting (Netlify, Vercel, etc.)
   - Or serve via Node.js

### Backend Setup

```bash
# 1. Install Kali Linux tools (if not already installed)
chmod +x install-kali-tools.sh
sudo ./install-kali-tools.sh

# 2. Start the backend server
cd server
npm install
sudo node index.js  # Requires sudo for privileged scans
```

The backend will start on `http://localhost:8080`

### Frontend Setup

```bash
# 1. Install dependencies
npm install

# 2. Build for production
npm run build

# 3. Serve the build
npm run preview
# OR deploy the 'dist' folder to your hosting provider
```

### Environment Configuration

Update `src/config/apiConfig.ts` if deploying backend to a different server:

```typescript
export const API_CONFIG = {
  BASE_URL: 'http://YOUR_SERVER:8080',  // Change this
  WS_URL: 'ws://YOUR_SERVER:8080',      // Change this
  // ... rest of config
};
```

---

## 🛠️ Integrated Kali Linux Tools

This platform integrates **30+ real Kali Linux tools**:

### Reconnaissance
- Nmap (Network mapper)
- DNS enumeration (dig)
- WHOIS lookup
- SSL certificate analysis (openssl)
- Amass (subdomain enumeration)
- theHarvester (OSINT)
- Sublist3r
- Recon-ng

### Vulnerability Scanning
- Nikto (Web vulnerability scanner)
- Nuclei (Template-based scanner)
- WhatWeb (Web fingerprinting)
- SSLyze (SSL/TLS scanner)
- Wapiti (Web application scanner)

### Web Application Testing
- SQLMap (SQL injection)
- XSStrike (XSS detection)
- Gobuster (Directory enumeration)
- Dirb
- WPScan (WordPress security)
- Commix (Command injection)
- Wafw00f (WAF detection)

### Network Scanning
- Masscan (Fast port scanner)
- Enum4linux (SMB enumeration)
- Dnsenum
- Fierce (DNS reconnaissance)

### Exploitation
- Metasploit Framework
- Hydra (Brute force)
- John the Ripper (Password cracking)
- Hashcat (Advanced password recovery)
- CrackMapExec (Active Directory)

---

## 🤖 AI Integration (Exa.ai)

The tool uses Exa.ai for:
- Scan strategy optimization
- Vulnerability analysis recommendations
- Exploit technique suggestions
- Real-time threat intelligence

Configure your Exa.ai API key in the ExaInsights panel.

---

## 📊 Logging & Debugging

### Backend Logs
All scan executions are logged with:
- Session IDs
- Timestamps
- Tool outputs
- Error details
- Exit codes

Logs appear in the console where you run `node index.js`

### Frontend Logs
Browser console shows:
- Backend connection status
- WebSocket state
- Tool execution progress
- Error messages with full stack traces

### Error Handling
When a tool fails, the system will show:
1. **What failed**: Tool name and target
2. **Why it failed**: Error message from the tool
3. **How to fix**: Suggested actions (e.g., check privileges, install tool)

---

## 🔍 Verification & Testing

### Test Backend Connection
```bash
curl http://localhost:8080/api/check-kali
# Should return: {"isKali": true} if on Kali Linux
```

### Test Tool Availability
```bash
curl http://localhost:8080/api/tools/installed
# Returns list of all installed tools
```

### Run Test Scan
1. Open the application
2. Go to "Network Scanning"
3. Enter target: `scanme.nmap.org` (legal test target)
4. Start scan
5. Verify real-time output appears

---

## 🚨 Security Considerations

1. **Legal Compliance**
   - Only scan targets you own or have written permission to test
   - Unauthorized scanning is illegal in most jurisdictions
   - This tool is for professional security testing only

2. **Network Security**
   - Backend should be firewalled (only allow localhost access)
   - Use VPN/secure network for production deployments
   - Never expose backend directly to the internet

3. **Authentication** 
   - 5-attempt login lockout implemented (15-minute cooldown)
   - Default credentials: username `kali`, password `kali`
   - Change password after first login via Profile button
   - Role-based access control (Admin/User roles)
   - Session management with automatic expiry
   - Row-Level Security ensures user data isolation

4. **Tool Privileges**
   - Some tools require root/sudo
   - Run backend with minimum required privileges
   - Use capability-based permissions where possible

---

## 🐛 Troubleshooting

### "Backend Offline" Error
**Cause**: Cannot connect to Node.js backend
**Fix**:
```bash
cd server
sudo node index.js
```

### "Not Running on Kali Linux" Warning
**Cause**: Backend detected non-Kali system
**Fix**: This tool MUST run on Kali Linux. Deploy to Kali environment.

### Tool Not Found Errors
**Cause**: Required Kali tool not installed
**Fix**:
```bash
sudo apt update
sudo apt install <tool-name>
```

### Permission Denied Errors
**Cause**: Tool requires elevated privileges
**Fix**: Run backend with sudo:
```bash
sudo node index.js
```

### WebSocket Connection Failed
**Cause**: Firewall or network issue
**Fix**:
- Check if port 8080 is open
- Verify API_CONFIG.BASE_URL points to correct server
- Check browser console for detailed error

---

## 📈 Performance Optimization

1. **Concurrent Scans**
   - Backend supports multiple simultaneous scans
   - Each scan gets a unique session ID
   - WebSocket per session for real-time streaming

2. **Timeouts**
   - Long-running scans have 10-15 minute timeouts
   - Configurable in backend (server/index.js)

3. **Resource Management**
   - Backend cleans up completed sessions
   - Tools are terminated on stop/abort
   - Memory-efficient streaming (no buffering)

---

## 🔮 Future Enhancements

Suggested capabilities to add:

1. **Automated Report Generation**
   - PDF/HTML reports with findings
   - Executive summaries
   - Remediation timelines

2. **Scheduled Scans**
   - Cron-based recurring scans
   - Email notifications
   - Comparison with previous scans

3. **Multi-Target Scanning**
   - Bulk target import (CSV)
   - Network range scanning
   - Asset discovery and tracking

4. **API Integration**
   - REST API for external integration
   - Webhook notifications
   - CI/CD pipeline integration

5. **Collaboration Features**
   - Multi-user support
   - Role-based access control
   - Shared findings and notes

6. **Advanced Reporting**
   - CVSS scoring
   - Risk heat maps
   - Trend analysis over time

7. **Cloud Integration**
   - AWS/Azure/GCP scanning
   - Container security (Docker/K8s)
   - Serverless function testing

8. **Compliance Modules**
   - OWASP Top 10 mapping
   - PCI DSS compliance checks
   - GDPR security assessment

---

## 📞 Support & Contact

**Author**: Harsh Malik  
**Copyright**: © 2024 Harsh Malik. All Rights Reserved.

For professional inquiries, enterprise licensing, or custom development:
- Open an issue on the repository
- Contact through proper channels

---

## 📄 License

This software is proprietary and copyrighted by Harsh Malik. All rights reserved.

Unauthorized copying, distribution, or use is strictly prohibited.

---

## ⚖️ Legal Disclaimer

This tool is provided for **authorized security testing only**. The author assumes no liability for misuse or illegal activities performed with this software. Users are responsible for ensuring they have proper authorization before conducting any security assessments.

**By using this tool, you agree that**:
1. You will only scan systems you own or have explicit written permission to test
2. You understand the legal implications of unauthorized hacking
3. You will comply with all applicable laws and regulations
4. The author is not responsible for any damages caused by use of this tool

---

**Built with security in mind. No compromises. No fake data. Real tools. Real results.**
