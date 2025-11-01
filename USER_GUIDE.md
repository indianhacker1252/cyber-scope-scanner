# VAPT Tool - User Guide

**Copyright © 2024 Harsh Malik - All Rights Reserved**

## Welcome to the VAPT Tool

This guide will help you get started with the Vulnerability Assessment and Penetration Testing (VAPT) Tool.

---

## Table of Contents
1. [Getting Started](#getting-started)
2. [Dashboard Overview](#dashboard-overview)
3. [Running Scans](#running-scans)
4. [Understanding Results](#understanding-results)
5. [Generating Reports](#generating-reports)
6. [Best Practices](#best-practices)

---

## Getting Started

### Accessing the Tool

1. Open your web browser
2. Navigate to: http://localhost:5173
3. You will see the login screen

### First Time Login

**Default Credentials** (change these immediately):
- Username: `kali`
- Password: `kali`

### Changing Your Password

⚠️ **IMPORTANT**: Change your password on first login!

1. Click the **Profile** icon (top right)
2. Enter your current password
3. Enter a new strong password
4. Click **Save Changes**

**Password Requirements**:
- Minimum 8 characters
- Mix of uppercase and lowercase letters
- Include numbers and special characters
- Example: `MyP@ssw0rd2024!`

### Account Lockout

For security, your account will be locked after **5 failed login attempts**. The lockout lasts for **15 minutes**.

If locked out:
- Wait 15 minutes and try again
- Contact your administrator for immediate unlock

---

## Dashboard Overview

### Main Interface

The dashboard consists of several key areas:

#### 1. **Header Bar** (Top)
- **Tool Name**: VAPT Tool branding
- **Role Badge**: Shows your user role (Admin/User)
- **Icons**:
  - 🔧 Troubleshooting Helper
  - ⚙️ System Diagnostics
  - ⚙️ Settings
  - 👤 Profile
  - 🚪 Logout

#### 2. **Sidebar** (Left)
Quick access to different scanning modules:
- 📊 Dashboard Overview
- 🌐 Reconnaissance
- 🔍 Network Scanning
- 🐛 Web Vulnerabilities
- 💻 Code Analysis
- 🗄️ Database Testing
- 🎯 Exploit Testing
- 🛠️ Advanced Tools
- 🤖 AI Auto-VAPT
- 📱 Mobile Security
- 🏭 IoT Security
- 🔬 Exa Insights
- 🧠 PentestGPT
- 📋 Reports
- 🐙 Git Repository

#### 3. **Main Content Area** (Center)
- Target input field
- Scan controls
- Results display
- Real-time output

#### 4. **Status Indicator** (Bottom Left)
Shows connection status:
- ✅ **Kali Linux Active** - Everything working
- ⚠️ **Backend Offline** - Connection issue

---

## Running Scans

### Basic Scan Workflow

1. **Select Scan Type** from sidebar
2. **Enter Target** information
3. **Configure Options** (if available)
4. **Start Scan**
5. **Monitor Progress**
6. **Review Results**

### Scan Types

#### 1. Reconnaissance 🌐

**Purpose**: Gather information about the target

**Tools Available**:
- **DNS Lookup**: Discover DNS records
- **WHOIS Lookup**: Get domain registration info
- **SSL Certificate Check**: Analyze SSL/TLS configuration
- **Subdomain Enumeration**: Find subdomains
- **Technology Detection**: Identify web technologies

**How to Use**:
```
1. Select "Reconnaissance" from sidebar
2. Choose scan type (e.g., DNS Lookup)
3. Enter domain: example.com
4. Click "Start Reconnaissance"
5. Wait for results
```

#### 2. Network Scanning 🔍

**Purpose**: Discover hosts and open ports

**Tools Available**:
- **Nmap**: Advanced port scanning
- **Masscan**: Fast port scanning
- **Service Detection**: Identify running services

**How to Use**:
```
1. Select "Network Scanning"
2. Choose scan mode:
   - Quick Scan (Top 100 ports)
   - Full Scan (All 65535 ports)
   - Custom Scan (Specific ports)
3. Enter target: 192.168.1.1 or example.com
4. Click "Start Scan"
```

**Example Targets**:
- Single IP: `192.168.1.100`
- IP Range: `192.168.1.1-50`
- Subnet: `192.168.1.0/24`
- Domain: `example.com`

#### 3. Web Vulnerabilities 🐛

**Purpose**: Test web applications for security issues

**Tools Available**:
- **Nikto**: Web server scanner
- **SQLMap**: SQL injection testing
- **Gobuster**: Directory brute-forcing
- **WAF Detection**: Identify web application firewalls

**How to Use**:
```
1. Select "Web Vulnerabilities"
2. Choose scan type
3. Enter URL: https://example.com
4. Configure options (wordlists, etc.)
5. Click "Start Scan"
```

**⚠️ Warning**: SQL injection scans can be invasive. Only test authorized targets!

#### 4. AI Auto-VAPT 🤖

**Purpose**: Automated vulnerability assessment using AI

**Features**:
- Automated multi-stage scanning
- AI-powered vulnerability analysis
- Comprehensive reporting

**How to Use**:
```
1. Select "AI Auto-VAPT"
2. Enter target domain/IP
3. Choose scan depth:
   - Quick: Basic scans
   - Normal: Standard testing
   - Deep: Comprehensive analysis
4. Click "Start Automated VAPT"
5. Monitor progress in real-time
```

**Stages**:
1. 🔍 Reconnaissance (DNS, WHOIS, Subdomains)
2. 🌐 Network Scanning (Port discovery)
3. 🕷️ Web Scanning (Nikto, tech detection)
4. 🔐 Security Testing (WAF detection, SQLMap)
5. 📊 AI Analysis (Vulnerability assessment)

#### 5. Advanced Tools 🛠️

**Purpose**: Specialized penetration testing tools

**Tools Available**:
- **Hydra**: Password brute-forcing
- **John the Ripper**: Password cracking
- **Hashcat**: Advanced hash cracking
- **Metasploit**: Exploitation framework

**⚠️ DANGER**: These are offensive tools. Only use on authorized targets!

**Example - Hydra Password Attack**:
```
1. Select "Advanced Tools" → "Hydra"
2. Enter target: 192.168.1.100
3. Select service: SSH, FTP, HTTP, etc.
4. Upload username list
5. Upload password list
6. Click "Start Attack"
```

---

## Understanding Results

### Reading Scan Output

#### Network Scan Results

```
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    open     http
443/tcp   open     https
3306/tcp  closed   mysql
```

**Interpretation**:
- **Open**: Service is accessible and responding
- **Closed**: Port is reachable but no service listening
- **Filtered**: Firewall is blocking access

#### Vulnerability Results

Each vulnerability includes:

- **Name**: Vulnerability identifier
- **Severity**: Critical / High / Medium / Low / Info
- **Description**: What the vulnerability is
- **Proof of Concept (POC)**: Evidence of the vulnerability
- **Request/Response**: HTTP request and response showing the issue
- **Recommendation**: How to fix it

**Example**:
```
Vulnerability: SQL Injection
Severity: Critical
Location: /login.php?id=1

Proof of Concept:
  Request: GET /login.php?id=1' OR '1'='1
  Response: Access granted to admin panel

Request Data:
  GET /login.php?id=1' OR '1'='1-- HTTP/1.1
  Host: example.com
  User-Agent: sqlmap/1.6

Response Data:
  HTTP/1.1 200 OK
  Content-Type: text/html
  
  <html><body>Welcome, admin!</body></html>

Recommendation:
  - Use parameterized queries
  - Implement input validation
  - Apply principle of least privilege
```

### Severity Levels

- 🔴 **Critical**: Immediate action required
- 🟠 **High**: Address as soon as possible
- 🟡 **Medium**: Important but not urgent
- 🟢 **Low**: Minor issue
- ℹ️ **Info**: Informational finding

---

## Generating Reports

### Creating Reports

1. Navigate to **Reports** section
2. Select date range or scan type
3. Choose format:
   - PDF Report
   - HTML Report
   - JSON Data
   - CSV Export
4. Click **Generate Report**

### Report Contents

Professional reports include:

1. **Executive Summary**
   - Overall risk assessment
   - Critical findings count
   - Remediation priority

2. **Methodology**
   - Tools used
   - Scan parameters
   - Timeline

3. **Findings**
   - Detailed vulnerabilities
   - Proof of Concept
   - Request/Response data
   - Screenshots (where applicable)

4. **Recommendations**
   - Remediation steps
   - Best practices
   - Compliance guidance

5. **Appendix**
   - Full scan outputs
   - Tool versions
   - Raw data

### Exporting Data

```
Reports → Select Scans → Export → Choose Format
```

---

## Best Practices

### Before Scanning

✅ **Always get authorization**
- Written permission from target owner
- Defined scope and boundaries
- Clear timeline and methods

✅ **Understand your target**
- Is it a production system?
- What is the business impact of testing?
- Are there any off-limits systems?

✅ **Plan your approach**
- Start with passive reconnaissance
- Progress to active scanning
- Save aggressive tests for last

### During Scanning

✅ **Monitor scan progress**
- Watch for errors or anomalies
- Check system resources
- Be ready to stop if issues arise

✅ **Respect rate limits**
- Don't overwhelm the target
- Use appropriate scan speeds
- Consider time windows

✅ **Document everything**
- Take screenshots
- Save scan outputs
- Note any unusual findings

### After Scanning

✅ **Verify findings**
- Confirm vulnerabilities are real
- Eliminate false positives
- Test exploitability (if authorized)

✅ **Generate professional reports**
- Clear and concise findings
- Include proof of concept
- Provide remediation guidance

✅ **Communicate responsibly**
- Follow disclosure policies
- Protect sensitive information
- Provide reasonable fix timeline

---

## Common Use Cases

### 1. Internal Network Assessment

**Scenario**: Test internal network security

**Steps**:
```
1. Run Network Scanning on internal IP ranges
2. Identify active hosts and services
3. Run Web Vulnerabilities on web services
4. Check for default credentials
5. Document findings
6. Generate report
```

### 2. Web Application Testing

**Scenario**: Test company website

**Steps**:
```
1. Start with Reconnaissance
   - DNS, WHOIS, subdomains
   - Technology detection
2. Run Nikto scan
3. Directory brute-forcing with Gobuster
4. SQL injection testing with SQLMap
5. Review results and generate report
```

### 3. Password Security Audit

**Scenario**: Test password strength

**Steps**:
```
1. Obtain password hashes (authorized only!)
2. Use John the Ripper or Hashcat
3. Analyze cracked passwords
4. Report weak password practices
5. Recommend password policy improvements
```

---

## Troubleshooting

### Common Issues

#### "Backend Offline"
- Check if backend server is running
- Contact administrator
- Try restarting the application

#### "Tool Not Found"
- Tool may not be installed
- Administrator needs to run installation script
- Check System Diagnostics

#### "Permission Denied"
- Some tools require root privileges
- Administrator may need to configure tool permissions
- Try a different scan type

#### Slow Scans
- Target may be slow to respond
- Network connectivity issues
- Reduce scan intensity in options

### Getting Help

1. Click **Troubleshooting Helper** (🔧 icon)
2. Check error messages in scan output
3. Review System Diagnostics
4. Contact your administrator

---

## Security and Privacy

### Your Responsibilities

- ✅ Only scan authorized targets
- ✅ Protect scan results and credentials
- ✅ Follow company security policies
- ✅ Report security issues responsibly
- ✅ Don't share your login credentials

### Data Protection

- All scans are logged with your user ID
- Reports are stored in the database
- Administrators can view all scan activity
- Sensitive data should be handled carefully

---

## Legal Notice

⚠️ **CRITICAL**: This tool is for authorized security testing only.

**Unauthorized use is illegal and may result in**:
- Criminal prosecution
- Civil liability
- Loss of employment
- Professional consequences

**Always**:
- Obtain written authorization
- Stay within agreed scope
- Document all activities
- Follow responsible disclosure

---

## Quick Reference

### Keyboard Shortcuts
- `Ctrl + S`: Save report
- `Ctrl + E`: Export results
- `Esc`: Stop scan
- `F5`: Refresh results

### Target Format Examples
- IP: `192.168.1.100`
- Domain: `example.com`
- URL: `https://example.com/app`
- IP Range: `192.168.1.1-50`
- Subnet: `192.168.1.0/24`

### Common Ports
- 21: FTP
- 22: SSH
- 23: Telnet
- 25: SMTP (Email)
- 53: DNS
- 80: HTTP
- 443: HTTPS
- 3306: MySQL
- 3389: RDP
- 5432: PostgreSQL

---

## Support

For additional help:
- Check `ADMIN_GUIDE.md` for advanced features
- Review `TROUBLESHOOTING.md`
- Contact your system administrator

**Copyright © 2024 Harsh Malik - All Rights Reserved**

---

*Stay ethical. Stay legal. Happy testing!* 🔒