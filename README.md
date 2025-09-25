# VAPT Arsenal - Vulnerability Assessment & Penetration Testing Tool

A comprehensive web-based VAPT (Vulnerability Assessment & Penetration Testing) tool suite built with React, integrating real Kali Linux security tools for professional penetration testing.

## 🚀 Quick Installation

### Prerequisites
- **Kali Linux** (recommended) or any Linux distribution
- **Node.js** (v16 or higher)
- **npm** or **yarn**
- **Required Security Tools** (auto-installed with script)

### Option 1: Automatic Setup (Recommended)
```bash
# Clone the repository
git clone <your-repo-url>
cd vapt-arsenal

# Make script executable and run
chmod +x start-vapt.sh
./start-vapt.sh
```

### Option 2: Manual Setup
```bash
# Install backend dependencies
cd server
npm install

# Start backend server
node index.js &

# Install frontend dependencies (in new terminal)
cd ../
npm install

# Start frontend development server
npm run dev
```

## 🔧 Required Tools Installation

The following security tools will be auto-installed:
```bash
# Network & Port Scanning
sudo apt install nmap

# Web Vulnerability Scanning
sudo apt install nikto

# SQL Injection Testing
sudo apt install sqlmap

# Directory Enumeration
sudo apt install gobuster

# Advanced Vulnerability Detection
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Technology Fingerprinting
sudo apt install whatweb

# Subdomain Enumeration
sudo apt install amass sublist3r

# Wordlists
sudo apt install wordlists
```

## 🌐 Access Points

- **Frontend Dashboard**: http://localhost:5173
- **Backend API**: http://localhost:8080
- **WebSocket Stream**: ws://localhost:8080

## 📊 Dashboard Overview

### Header Buttons
- **🛡️ VAPT Arsenal**: Main logo/title
- **📊 Status Indicator**: Shows system status (Online/Offline)
- **📈 Diagnostics**: Check backend connectivity and system health
- **⚙️ Settings**: Configure API URLs, AI settings, and preferences
- **👤 Profile**: User profile and account settings

### Main Dashboard Sections

#### 1. Target Input & Configuration
**Location**: Main dashboard tab
**Purpose**: Configure scan targets and parameters

**Buttons & Usage**:
- **Single Target Tab**: Enter one URL/IP address
- **Multiple Targets Tab**: Enter multiple targets (one per line)
- **File Upload Tab**: Upload text file with targets
- **Choose File**: Select target file from computer
- **Start Manual Scan**: Begin custom vulnerability scan
- **Start Automated Scan**: Run comprehensive automated scan
- **Save Configuration**: Save current scan settings

#### 2. Network Scanning
**Purpose**: Network discovery and port scanning

**Buttons & Functions**:
- **Quick Scan**: Fast port scan (top 1000 ports)
- **Full Scan**: Comprehensive port scan (all 65535 ports)
- **Service Detection**: Identify services on open ports
- **OS Detection**: Fingerprint operating system
- **Vulnerability Scan**: Check for known vulnerabilities
- **Custom Scan**: Configure custom Nmap parameters

#### 3. Web Vulnerabilities
**Purpose**: Web application security testing

**Buttons & Functions**:
- **Directory Enumeration**: Find hidden directories (Gobuster)
- **Technology Detection**: Identify web technologies (WhatWeb)
- **Vulnerability Scan**: Web vulnerability scanning (Nikto)
- **SQL Injection Test**: Test for SQL injection (SQLMap)
- **Advanced Vulnerability Detection**: Modern vulnerability scanning (Nuclei)

#### 4. Reconnaissance
**Purpose**: Information gathering and OSINT

**Buttons & Functions**:
- **Subdomain Enumeration**: Find subdomains (Amass, Sublist3r)
- **DNS Enumeration**: DNS record analysis
- **WHOIS Lookup**: Domain registration information
- **Port Scanning**: Network port discovery
- **Service Fingerprinting**: Identify running services

#### 5. Code Analysis
**Purpose**: Source code security analysis

**Buttons & Functions**:
- **Static Analysis**: Analyze source code for vulnerabilities
- **Dependency Check**: Check for vulnerable dependencies
- **Security Audit**: Comprehensive code security review
- **Generate Report**: Create security analysis report

#### 6. Database Testing
**Purpose**: Database security assessment

**Buttons & Functions**:
- **Connection Test**: Test database connectivity
- **SQL Injection**: Advanced SQL injection testing
- **Privilege Escalation**: Test for privilege escalation
- **Data Extraction**: Extract sensitive data (authorized testing only)

#### 7. Mobile Security
**Purpose**: Mobile application security testing

**Buttons & Functions**:
- **APK Analysis**: Android application analysis
- **iOS Security**: iOS application testing
- **API Testing**: Mobile API security assessment
- **Certificate Pinning**: Test SSL certificate pinning

#### 8. IoT Security
**Purpose**: Internet of Things device testing

**Buttons & Functions**:
- **Device Discovery**: Find IoT devices on network
- **Firmware Analysis**: Analyze device firmware
- **Protocol Testing**: Test IoT communication protocols
- **Default Credentials**: Check for default passwords

#### 9. Advanced Scanning
**Purpose**: Advanced vulnerability detection

**Buttons & Functions**:
- **Custom Payloads**: Load custom exploit payloads
- **Exploit Testing**: Test specific exploits
- **Zero-Day Detection**: Advanced threat detection
- **Custom Scripts**: Run custom security scripts

#### 10. Reports & Documentation
**Purpose**: Generate professional reports

**Buttons & Functions**:
- **Generate HTML Report**: Create web-based report
- **Generate PDF Report**: Create PDF documentation
- **Export Results**: Export scan results (JSON/CSV)
- **VAPT Report**: Professional penetration testing report
- **Executive Summary**: High-level security summary

## 🔧 Configuration & Settings

### API Configuration
1. Click **Settings** button (⚙️) in header
2. Navigate to **API & AI Configuration** tab
3. Configure:
   - **Backend API URL**: Default `http://localhost:8080`
   - **WebSocket URL**: Default `ws://localhost:8080`
   - **OpenAI API Key**: For AI-powered analysis

### Scan Configuration
- **Scan Intensity**: Low, Medium, High, Aggressive
- **Thread Count**: Number of concurrent threads (1-50)
- **Timeout**: Request timeout in seconds
- **User Agent**: Custom user agent string
- **Rate Limiting**: Requests per second

## 🚨 Troubleshooting

### Common Issues & Solutions

#### Backend Connection Failed
1. Click **Diagnostics** button (📈) in header
2. Check backend connectivity status
3. Ensure backend server is running on port 8080
4. Verify firewall settings allow connections

#### Tools Not Found
```bash
# Check tool installation
which nmap
which nikto
which sqlmap

# Install missing tools
sudo apt update
sudo apt install <missing-tool>
```

#### Permission Denied
```bash
# Run with appropriate permissions
sudo ./start-vapt.sh

# Or adjust permissions
chmod +x start-vapt.sh
```

#### WebSocket Connection Issues
1. Check if backend WebSocket server is running
2. Verify WebSocket URL in Settings
3. Check browser console for connection errors
4. Try refreshing the page

## 🔒 Security & Legal Notes

**⚠️ IMPORTANT LEGAL DISCLAIMER**:
- Only scan systems you own or have explicit written permission to test
- Follow responsible disclosure practices for any vulnerabilities found
- Respect rate limits and terms of service
- Unauthorized scanning may be illegal in your jurisdiction
- Use VPN when appropriate for legitimate bug bounty testing

## 📚 Usage Examples

### Basic Network Scan
1. Go to **Network Scanning** tab
2. Enter target IP/domain in **Target Input**
3. Click **Quick Scan** for fast port discovery
4. View results in **Scan Results** tab

### Web Application Testing
1. Navigate to **Web Vulnerabilities** tab
2. Enter target URL
3. Click **Directory Enumeration** to find hidden paths
4. Use **Vulnerability Scan** for comprehensive testing
5. Check **SQL Injection Test** for database vulnerabilities

### Comprehensive Assessment
1. Use **Target Input** to configure multiple targets
2. Click **Start Automated Scan** for full assessment
3. Monitor progress in real-time
4. Generate professional report when complete

## 🎯 Advanced Features

### Bug Bounty Hunting
- Subdomain takeover detection
- CVE auto-matching
- Payload injection testing
- Burp Suite integration
- Bounty program validation

### AI-Powered Analysis
- Automated vulnerability assessment
- Intelligent report generation
- Risk prioritization
- Remediation suggestions

### Real-Time Monitoring
- Live scan progress tracking
- WebSocket-based output streaming
- Real-time vulnerability detection
- Instant notifications

## 🤝 Support & Community

- **Documentation**: Check this README for detailed instructions
- **Issues**: Report bugs via GitHub issues
- **Discord**: Join our community for support
- **Updates**: Regular tool updates and improvements

## 📄 License

This tool is for educational and authorized security testing purposes only. Users are responsible for compliance with applicable laws and regulations.

---

**Ready to secure your infrastructure? Start your first scan! 🎯**