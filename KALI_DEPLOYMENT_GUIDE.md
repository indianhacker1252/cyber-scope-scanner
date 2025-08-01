# CyberScope Scanner - Kali Linux Deployment Guide

## Overview
This cybersecurity tool provides a comprehensive web-based interface for Kali Linux security tools. It integrates with real Kali tools like Nmap, Nikto, SQLMap, Gobuster, Amass, Nuclei, and many more.

## Prerequisites
- Kali Linux 2023.1+ (recommended)
- Node.js 18+ and npm
- Internet connection
- Sudo privileges

## Quick Installation

### 1. Clone and Setup
```bash
# Clone the repository
git clone https://github.com/your-username/cyber-scope-scanner.git
cd cyber-scope-scanner

# Install dependencies
npm install

# Make installation script executable
chmod +x install-kali-tools.sh

# Run the installation script (installs missing tools)
sudo ./install-kali-tools.sh
```

### 2. Development Mode
```bash
# Start development server
npm run dev

# Access the application at:
# http://localhost:8080
```

### 3. Production Deployment
```bash
# Build for production
npm run build

# Install a web server (if not already installed)
sudo apt install nginx

# Copy build files to web server
sudo cp -r dist/* /var/www/html/

# Start nginx
sudo systemctl start nginx
sudo systemctl enable nginx

# Access at: http://your-kali-ip/
```

## Tool Integration

### Supported Kali Tools
✅ **Network Scanning:**
- Nmap - Network discovery and security auditing
- Masscan - Fast port scanner

✅ **Web Application Testing:**
- Nikto - Web vulnerability scanner
- Gobuster - Directory/file brute-forcer
- SQLMap - SQL injection testing
- WhatWeb - Web application fingerprinting
- Wafw00f - WAF detection

✅ **Reconnaissance:**
- Amass - Subdomain enumeration
- theHarvester - Information gathering
- Recon-ng - Web reconnaissance framework

✅ **Vulnerability Assessment:**
- Nuclei - Fast vulnerability scanner
- OWASP ZAP - Web application security scanner

✅ **Password Attacks:**
- Hydra - Network brute force
- John the Ripper - Password cracking
- Hashcat - Advanced password recovery

✅ **Exploitation:**
- Metasploit Framework - Exploitation framework

## Features

### 🎯 Target Input
- Single or multiple targets
- Network range scanning
- File upload for target lists
- Configurable scan intensity

### 🔍 Real-time Scanning
- Live scan progress monitoring
- Real-time results display
- Session management
- Scan termination controls

### 📊 Comprehensive Reporting
- Detailed vulnerability reports
- Executive summaries
- Export to PDF/Markdown
- Historical scan data

### 🛠️ Tool Management
- Automatic tool detection
- Version monitoring
- Configuration management
- Update notifications

## Usage Examples

### 1. Basic Web Application Scan
```bash
# Target: https://example.com
# Tests: SQL Injection, XSS, Directory Enumeration
```

### 2. Network Infrastructure Assessment
```bash
# Target: 192.168.1.0/24
# Tests: Port scanning, Service enumeration, Vulnerability detection
```

### 3. Comprehensive Security Audit
```bash
# Target: domain.com
# Tests: Subdomain enumeration, Web vulnerabilities, Network scanning
```

## Security Considerations

### 🔒 Legal Notice
**IMPORTANT**: Only use this tool on systems you own or have explicit permission to test. Unauthorized testing is illegal and unethical.

### 🛡️ Best Practices
1. **Authorization**: Always obtain written permission before testing
2. **Scope**: Define clear testing boundaries
3. **Rate Limiting**: Use appropriate scan speeds to avoid DoS
4. **Data Protection**: Secure scan results and reports
5. **Compliance**: Follow applicable laws and regulations

## Configuration

### Environment Variables
Create a `.env` file in the project root:
```bash
# Kali tool paths (optional - auto-detected)
NMAP_PATH=/usr/bin/nmap
NIKTO_PATH=/usr/bin/nikto
SQLMAP_PATH=/usr/bin/sqlmap

# Scan limits
MAX_CONCURRENT_SCANS=3
DEFAULT_TIMEOUT=300

# Report settings
REPORT_OUTPUT_DIR=/tmp/reports
```

### Custom Wordlists
Place custom wordlists in `/usr/share/wordlists/custom/`:
```bash
sudo mkdir -p /usr/share/wordlists/custom
sudo wget https://github.com/danielmiessler/SecLists/archive/master.zip
sudo unzip master.zip -d /usr/share/wordlists/custom/
```

## Troubleshooting

### Common Issues

#### Tool Not Found
```bash
# Check if tool is installed
which nmap

# Install missing tools
sudo apt update
sudo apt install nmap nikto sqlmap gobuster
```

#### Permission Errors
```bash
# Add user to sudo group
sudo usermod -aG sudo $USER

# For network scans, some tools need root
sudo setcap cap_net_raw+ep /usr/bin/nmap
```

#### Port Conflicts
```bash
# Change default port in vite.config.ts
server: {
  port: 3000  // Change from 8080
}
```

#### Memory Issues
```bash
# Increase Node.js memory limit
export NODE_OPTIONS="--max-old-space-size=4096"
npm run dev
```

## Advanced Configuration

### Custom Tool Integration
Add new tools by editing `src/utils/kaliTools.ts`:

```typescript
// Add new tool method
async runCustomTool(target: string): Promise<string> {
  const command = `custom-tool ${target}`;
  const { stdout } = await execAsync(command);
  return stdout;
}
```

### API Integration
The tool supports REST API endpoints for automation:

```bash
# Start scan
curl -X POST http://localhost:8080/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "tests": ["nmap", "nikto"]}'

# Get results
curl http://localhost:8080/api/results/scan-id
```

## Performance Tuning

### For Large Networks
```bash
# Increase system limits
echo "* soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65536" | sudo tee -a /etc/security/limits.conf

# Optimize network parameters
echo "net.core.rmem_max = 134217728" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### For Multiple Targets
- Use target file input for bulk scanning
- Adjust concurrent thread limits
- Monitor system resources during scans

## Updates and Maintenance

### Keep Tools Updated
```bash
# Update Kali tools
sudo apt update && sudo apt upgrade

# Update Nuclei templates
nuclei -update-templates

# Update Metasploit
sudo msfupdate
```

### Update Application
```bash
# Pull latest changes
git pull origin main

# Reinstall dependencies
npm install

# Rebuild application
npm run build
```

## Support and Contributing

### Getting Help
1. Check this documentation
2. Review console logs for errors
3. Check GitHub issues
4. Contact support team

### Contributing
1. Fork the repository
2. Create feature branch
3. Make changes and test
4. Submit pull request

## License
This tool is provided for educational and authorized testing purposes only. Users are responsible for compliance with applicable laws and regulations.

---

**Remember**: With great power comes great responsibility. Use this tool ethically and legally.