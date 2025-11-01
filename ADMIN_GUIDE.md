# VAPT Tool - Administrator Guide

**Copyright © 2024 Harsh Malik - All Rights Reserved**

## Table of Contents
1. [Installation](#installation)
2. [Initial Setup](#initial-setup)
3. [User Management](#user-management)
4. [Security Configuration](#security-configuration)
5. [System Administration](#system-administration)
6. [Troubleshooting](#troubleshooting)

---

## Installation

### Prerequisites
- **Operating System**: Kali Linux (Recommended) or Debian-based Linux
- **RAM**: Minimum 4GB, Recommended 8GB+
- **Storage**: 20GB free space
- **Network**: Internet connection for initial setup

### Installation Steps

1. **Clone the Repository**
```bash
git clone <repository-url>
cd vapt-tool
```

2. **Run Installation Script**
```bash
chmod +x install-kali-tools.sh
./install-kali-tools.sh
```

This script will install:
- All required penetration testing tools (Nmap, Nikto, SQLMap, etc.)
- Node.js and npm
- Go and Go-based security tools
- Python3 and pip
- Backend and frontend dependencies

3. **Start the Application**
```bash
chmod +x start-vapt.sh
./start-vapt.sh
```

The tool will be available at:
- **Frontend**: http://localhost:5173
- **Backend**: http://localhost:8080

---

## Initial Setup

### Default Credentials
- **Username**: `kali`
- **Password**: `kali`
- **Role**: Administrator

### First Login

1. Navigate to http://localhost:5173
2. Log in with default credentials
3. **IMMEDIATELY change the default password**:
   - Click on Profile icon (top right)
   - Update username and password
   - Save changes

### Creating Default User (If Not Created)

If the default user doesn't exist, create it manually:

```bash
# Access Supabase/Lovable Cloud backend
# Use the create-default-user edge function
```

Or use the SQL commands:

```sql
-- Insert into auth.users
INSERT INTO auth.users (email, encrypted_password, email_confirmed_at, raw_user_meta_data)
VALUES ('kali@vapt.local', crypt('kali', gen_salt('bf')), now(), '{"username": "kali", "display_name": "Kali Admin"}');

-- Add admin role
INSERT INTO user_roles (user_id, role)
SELECT id, 'admin' FROM auth.users WHERE email = 'kali@vapt.local';
```

---

## User Management

### Adding New Users

As an administrator, you can create new users:

1. **Via Database** (Recommended for initial users):
```sql
-- Create new user
INSERT INTO auth.users (email, encrypted_password, email_confirmed_at, raw_user_meta_data)
VALUES ('newuser@vapt.local', crypt('SecurePassword123!', gen_salt('bf')), now(), 
        '{"username": "newuser", "display_name": "New User"}');

-- Assign role (admin or user)
INSERT INTO user_roles (user_id, role)
SELECT id, 'user' FROM auth.users WHERE email = 'newuser@vapt.local';
```

2. **Via Application** (Future feature):
   - Navigate to User Management section
   - Click "Add User"
   - Fill in details and assign role

### User Roles

- **Admin**: Full access to all features, can view all reports, manage users
- **User**: Standard access, can run scans and view own reports

### Changing User Passwords

Users can change their own passwords via Profile settings. As admin, you can reset passwords:

```sql
UPDATE auth.users 
SET encrypted_password = crypt('NewPassword123!', gen_salt('bf'))
WHERE email = 'user@vapt.local';
```

### Account Lockout Management

After 5 failed login attempts, accounts are locked for 15 minutes. To manually unlock:

```sql
-- Clear failed attempts for a user
DELETE FROM login_attempts 
WHERE username = 'locked_username' 
AND success = false;
```

---

## Security Configuration

### Backend Security

1. **API Endpoint Protection**
   - Ensure backend runs on localhost only in production
   - Use firewall rules to restrict access:
```bash
sudo ufw allow from 127.0.0.1 to any port 8080
sudo ufw deny 8080
```

2. **Database Security**
   - Enable Row Level Security (RLS) on all tables ✅ (Already configured)
   - Regularly backup database
   - Review login attempts logs

3. **Network Security**
   - Run on isolated network segment
   - Use VPN for remote access
   - Enable HTTPS (production deployment)

### Monitoring Login Attempts

```sql
-- View recent failed attempts
SELECT username, attempted_at, ip_address
FROM login_attempts
WHERE success = false
ORDER BY attempted_at DESC
LIMIT 50;

-- Check for brute force attacks
SELECT username, COUNT(*) as attempt_count, MAX(attempted_at) as last_attempt
FROM login_attempts
WHERE success = false
AND attempted_at > NOW() - INTERVAL '1 hour'
GROUP BY username
HAVING COUNT(*) > 3
ORDER BY attempt_count DESC;
```

---

## System Administration

### Viewing Scan Reports

Administrators can view all scan reports:

1. Navigate to Reports section
2. Filter by user, date, or scan type
3. Export reports as needed

**Database Query**:
```sql
SELECT sr.*, p.username, p.display_name
FROM scan_reports sr
JOIN profiles p ON sr.user_id = p.id
ORDER BY sr.created_at DESC;
```

### Managing Scan Results

```sql
-- View scan statistics
SELECT 
    scan_type,
    severity,
    COUNT(*) as vulnerability_count
FROM scan_reports
WHERE created_at > NOW() - INTERVAL '30 days'
GROUP BY scan_type, severity
ORDER BY vulnerability_count DESC;

-- Delete old scans (older than 90 days)
DELETE FROM scan_reports
WHERE created_at < NOW() - INTERVAL '90 days';
```

### System Diagnostics

Access System Diagnostics from the header:
- View backend connection status
- Check installed tools
- Monitor system resources
- View error logs

### Backup and Recovery

**Database Backup**:
```bash
# Backup database (if using local PostgreSQL)
pg_dump -U postgres vapt_db > backup_$(date +%Y%m%d).sql

# Restore
psql -U postgres vapt_db < backup_20240101.sql
```

**Application Backup**:
```bash
# Backup configuration and data
tar -czf vapt-backup-$(date +%Y%m%d).tar.gz \
    server/ src/ public/ *.md *.sh *.json
```

---

## Troubleshooting

### Common Issues

#### 1. Backend Not Starting

**Symptoms**: "Backend Offline" status indicator

**Solutions**:
```bash
# Check if backend is running
ps aux | grep "node.*server/index.js"

# Check port availability
netstat -tuln | grep 8080

# Restart backend
cd server
node index.js
```

#### 2. Tools Not Working

**Symptoms**: Scan results show tool not found

**Solutions**:
```bash
# Verify tool installation
which nmap sqlmap nikto

# Reinstall tools
./install-kali-tools.sh

# Check tool permissions
sudo setcap cap_net_raw+ep /usr/bin/nmap
```

#### 3. Login Issues

**Symptoms**: Cannot log in with correct credentials

**Solutions**:
```bash
# Check database connection
# View auth logs in Lovable Cloud backend

# Reset user password manually (see User Management section)

# Clear lockout
DELETE FROM login_attempts WHERE username = 'your_username';
```

#### 4. Permission Denied Errors

**Symptoms**: Scans fail with permission errors

**Solutions**:
```bash
# Run backend with sudo (not recommended for production)
sudo node server/index.js

# Or set capabilities for specific tools
sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap
sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/masscan
```

### Logs and Debugging

**View Backend Logs**:
```bash
# If using systemd
journalctl -u vapt-backend -f

# If running manually
tail -f /var/log/vapt/backend.log
```

**Enable Debug Mode**:
```bash
# Edit server/index.js
DEBUG=true node server/index.js
```

### Performance Optimization

1. **Limit Concurrent Scans**:
   - Edit `server/index.js` to set max concurrent sessions
   - Recommended: 5-10 concurrent scans

2. **Database Optimization**:
```sql
-- Add indexes for better performance
CREATE INDEX idx_scan_reports_user_created ON scan_reports(user_id, created_at DESC);
CREATE INDEX idx_login_attempts_username ON login_attempts(username, attempted_at DESC);
```

3. **Resource Monitoring**:
```bash
# Monitor system resources
htop

# Monitor network usage
iftop

# Monitor disk I/O
iotop
```

---

## Security Best Practices

1. ✅ **Change default credentials immediately**
2. ✅ **Use strong passwords (12+ characters, mixed case, numbers, symbols)**
3. ✅ **Regularly review login attempts and user activity**
4. ✅ **Keep tools and dependencies updated**
5. ✅ **Run scans only on authorized targets**
6. ✅ **Store sensitive data encrypted**
7. ✅ **Regularly backup database and configurations**
8. ✅ **Monitor system logs for suspicious activity**
9. ✅ **Use VPN for remote access**
10. ✅ **Implement network segmentation**

---

## Legal and Compliance

⚠️ **IMPORTANT**: This tool is designed for authorized security testing only.

- Only scan systems you own or have explicit written permission to test
- Comply with all applicable laws and regulations
- Document all scanning activities
- Maintain proper authorization documentation
- Follow responsible disclosure practices

**Unauthorized use may result in**:
- Criminal prosecution
- Civil liability
- Loss of professional certifications
- Termination of employment

---

## Support and Updates

For issues and updates:
- Check `TROUBLESHOOTING.md` for common problems
- Review `KALI_DEPLOYMENT_GUIDE.md` for deployment specifics
- Contact system administrator or tool developer

**Copyright © 2024 Harsh Malik - All Rights Reserved**

---

## Appendix: Installed Tools

### Reconnaissance Tools
- Nmap - Network scanner
- Amass - Attack surface mapping
- Subfinder - Subdomain discovery
- TheHarvester - OSINT gathering
- Recon-ng - Web reconnaissance
- DNSrecon - DNS enumeration
- Fierce - DNS reconnaissance

### Web Application Tools
- Nikto - Web server scanner
- SQLMap - SQL injection tool
- Gobuster - Directory/file brute-forcer
- Dirb - Web content scanner
- WhatWeb - Web technology identifier
- Wafw00f - WAF detection
- ZAProxy - Web app security scanner
- Burp Suite - Web vulnerability scanner

### Exploitation Tools
- Metasploit Framework - Exploitation framework
- Hydra - Password cracker
- John the Ripper - Password cracker
- Hashcat - Advanced password recovery

### Network Tools
- Masscan - Fast port scanner
- Wireshark - Network protocol analyzer
- Aircrack-ng - Wireless security tools
- SSLyze - SSL/TLS scanner
- TestSSL - SSL/TLS vulnerability scanner

### Forensics and Analysis
- Binwalk - Firmware analysis
- Foremost - File recovery
- ExifTool - Metadata reader
- Steghide - Steganography tool
- Volatility - Memory forensics

### Advanced Tools
- Nuclei - Vulnerability scanner
- SpiderFoot - OSINT automation
- Hashid - Hash identifier