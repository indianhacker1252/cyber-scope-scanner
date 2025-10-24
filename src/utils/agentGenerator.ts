export interface AgentConfig {
  platform: 'windows' | 'linux' | 'macos' | 'android' | 'ios';
  serverUrl: string;
  agentId: string;
  scanOptions: string[];
}

class AgentGenerator {
  generateAgentScript(config: AgentConfig): string {
    switch (config.platform) {
      case 'windows':
        return this.generateWindowsAgent(config);
      case 'linux':
        return this.generateLinuxAgent(config);
      case 'macos':
        return this.generateMacOSAgent(config);
      case 'android':
        return this.generateAndroidAgent(config);
      case 'ios':
        return this.generateIOSAgent(config);
      default:
        throw new Error('Unsupported platform');
    }
  }

  private generateWindowsAgent(config: AgentConfig): string {
    return `# CyberScope Security Agent - Windows
# Agent ID: ${config.agentId}
# Server: ${config.serverUrl}

$AgentId = "${config.agentId}"
$ServerUrl = "${config.serverUrl}"
$ScanOptions = @(${config.scanOptions.map(opt => `"${opt}"`).join(', ')})

function Send-SystemInfo {
    $computerInfo = Get-ComputerInfo
    $networkInfo = Get-NetIPAddress | Where-Object {$_.AddressFamily -eq "IPv4"}
    
    $data = @{
        agentId = $AgentId
        hostname = $env:COMPUTERNAME
        os = $computerInfo.WindowsProductName
        version = $computerInfo.WindowsVersion
        architecture = $computerInfo.OsArchitecture
        ipAddresses = $networkInfo.IPAddress
        scanOptions = $ScanOptions
        timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
    }
    
    try {
        $json = $data | ConvertTo-Json
        Invoke-RestMethod -Uri "$ServerUrl/api/agent/register" -Method Post -Body $json -ContentType "application/json"
        Write-Host "Agent registered successfully"
    } catch {
        Write-Error "Failed to register agent: $_"
    }
}

function Get-SecurityStatus {
    $services = @{}
    
    # Check Windows Defender
    $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($defender) {
        $services["WindowsDefender"] = @{
            enabled = $defender.AntivirusEnabled
            updated = $defender.AntivirusSignatureLastUpdated
        }
    }
    
    # Check Firewall
    $firewall = Get-NetFirewallProfile
    $services["Firewall"] = @{
        profiles = $firewall | Select-Object Name, Enabled
    }
    
    # Check Windows Updates
    $updates = Get-HotFix | Select-Object -Last 5
    $services["Updates"] = @{
        recentUpdates = $updates
    }
    
    return $services
}

function Start-VulnerabilityScan {
    Write-Host "Starting vulnerability scan..."
    
    $vulnerabilities = @()
    
    # Check for open ports
    $openPorts = Test-NetConnection -ComputerName localhost -Port 135,139,445,3389 -InformationLevel Quiet
    if ($openPorts) {
        $vulnerabilities += @{
            type = "OpenPort"
            severity = "Medium"
            description = "Potentially unnecessary open ports detected"
        }
    }
    
    # Check for weak passwords
    # Check for outdated software
    # Check for missing security patches
    
    $scanResults = @{
        agentId = $AgentId
        vulnerabilities = $vulnerabilities
        timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
    }
    
    try {
        $json = $scanResults | ConvertTo-Json -Depth 10
        Invoke-RestMethod -Uri "$ServerUrl/api/agent/scan-results" -Method Post -Body $json -ContentType "application/json"
        Write-Host "Scan results sent successfully"
    } catch {
        Write-Error "Failed to send scan results: $_"
    }
}

# Main execution
Write-Host "CyberScope Security Agent Starting..."
Send-SystemInfo
Start-VulnerabilityScan

# Keep agent running and check in periodically
while ($true) {
    Start-Sleep -Seconds 300
    Send-SystemInfo
    Start-VulnerabilityScan
}
`;
  }

  private generateLinuxAgent(config: AgentConfig): string {
    return `#!/bin/bash
# CyberScope Security Agent - Linux
# Agent ID: ${config.agentId}
# Server: ${config.serverUrl}

AGENT_ID="${config.agentId}"
SERVER_URL="${config.serverUrl}"
AGENT_SCAN_OPTIONS="${config.scanOptions.join(',')}"

function send_system_info() {
    local hostname=$(hostname)
    local os_info=$(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)
    local kernel=$(uname -r)
    local arch=$(uname -m)
    local ip_addresses=$(ip addr show | grep "inet " | awk '{print $2}' | cut -d'/' -f1 | tr '\\n' ',')
    
    local json_data=$(cat <<EOF
{
  "agentId": "$AGENT_ID",
  "hostname": "$hostname",
  "os": "$os_info",
  "kernel": "$kernel",
  "architecture": "$arch",
  "ipAddresses": "$ip_addresses",
  "scanOptions": "$AGENT_SCAN_OPTIONS",
  "timestamp": "$(date -Iseconds)"
}
EOF
)
    
    curl -X POST "$SERVER_URL/api/agent/register" \\
        -H "Content-Type: application/json" \\
        -d "$json_data"
}

function get_security_status() {
    echo "Checking security status..."
    
    # Check firewall
    if command -v ufw &> /dev/null; then
        ufw status
    elif command -v firewalld &> /dev/null; then
        firewall-cmd --state
    fi
    
    # Check for security updates
    if command -v apt &> /dev/null; then
        apt list --upgradable 2>/dev/null | grep security
    elif command -v yum &> /dev/null; then
        yum check-update --security
    fi
}

function start_vulnerability_scan() {
    echo "Starting vulnerability scan..."
    
    local vulnerabilities="[]"
    
    # Check for open ports
    if command -v netstat &> /dev/null; then
        local open_ports=$(netstat -tuln | grep LISTEN)
        if [ -n "$open_ports" ]; then
            vulnerabilities='[{"type":"OpenPorts","severity":"Medium","description":"Open network ports detected"}]'
        fi
    fi
    
    # Check for SUID binaries
    local suid_files=$(find / -perm -4000 2>/dev/null | wc -l)
    
    # Check SSH configuration
    if [ -f /etc/ssh/sshd_config ]; then
        local root_login=$(grep "^PermitRootLogin" /etc/ssh/sshd_config)
    fi
    
    local json_data=$(cat <<EOF
{
  "agentId": "$AGENT_ID",
  "vulnerabilities": $vulnerabilities,
  "timestamp": "$(date -Iseconds)"
}
EOF
)
    
    curl -X POST "$SERVER_URL/api/agent/scan-results" \\
        -H "Content-Type: application/json" \\
        -d "$json_data"
}

# Main execution
echo "CyberScope Security Agent Starting..."
send_system_info
start_vulnerability_scan

# Keep agent running
while true; do
    sleep 300
    send_system_info
    start_vulnerability_scan
done
`;
  }

  private generateMacOSAgent(config: AgentConfig): string {
    return `#!/bin/bash
# CyberScope Security Agent - macOS
# Agent ID: ${config.agentId}
# Server: ${config.serverUrl}

AGENT_ID="${config.agentId}"
SERVER_URL="${config.serverUrl}"

function send_system_info() {
    local hostname=$(hostname)
    local os_version=$(sw_vers -productVersion)
    local build=$(sw_vers -buildVersion)
    local arch=$(uname -m)
    
    local json_data=$(cat <<EOF
{
  "agentId": "$AGENT_ID",
  "hostname": "$hostname",
  "os": "macOS $os_version",
  "build": "$build",
  "architecture": "$arch",
  "timestamp": "$(date -Iseconds)"
}
EOF
)
    
    curl -X POST "$SERVER_URL/api/agent/register" \\
        -H "Content-Type: application/json" \\
        -d "$json_data"
}

function start_vulnerability_scan() {
    echo "Starting macOS vulnerability scan..."
    
    # Check Gatekeeper status
    local gatekeeper=$(spctl --status)
    
    # Check FileVault status
    local filevault=$(fdesetup status)
    
    # Check for software updates
    local updates=$(softwareupdate -l 2>&1)
    
    echo "Scan completed"
}

echo "CyberScope Security Agent Starting..."
send_system_info
start_vulnerability_scan
`;
  }

  private generateAndroidAgent(config: AgentConfig): string {
    return `// CyberScope Security Agent - Android
// Agent ID: ${config.agentId}
// Server: ${config.serverUrl}

package com.cyberscope.agent;

import android.app.Service;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;
import org.json.JSONObject;
import java.net.HttpURLConnection;
import java.net.URL;

public class SecurityAgent extends Service {
    private static final String AGENT_ID = "${config.agentId}";
    private static final String SERVER_URL = "${config.serverUrl}";
    
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        sendSystemInfo();
        startVulnerabilityScan();
        return START_STICKY;
    }
    
    private void sendSystemInfo() {
        try {
            JSONObject data = new JSONObject();
            data.put("agentId", AGENT_ID);
            data.put("deviceModel", Build.MODEL);
            data.put("androidVersion", Build.VERSION.RELEASE);
            data.put("sdkVersion", Build.VERSION.SDK_INT);
            data.put("manufacturer", Build.MANUFACTURER);
            
            sendToServer("/api/agent/register", data);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private void startVulnerabilityScan() {
        // Check for rooted device
        // Check for debugging enabled
        // Check for unknown sources enabled
        // Check installed apps for malware
    }
    
    private void sendToServer(String endpoint, JSONObject data) {
        // HTTP POST implementation
    }
    
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
`;
  }

  private generateIOSAgent(config: AgentConfig): string {
    return `// CyberScope Security Agent - iOS
// Agent ID: ${config.agentId}
// Server: ${config.serverUrl}

import Foundation
import UIKit

class SecurityAgent {
    static let agentId = "${config.agentId}"
    static let serverUrl = "${config.serverUrl}"
    
    static func sendSystemInfo() {
        let device = UIDevice.current
        
        let data: [String: Any] = [
            "agentId": agentId,
            "deviceModel": device.model,
            "systemVersion": device.systemVersion,
            "deviceName": device.name
        ]
        
        sendToServer(endpoint: "/api/agent/register", data: data)
    }
    
    static func startVulnerabilityScan() {
        // Check for jailbreak
        // Check for app permissions
        // Check for outdated iOS version
    }
    
    static func sendToServer(endpoint: String, data: [String: Any]) {
        guard let url = URL(string: serverUrl + endpoint) else { return }
        
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        do {
            request.httpBody = try JSONSerialization.data(withJSONObject: data)
            
            let task = URLSession.shared.dataTask(with: request) { data, response, error in
                if let error = error {
                    print("Error: " + error.localizedDescription)
                    return
                }
            }
            task.resume()
        } catch {
            print("Error: " + error.localizedDescription)
        }
    }
}
`;
  }

  downloadAgent(config: AgentConfig) {
    const script = this.generateAgentScript(config);
    const extensions: Record<string, string> = {
      'windows': 'ps1',
      'linux': 'sh',
      'macos': 'sh',
      'android': 'java',
      'ios': 'swift'
    };
    
    const extension = extensions[config.platform];
    const filename = `cyberscope-agent-${config.platform}-${config.agentId}.${extension}`;
    
    const blob = new Blob([script], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }
}

export default new AgentGenerator();
