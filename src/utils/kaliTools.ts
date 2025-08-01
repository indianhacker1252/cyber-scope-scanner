import { spawn, exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

export interface ScanResult {
  id: string;
  tool: string;
  target: string;
  status: 'running' | 'completed' | 'failed';
  progress: number;
  findings: any[];
  output: string;
  startTime: Date;
  endTime?: Date;
}

export interface ToolConfig {
  name: string;
  command: string;
  version: string;
  installed: boolean;
  category: string;
}

export class KaliToolsManager {
  private static instance: KaliToolsManager;
  private activeSessions: Map<string, any> = new Map();
  
  static getInstance(): KaliToolsManager {
    if (!KaliToolsManager.instance) {
      KaliToolsManager.instance = new KaliToolsManager();
    }
    return KaliToolsManager.instance;
  }

  // Check if running in Kali Linux environment
  async isKaliLinux(): Promise<boolean> {
    try {
      const { stdout } = await execAsync('cat /etc/os-release | grep -i kali');
      return stdout.includes('Kali');
    } catch {
      return false;
    }
  }

  // Get installed Kali tools
  async getInstalledTools(): Promise<ToolConfig[]> {
    const tools = [
      { name: 'nmap', command: 'nmap', category: 'Network Scanning' },
      { name: 'nikto', command: 'nikto', category: 'Web Assessment' },
      { name: 'sqlmap', command: 'sqlmap', category: 'Database Testing' },
      { name: 'gobuster', command: 'gobuster', category: 'Directory Enumeration' },
      { name: 'dirb', command: 'dirb', category: 'Directory Enumeration' },
      { name: 'wpscan', command: 'wpscan', category: 'WordPress Security' },
      { name: 'masscan', command: 'masscan', category: 'Network Scanning' },
      { name: 'hydra', command: 'hydra', category: 'Brute Force' },
      { name: 'john', command: 'john', category: 'Password Cracking' },
      { name: 'hashcat', command: 'hashcat', category: 'Password Cracking' },
      { name: 'metasploit', command: 'msfconsole', category: 'Exploitation' },
      { name: 'burpsuite', command: 'burpsuite', category: 'Web Assessment' },
      { name: 'zaproxy', command: 'zaproxy', category: 'Web Assessment' },
      { name: 'amass', command: 'amass', category: 'Reconnaissance' },
      { name: 'subfinder', command: 'subfinder', category: 'Reconnaissance' },
      { name: 'nuclei', command: 'nuclei', category: 'Vulnerability Scanner' },
      { name: 'recon-ng', command: 'recon-ng', category: 'Reconnaissance' },
      { name: 'theharvester', command: 'theHarvester', category: 'Information Gathering' },
      { name: 'whatweb', command: 'whatweb', category: 'Web Fingerprinting' },
      { name: 'wafw00f', command: 'wafw00f', category: 'WAF Detection' },
    ];

    const installedTools = await Promise.all(
      tools.map(async (tool) => {
        try {
          const { stdout } = await execAsync(`which ${tool.command}`);
          const version = await this.getToolVersion(tool.command);
          return {
            ...tool,
            version,
            installed: true,
          };
        } catch {
          return {
            ...tool,
            version: 'Not installed',
            installed: false,
          };
        }
      })
    );

    return installedTools;
  }

  // Get tool version
  async getToolVersion(command: string): Promise<string> {
    try {
      const versionCommands: Record<string, string> = {
        'nmap': 'nmap --version | head -1',
        'nikto': 'nikto -Version',
        'sqlmap': 'sqlmap --version',
        'gobuster': 'gobuster version',
        'nuclei': 'nuclei -version',
        'masscan': 'masscan --version',
        'hydra': 'hydra -h | grep "^Hydra"',
        'john': 'john --version',
        'hashcat': 'hashcat --version',
        'amass': 'amass version',
        'subfinder': 'subfinder -version',
        'theHarvester': 'theHarvester --version',
        'whatweb': 'whatweb --version',
        'wafw00f': 'wafw00f --version',
      };

      const versionCmd = versionCommands[command] || `${command} --version`;
      const { stdout } = await execAsync(versionCmd);
      return stdout.split('\n')[0].trim();
    } catch {
      return 'Unknown';
    }
  }

  // Network Scanning with Nmap
  async runNmapScan(target: string, scanType: string = 'basic'): Promise<string> {
    const scanTypes: Record<string, string> = {
      'basic': '-sS -O -sV',
      'aggressive': '-A -T4',
      'stealth': '-sS -T1',
      'udp': '-sU',
      'full': '-p- -A',
      'vuln': '--script vuln',
      'discovery': '-sn',
    };

    const scanOptions = scanTypes[scanType] || scanTypes.basic;
    const command = `nmap ${scanOptions} ${target}`;
    
    try {
      const { stdout, stderr } = await execAsync(command, { timeout: 300000 }); // 5 min timeout
      return stdout + (stderr ? `\nErrors: ${stderr}` : '');
    } catch (error: any) {
      throw new Error(`Nmap scan failed: ${error.message}`);
    }
  }

  // Web Vulnerability Scanning with Nikto
  async runNiktoScan(target: string): Promise<string> {
    const command = `nikto -h ${target} -Format txt`;
    
    try {
      const { stdout, stderr } = await execAsync(command, { timeout: 600000 }); // 10 min timeout
      return stdout + (stderr ? `\nErrors: ${stderr}` : '');
    } catch (error: any) {
      throw new Error(`Nikto scan failed: ${error.message}`);
    }
  }

  // SQL Injection Testing with SQLMap
  async runSQLMapScan(target: string, options: string = ''): Promise<string> {
    const safeOptions = options || '--batch --random-agent --level=1 --risk=1';
    const command = `sqlmap -u "${target}" ${safeOptions}`;
    
    try {
      const { stdout, stderr } = await execAsync(command, { timeout: 900000 }); // 15 min timeout
      return stdout + (stderr ? `\nErrors: ${stderr}` : '');
    } catch (error: any) {
      throw new Error(`SQLMap scan failed: ${error.message}`);
    }
  }

  // Directory Enumeration with Gobuster
  async runGobusterScan(target: string, wordlist?: string): Promise<string> {
    const defaultWordlist = '/usr/share/wordlists/dirb/common.txt';
    const wordlistPath = wordlist || defaultWordlist;
    const command = `gobuster dir -u ${target} -w ${wordlistPath} -t 20`;
    
    try {
      const { stdout, stderr } = await execAsync(command, { timeout: 600000 }); // 10 min timeout
      return stdout + (stderr ? `\nErrors: ${stderr}` : '');
    } catch (error: any) {
      throw new Error(`Gobuster scan failed: ${error.message}`);
    }
  }

  // Subdomain Enumeration with Amass
  async runAmassEnum(domain: string): Promise<string> {
    const command = `amass enum -d ${domain} -o /tmp/amass_${domain}.txt`;
    
    try {
      const { stdout, stderr } = await execAsync(command, { timeout: 1800000 }); // 30 min timeout
      const results = await execAsync(`cat /tmp/amass_${domain}.txt`);
      return results.stdout + (stderr ? `\nErrors: ${stderr}` : '');
    } catch (error: any) {
      throw new Error(`Amass enumeration failed: ${error.message}`);
    }
  }

  // Vulnerability Scanning with Nuclei
  async runNucleiScan(target: string, templates?: string): Promise<string> {
    const templateOption = templates ? `-t ${templates}` : '-t cves,vulnerabilities';
    const command = `nuclei -u ${target} ${templateOption} -o /tmp/nuclei_${Date.now()}.txt`;
    
    try {
      const { stdout, stderr } = await execAsync(command, { timeout: 1200000 }); // 20 min timeout
      return stdout + (stderr ? `\nErrors: ${stderr}` : '');
    } catch (error: any) {
      throw new Error(`Nuclei scan failed: ${error.message}`);
    }
  }

  // Web Application Fingerprinting
  async runWhatWebScan(target: string): Promise<string> {
    const command = `whatweb ${target} --aggression=3`;
    
    try {
      const { stdout, stderr } = await execAsync(command, { timeout: 180000 }); // 3 min timeout
      return stdout + (stderr ? `\nErrors: ${stderr}` : '');
    } catch (error: any) {
      throw new Error(`WhatWeb scan failed: ${error.message}`);
    }
  }

  // WAF Detection
  async runWAFDetection(target: string): Promise<string> {
    const command = `wafw00f ${target}`;
    
    try {
      const { stdout, stderr } = await execAsync(command, { timeout: 120000 }); // 2 min timeout
      return stdout + (stderr ? `\nErrors: ${stderr}` : '');
    } catch (error: any) {
      throw new Error(`WAF detection failed: ${error.message}`);
    }
  }

  // Mass Port Scanning with Masscan
  async runMasscanScan(target: string, ports: string = '1-65535'): Promise<string> {
    const command = `masscan ${target} -p${ports} --rate=1000`;
    
    try {
      const { stdout, stderr } = await execAsync(command, { timeout: 600000 }); // 10 min timeout
      return stdout + (stderr ? `\nErrors: ${stderr}` : '');
    } catch (error: any) {
      throw new Error(`Masscan failed: ${error.message}`);
    }
  }

  // Information Gathering with theHarvester
  async runTheHarvester(domain: string, source: string = 'google'): Promise<string> {
    const command = `theHarvester -d ${domain} -b ${source} -l 100`;
    
    try {
      const { stdout, stderr } = await execAsync(command, { timeout: 300000 }); // 5 min timeout
      return stdout + (stderr ? `\nErrors: ${stderr}` : '');
    } catch (error: any) {
      throw new Error(`theHarvester failed: ${error.message}`);
    }
  }

  // Brute Force with Hydra
  async runHydraBruteForce(target: string, service: string, userlist: string, passlist: string): Promise<string> {
    const command = `hydra -L ${userlist} -P ${passlist} ${target} ${service} -t 4`;
    
    try {
      const { stdout, stderr } = await execAsync(command, { timeout: 1800000 }); // 30 min timeout
      return stdout + (stderr ? `\nErrors: ${stderr}` : '');
    } catch (error: any) {
      throw new Error(`Hydra brute force failed: ${error.message}`);
    }
  }

  // Generate comprehensive report
  generateReport(scanResults: ScanResult[]): string {
    let report = `
# Cybersecurity Assessment Report
Generated: ${new Date().toISOString()}

## Executive Summary
This report contains the results of a comprehensive cybersecurity assessment performed using various Kali Linux tools.

## Scan Summary
Total Scans: ${scanResults.length}
Completed: ${scanResults.filter(r => r.status === 'completed').length}
Failed: ${scanResults.filter(r => r.status === 'failed').length}

## Detailed Results
`;

    scanResults.forEach((result, index) => {
      report += `
### ${index + 1}. ${result.tool.toUpperCase()} - ${result.target}
**Status:** ${result.status}
**Duration:** ${result.endTime ? Math.round((result.endTime.getTime() - result.startTime.getTime()) / 1000) : 'N/A'} seconds
**Findings:** ${result.findings.length}

\`\`\`
${result.output}
\`\`\`

---
`;
    });

    return report;
  }

  // Stop all running scans
  stopAllScans(): void {
    this.activeSessions.forEach((session, id) => {
      if (session && session.kill) {
        session.kill('SIGTERM');
      }
    });
    this.activeSessions.clear();
  }

  // Get active session count
  getActiveSessionCount(): number {
    return this.activeSessions.size;
  }
}

export default KaliToolsManager;