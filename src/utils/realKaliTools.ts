/**
 * VAPT Security Scanner - Real Kali Linux Tools Manager
 * 
 * Copyright (c) 2024 Harsh Malik
 * All Rights Reserved
 * 
 * This tool integrates with Kali Linux backend for real-time security scanning.
 * NO MOCK DATA - All scans connect to actual Kali Linux tools.
 * 
 * @author Harsh Malik
 * @version 2.0.0
 */

// Real Kali Linux Tools Manager - NO DEMO MODE
import { ScanResult, ToolConfig, AutomatedScanConfig } from './kaliTools';
import { API_CONFIG } from '@/config/apiConfig';

interface StreamingCallback {
  onOutput?: (data: string) => void;
  onProgress?: (progress: number) => void;
  onComplete?: (result: ScanResult) => void;
  onError?: (error: string) => void;
}

export class RealKaliToolsManager {
  private static instance: RealKaliToolsManager;
  private activeSessions = new Map<string, AbortController>();
  private wsConnections = new Map<string, WebSocket>();

  static getInstance(): RealKaliToolsManager {
    if (!RealKaliToolsManager.instance) {
      RealKaliToolsManager.instance = new RealKaliToolsManager();
    }
    return RealKaliToolsManager.instance;
  }

  // Check if we're actually in Kali Linux environment
  async isKaliLinux(): Promise<boolean> {
    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.CHECK_KALI}`, {
        signal: AbortSignal.timeout(5000) // 5 second timeout
      });
      
      if (!response.ok) {
        console.error(`[Backend Connection] HTTP ${response.status}: ${response.statusText}`);
        throw new Error(`Backend server returned error: ${response.status} ${response.statusText}`);
      }
      
      const result = await response.json();
      console.log(`[Backend Connection] Kali Linux detected: ${result.isKali}`);
      return result.isKali;
    } catch (error: any) {
      console.error('[Backend Connection] CRITICAL ERROR - Backend server unavailable:', {
        message: error.message,
        name: error.name,
        timestamp: new Date().toISOString(),
        endpoint: `${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.CHECK_KALI}`
      });
      throw new Error(`Backend connection failed: ${error.message}. Please ensure Node.js backend is running on localhost:8080`);
    }
  }

  // Get list of installed tools
  async getInstalledTools(): Promise<ToolConfig[]> {
    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.TOOLS_INSTALLED}`);
      return await response.json();
    } catch {
      return [];
    }
  }

  // Execute Nmap scan with real-time streaming
  async runNmapScan(
    target: string, 
    scanType: string = 'basic',
    callback?: StreamingCallback
  ): Promise<string> {
    const sessionId = `nmap-${Date.now()}`;
    const controller = new AbortController();
    this.activeSessions.set(sessionId, controller);

    try {
      console.log(`[Nmap] Starting scan: ${target} (${scanType}) - Session: ${sessionId}`);
      
      const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.SCAN_NMAP}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, scanType, sessionId }),
        signal: controller.signal
      });

      if (!response.ok) {
        const errorText = await response.text().catch(() => response.statusText);
        throw new Error(`Nmap scan failed: ${errorText}`);
      }

      console.log(`[Nmap] HTTP request successful, connecting WebSocket...`);
      
      // Use the robust streamResults method
      return this.streamResults(sessionId, callback);

    } catch (error: any) {
      console.error(`[Nmap] Error:`, error);
      this.cleanup(sessionId);
      
      // Check for privilege errors
      if (error.message?.includes('permission') || error.message?.includes('privilege')) {
        throw new Error('Nmap requires elevated privileges for this scan type. Try "basic" scan or run backend with sudo.');
      }
      
      throw error;
    }
  }

  // Execute Nikto scan
  async runNiktoScan(target: string, callback?: StreamingCallback): Promise<string> {
    const sessionId = `nikto-${Date.now()}`;
    const controller = new AbortController();
    this.activeSessions.set(sessionId, controller);

    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.SCAN_NIKTO}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, sessionId }),
        signal: controller.signal
      });

      if (!response.ok) {
        throw new Error(`Nikto scan failed: ${response.statusText}`);
      }

      return this.streamResults(sessionId, callback);
    } catch (error: any) {
      this.cleanup(sessionId);
      throw error;
    }
  }

  // Execute SQLMap scan
  async runSQLMapScan(target: string, options: string = '', callback?: StreamingCallback): Promise<string> {
    const sessionId = `sqlmap-${Date.now()}`;
    const controller = new AbortController();
    this.activeSessions.set(sessionId, controller);

    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.SCAN_SQLMAP}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, options, sessionId }),
        signal: controller.signal
      });

      if (!response.ok) {
        throw new Error(`SQLMap scan failed: ${response.statusText}`);
      }

      return this.streamResults(sessionId, callback);
    } catch (error: any) {
      this.cleanup(sessionId);
      throw error;
    }
  }

  // Execute Gobuster directory enumeration
  async runGobusterScan(target: string, wordlist?: string, callback?: StreamingCallback): Promise<string> {
    const sessionId = `gobuster-${Date.now()}`;
    const controller = new AbortController();
    this.activeSessions.set(sessionId, controller);

    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.SCAN_GOBUSTER}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, wordlist, sessionId }),
        signal: controller.signal
      });

      if (!response.ok) {
        throw new Error(`Gobuster scan failed: ${response.statusText}`);
      }

      return this.streamResults(sessionId, callback);
    } catch (error: any) {
      this.cleanup(sessionId);
      throw error;
    }
  }

  // Execute Amass subdomain enumeration
  async runAmassEnum(domain: string, callback?: StreamingCallback): Promise<string> {
    const sessionId = `amass-${Date.now()}`;
    const controller = new AbortController();
    this.activeSessions.set(sessionId, controller);

    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.SCAN_AMASS}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain, sessionId }),
        signal: controller.signal
      });

      if (!response.ok) {
        throw new Error(`Amass scan failed: ${response.statusText}`);
      }

      return this.streamResults(sessionId, callback);
    } catch (error: any) {
      this.cleanup(sessionId);
      throw error;
    }
  }

  // Execute DNS Lookup
  async runDNSLookup(domain: string, callback?: StreamingCallback): Promise<string> {
    const sessionId = `dns-${Date.now()}`;
    const controller = new AbortController();
    this.activeSessions.set(sessionId, controller);

    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.SCAN_DNS}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain, sessionId }),
        signal: controller.signal
      });

      if (!response.ok) {
        throw new Error(`DNS lookup failed: ${response.statusText}`);
      }

      return this.streamResults(sessionId, callback);
    } catch (error: any) {
      this.cleanup(sessionId);
      throw error;
    }
  }

  // Execute WHOIS Lookup
  async runWhoisLookup(domain: string, callback?: StreamingCallback): Promise<string> {
    const sessionId = `whois-${Date.now()}`;
    const controller = new AbortController();
    this.activeSessions.set(sessionId, controller);

    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.SCAN_WHOIS}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain, sessionId }),
        signal: controller.signal
      });

      if (!response.ok) {
        throw new Error(`WHOIS lookup failed: ${response.statusText}`);
      }

      return this.streamResults(sessionId, callback);
    } catch (error: any) {
      this.cleanup(sessionId);
      throw error;
    }
  }

  // Execute SSL Certificate Analysis
  async runSSLAnalysis(domain: string, callback?: StreamingCallback): Promise<string> {
    const sessionId = `ssl-${Date.now()}`;
    const controller = new AbortController();
    this.activeSessions.set(sessionId, controller);

    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.SCAN_SSL}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain, sessionId }),
        signal: controller.signal
      });

      if (!response.ok) {
        throw new Error(`SSL analysis failed: ${response.statusText}`);
      }

      return this.streamResults(sessionId, callback);
    } catch (error: any) {
      this.cleanup(sessionId);
      throw error;
    }
  }

  // Execute Nuclei vulnerability scan
  async runNucleiScan(target: string, templates?: string, callback?: StreamingCallback): Promise<string> {
    const sessionId = `nuclei-${Date.now()}`;
    const controller = new AbortController();
    this.activeSessions.set(sessionId, controller);

    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.SCAN_NUCLEI}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, templates, sessionId }),
        signal: controller.signal
      });

      if (!response.ok) {
        throw new Error(`Nuclei scan failed: ${response.statusText}`);
      }

      return this.streamResults(sessionId, callback);
    } catch (error: any) {
      this.cleanup(sessionId);
      throw error;
    }
  }

  // Execute WhatWeb technology detection
  async runWhatWebScan(target: string, callback?: StreamingCallback): Promise<string> {
    const sessionId = `whatweb-${Date.now()}`;
    const controller = new AbortController();
    this.activeSessions.set(sessionId, controller);

    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.SCAN_WHATWEB}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, sessionId }),
        signal: controller.signal
      });

      if (!response.ok) {
        throw new Error(`WhatWeb scan failed: ${response.statusText}`);
      }

      return this.streamResults(sessionId, callback);
    } catch (error: any) {
      this.cleanup(sessionId);
      throw error;
    }
  }

  // Execute Sublist3r subdomain enumeration
  async runSublist3rScan(domain: string, callback?: StreamingCallback): Promise<string> {
    const sessionId = `sublist3r-${Date.now()}`;
    const controller = new AbortController();
    this.activeSessions.set(sessionId, controller);

    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.SCAN_SUBLIST3R}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain, sessionId }),
        signal: controller.signal
      });

      if (!response.ok) {
        throw new Error(`Sublist3r scan failed: ${response.statusText}`);
      }

      return this.streamResults(sessionId, callback);
    } catch (error: any) {
      this.cleanup(sessionId);
      throw error;
    }
  }

  // Common method to handle WebSocket streaming with better error handling
  private streamResults(sessionId: string, callback?: StreamingCallback): Promise<string> {
    return new Promise((resolve, reject) => {
      let fullOutput = '';
      let resolved = false;

      console.log(`[WS] Connecting to: ${API_CONFIG.WS_URL}/stream/${sessionId}`);
      const ws = new WebSocket(`${API_CONFIG.WS_URL}/stream/${sessionId}`);
      this.wsConnections.set(sessionId, ws);

      // Set timeout for WebSocket connection (10 minutes for long scans)
      const timeout = setTimeout(() => {
        if (!resolved) {
          resolved = true;
          console.error(`[WS] Connection timeout for session: ${sessionId}`);
          this.cleanup(sessionId);
          reject(new Error('WebSocket connection timeout (10min). Scan may be taking longer than expected.'));
        }
      }, 600000); // 10 minute timeout for long-running scans

      ws.onopen = () => {
        console.log(`[WS] ✓ Connected: ${sessionId}`);
        callback?.onOutput?.('● Connected to backend scan server...\n');
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          console.log(`[WS] Message type: ${data.type}`);
          
          switch (data.type) {
            case 'output':
              fullOutput += data.content;
              callback?.onOutput?.(data.content);
              break;
            case 'progress':
              callback?.onProgress?.(data.progress);
              break;
            case 'complete':
              if (!resolved) {
                resolved = true;
                clearTimeout(timeout);
                console.log(`[WS] ✓ Scan complete: ${sessionId}`);
                resolve(fullOutput);
                this.cleanup(sessionId);
                callback?.onComplete?.(data.result);
              }
              break;
            case 'error':
              if (!resolved) {
                resolved = true;
                clearTimeout(timeout);
                console.error(`[WS] Scan error: ${data.message}`);
                reject(new Error(data.message));
                this.cleanup(sessionId);
                callback?.onError?.(data.message);
              }
              break;
          }
        } catch (error) {
          console.error('[WS] Error parsing message:', error);
          callback?.onError?.('Error parsing server response');
        }
      };

      ws.onerror = (error) => {
        console.error('[WS] Connection error:', error);
        if (!resolved) {
          resolved = true;
          clearTimeout(timeout);
          reject(new Error('WebSocket connection failed. Ensure backend is running: cd server && node index.js'));
          this.cleanup(sessionId);
        }
      };

      ws.onclose = (event) => {
        console.log(`[WS] Connection closed: ${sessionId} (code: ${event.code})`);
        if (!resolved) {
          resolved = true;
          clearTimeout(timeout);
          this.cleanup(sessionId);
          reject(new Error(`Connection closed by server (code: ${event.code})`));
        }
      };
    });
  }

  // Stop a specific scan
  stopScan(sessionId: string): void {
    const controller = this.activeSessions.get(sessionId);
    if (controller) {
      controller.abort();
    }
    this.cleanup(sessionId);
  }

  // Stop all running scans
  stopAllScans(): void {
    for (const [sessionId, controller] of this.activeSessions) {
      controller.abort();
      this.cleanup(sessionId);
    }
  }

  // Get count of active scans
  getActiveSessionCount(): number {
    return this.activeSessions.size;
  }

  // Cleanup session resources
  private cleanup(sessionId: string): void {
    this.activeSessions.delete(sessionId);
    
    const ws = this.wsConnections.get(sessionId);
    if (ws) {
      ws.close();
      this.wsConnections.delete(sessionId);
    }
  }

  // Generate comprehensive report
  async generateReport(scanResults: ScanResult[]): Promise<string> {
    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}/api/reports/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scanResults })
      });

      if (!response.ok) {
        throw new Error('Failed to generate report');
      }

      return await response.text();
    } catch (error: any) {
      throw new Error(`Report generation failed: ${error.message}`);
    }
  }

  // Advanced Tool: Masscan (Fast Port Scanner)
  async runMasscanScan(target: string, ports: string = '1-65535', rate: string = '1000', callback?: StreamingCallback): Promise<string> {
    const sessionId = `masscan-${Date.now()}`;
    const controller = new AbortController();
    this.activeSessions.set(sessionId, controller);

    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.SCAN_MASSCAN}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, ports, rate, sessionId }),
        signal: controller.signal
      });

      if (!response.ok) {
        throw new Error(`Masscan scan failed: ${response.statusText}`);
      }

      return this.streamResults(sessionId, callback);
    } catch (error: any) {
      this.cleanup(sessionId);
      throw error;
    }
  }

  // Advanced Tool: Hydra (Password Cracking)
  async runHydraScan(target: string, service: string, usernameList?: string, passwordList?: string, callback?: StreamingCallback): Promise<string> {
    const sessionId = `hydra-${Date.now()}`;
    const controller = new AbortController();
    this.activeSessions.set(sessionId, controller);

    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.SCAN_HYDRA}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, service, usernameList, passwordList, sessionId }),
        signal: controller.signal
      });

      if (!response.ok) {
        throw new Error(`Hydra scan failed: ${response.statusText}`);
      }

      return this.streamResults(sessionId, callback);
    } catch (error: any) {
      this.cleanup(sessionId);
      throw error;
    }
  }

  // Advanced Tool: WPScan (WordPress Scanner)
  async runWPScan(target: string, apiToken?: string, callback?: StreamingCallback): Promise<string> {
    const sessionId = `wpscan-${Date.now()}`;
    const controller = new AbortController();
    this.activeSessions.set(sessionId, controller);

    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.SCAN_WPSCAN}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, apiToken, sessionId }),
        signal: controller.signal
      });

      if (!response.ok) {
        throw new Error(`WPScan failed: ${response.statusText}`);
      }

      return this.streamResults(sessionId, callback);
    } catch (error: any) {
      this.cleanup(sessionId);
      throw error;
    }
  }

  // Advanced Tool: Enum4linux (SMB Enumeration)
  async runEnum4linuxScan(target: string, callback?: StreamingCallback): Promise<string> {
    const sessionId = `enum4linux-${Date.now()}`;
    const controller = new AbortController();
    this.activeSessions.set(sessionId, controller);

    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.SCAN_ENUM4LINUX}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, sessionId }),
        signal: controller.signal
      });

      if (!response.ok) {
        throw new Error(`Enum4linux scan failed: ${response.statusText}`);
      }

      return this.streamResults(sessionId, callback);
    } catch (error: any) {
      this.cleanup(sessionId);
      throw error;
    }
  }

  // Advanced Tool: theHarvester (OSINT)
  async runTheHarvester(domain: string, sources?: string, callback?: StreamingCallback): Promise<string> {
    const sessionId = `theharvester-${Date.now()}`;
    const controller = new AbortController();
    this.activeSessions.set(sessionId, controller);

    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.SCAN_THEHARVESTER}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain, sources, sessionId }),
        signal: controller.signal
      });

      if (!response.ok) {
        throw new Error(`theHarvester scan failed: ${response.statusText}`);
      }

      return this.streamResults(sessionId, callback);
    } catch (error: any) {
      this.cleanup(sessionId);
      throw error;
    }
  }

  // Advanced Tool: SSLyze (SSL/TLS Analysis)
  async runSSLyze(target: string, callback?: StreamingCallback): Promise<string> {
    const sessionId = `sslyze-${Date.now()}`;
    const controller = new AbortController();
    this.activeSessions.set(sessionId, controller);

    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.SCAN_SSLYZE}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, sessionId }),
        signal: controller.signal
      });

      if (!response.ok) {
        throw new Error(`SSLyze scan failed: ${response.statusText}`);
      }

      return this.streamResults(sessionId, callback);
    } catch (error: any) {
      this.cleanup(sessionId);
      throw error;
    }
  }

  // Advanced Tool: Wafw00f (WAF Detection)
  async runWafw00f(target: string, callback?: StreamingCallback): Promise<string> {
    const sessionId = `wafw00f-${Date.now()}`;
    const controller = new AbortController();
    this.activeSessions.set(sessionId, controller);

    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.SCAN_WAFW00F}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, sessionId }),
        signal: controller.signal
      });

      if (!response.ok) {
        throw new Error(`Wafw00f scan failed: ${response.statusText}`);
      }

      return this.streamResults(sessionId, callback);
    } catch (error: any) {
      this.cleanup(sessionId);
      throw error;
    }
  }

  // Advanced Tool: Wapiti (Web Vulnerability Scanner)
  async runWapiti(target: string, callback?: StreamingCallback): Promise<string> {
    const sessionId = `wapiti-${Date.now()}`;
    const controller = new AbortController();
    this.activeSessions.set(sessionId, controller);

    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.SCAN_WAPITI}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, sessionId }),
        signal: controller.signal
      });

      if (!response.ok) {
        throw new Error(`Wapiti scan failed: ${response.statusText}`);
      }

      return this.streamResults(sessionId, callback);
    } catch (error: any) {
      this.cleanup(sessionId);
      throw error;
    }
  }

  // Advanced Tool: Commix (Command Injection)
  async runCommix(target: string, callback?: StreamingCallback): Promise<string> {
    const sessionId = `commix-${Date.now()}`;
    const controller = new AbortController();
    this.activeSessions.set(sessionId, controller);

    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.SCAN_COMMIX}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, sessionId }),
        signal: controller.signal
      });

      if (!response.ok) {
        throw new Error(`Commix scan failed: ${response.statusText}`);
      }

      return this.streamResults(sessionId, callback);
    } catch (error: any) {
      this.cleanup(sessionId);
      throw error;
    }
  }

  // Advanced Tool: XSStrike (XSS Scanner)
  async runXSStrike(target: string, callback?: StreamingCallback): Promise<string> {
    const sessionId = `xsstrike-${Date.now()}`;
    const controller = new AbortController();
    this.activeSessions.set(sessionId, controller);

    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.SCAN_XSSTRIKE}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, sessionId }),
        signal: controller.signal
      });

      if (!response.ok) {
        throw new Error(`XSStrike scan failed: ${response.statusText}`);
      }

      return this.streamResults(sessionId, callback);
    } catch (error: any) {
      this.cleanup(sessionId);
      throw error;
    }
  }

  // Advanced Tool: Dnsenum (DNS Enumeration)
  async runDnsenum(domain: string, callback?: StreamingCallback): Promise<string> {
    const sessionId = `dnsenum-${Date.now()}`;
    const controller = new AbortController();
    this.activeSessions.set(sessionId, controller);

    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.SCAN_DNSENUM}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain, sessionId }),
        signal: controller.signal
      });

      if (!response.ok) {
        throw new Error(`Dnsenum scan failed: ${response.statusText}`);
      }

      return this.streamResults(sessionId, callback);
    } catch (error: any) {
      this.cleanup(sessionId);
      throw error;
    }
  }

  // Advanced Tool: Fierce (DNS Reconnaissance)
  async runFierce(domain: string, callback?: StreamingCallback): Promise<string> {
    const sessionId = `fierce-${Date.now()}`;
    const controller = new AbortController();
    this.activeSessions.set(sessionId, controller);

    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.SCAN_FIERCE}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain, sessionId }),
        signal: controller.signal
      });

      if (!response.ok) {
        throw new Error(`Fierce scan failed: ${response.statusText}`);
      }

      return this.streamResults(sessionId, callback);
    } catch (error: any) {
      this.cleanup(sessionId);
      throw error;
    }
  }

  // Advanced Tool: CrackMapExec (Network Pentesting)
  async runCrackMapExec(target: string, protocol: string = 'smb', username?: string, password?: string, callback?: StreamingCallback): Promise<string> {
    const sessionId = `crackmapexec-${Date.now()}`;
    const controller = new AbortController();
    this.activeSessions.set(sessionId, controller);

    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.SCAN_CRACKMAPEXEC}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, protocol, username, password, sessionId }),
        signal: controller.signal
      });

      if (!response.ok) {
        throw new Error(`CrackMapExec scan failed: ${response.statusText}`);
      }

      return this.streamResults(sessionId, callback);
    } catch (error: any) {
      this.cleanup(sessionId);
      throw error;
    }
  }

  // Advanced Tool: Metasploit
  async runMetasploit(commands: string[], callback?: StreamingCallback): Promise<string> {
    const sessionId = `metasploit-${Date.now()}`;
    const controller = new AbortController();
    this.activeSessions.set(sessionId, controller);

    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.SCAN_METASPLOIT}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ commands, sessionId }),
        signal: controller.signal
      });

      if (!response.ok) {
        throw new Error(`Metasploit failed: ${response.statusText}`);
      }

      return this.streamResults(sessionId, callback);
    } catch (error: any) {
      this.cleanup(sessionId);
      throw error;
    }
  }

  // Advanced Tool: John the Ripper
  async runJohn(hashFile: string, wordlist?: string, format?: string, callback?: StreamingCallback): Promise<string> {
    const sessionId = `john-${Date.now()}`;
    const controller = new AbortController();
    this.activeSessions.set(sessionId, controller);

    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.SCAN_JOHN}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hashFile, wordlist, format, sessionId }),
        signal: controller.signal
      });

      if (!response.ok) {
        throw new Error(`John scan failed: ${response.statusText}`);
      }

      return this.streamResults(sessionId, callback);
    } catch (error: any) {
      this.cleanup(sessionId);
      throw error;
    }
  }

  // Advanced Tool: Hashcat
  async runHashcat(hashFile: string, wordlist?: string, mode: string = '0', callback?: StreamingCallback): Promise<string> {
    const sessionId = `hashcat-${Date.now()}`;
    const controller = new AbortController();
    this.activeSessions.set(sessionId, controller);

    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.SCAN_HASHCAT}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hashFile, wordlist, mode, sessionId }),
        signal: controller.signal
      });

      if (!response.ok) {
        throw new Error(`Hashcat scan failed: ${response.statusText}`);
      }

      return this.streamResults(sessionId, callback);
    } catch (error: any) {
      this.cleanup(sessionId);
      throw error;
    }
  }

  // Advanced Tool: Recon-ng
  async runReconng(target: string, modules: string, workspace?: string, callback?: StreamingCallback): Promise<string> {
    const sessionId = `reconng-${Date.now()}`;
    const controller = new AbortController();
    this.activeSessions.set(sessionId, controller);

    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.SCAN_RECONNG}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, modules, workspace, sessionId }),
        signal: controller.signal
      });

      if (!response.ok) {
        throw new Error(`Recon-ng failed: ${response.statusText}`);
      }

      return this.streamResults(sessionId, callback);
    } catch (error: any) {
      this.cleanup(sessionId);
      throw error;
    }
  }

  // ============================================================================
  // WebHackersWeapons Tools Integration
  // ============================================================================

  // Subfinder - Fast subdomain enumeration
  async runSubfinderScan(domain: string, callback?: StreamingCallback): Promise<string> {
    const sessionId = `subfinder-${Date.now()}`;
    const controller = new AbortController();
    this.activeSessions.set(sessionId, controller);

    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.SCAN_SUBFINDER}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain, sessionId }),
        signal: controller.signal
      });

      if (!response.ok) throw new Error(`Subfinder failed: ${response.statusText}`);
      return this.streamResults(sessionId, callback);
    } catch (error: any) {
      this.cleanup(sessionId);
      throw error;
    }
  }

  // httpx - HTTP probing toolkit
  async runHttpxScan(target: string, callback?: StreamingCallback): Promise<string> {
    const sessionId = `httpx-${Date.now()}`;
    const controller = new AbortController();
    this.activeSessions.set(sessionId, controller);

    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.SCAN_HTTPX}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, sessionId }),
        signal: controller.signal
      });

      if (!response.ok) throw new Error(`httpx failed: ${response.statusText}`);
      return this.streamResults(sessionId, callback);
    } catch (error: any) {
      this.cleanup(sessionId);
      throw error;
    }
  }

  // Katana - Modern web crawler
  async runKatanaScan(target: string, callback?: StreamingCallback): Promise<string> {
    const sessionId = `katana-${Date.now()}`;
    const controller = new AbortController();
    this.activeSessions.set(sessionId, controller);

    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.SCAN_KATANA}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, sessionId }),
        signal: controller.signal
      });

      if (!response.ok) throw new Error(`Katana failed: ${response.statusText}`);
      return this.streamResults(sessionId, callback);
    } catch (error: any) {
      this.cleanup(sessionId);
      throw error;
    }
  }

  // Dalfox - XSS scanner
  async runDalfoxScan(target: string, callback?: StreamingCallback): Promise<string> {
    const sessionId = `dalfox-${Date.now()}`;
    const controller = new AbortController();
    this.activeSessions.set(sessionId, controller);

    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.SCAN_DALFOX}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, sessionId }),
        signal: controller.signal
      });

      if (!response.ok) throw new Error(`Dalfox failed: ${response.statusText}`);
      return this.streamResults(sessionId, callback);
    } catch (error: any) {
      this.cleanup(sessionId);
      throw error;
    }
  }

  // GAU - GetAllUrls
  async runGauScan(domain: string, callback?: StreamingCallback): Promise<string> {
    const sessionId = `gau-${Date.now()}`;
    const controller = new AbortController();
    this.activeSessions.set(sessionId, controller);

    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.SCAN_GAU}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain, sessionId }),
        signal: controller.signal
      });

      if (!response.ok) throw new Error(`GAU failed: ${response.statusText}`);
      return this.streamResults(sessionId, callback);
    } catch (error: any) {
      this.cleanup(sessionId);
      throw error;
    }
  }

  // FFUF - Fast web fuzzer
  async runFfufScan(target: string, callback?: StreamingCallback): Promise<string> {
    const sessionId = `ffuf-${Date.now()}`;
    const controller = new AbortController();
    this.activeSessions.set(sessionId, controller);

    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.SCAN_FFUF}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, sessionId }),
        signal: controller.signal
      });

      if (!response.ok) throw new Error(`FFUF failed: ${response.statusText}`);
      return this.streamResults(sessionId, callback);
    } catch (error: any) {
      this.cleanup(sessionId);
      throw error;
    }
  }

  // Arjun - Parameter discovery
  async runArjunScan(target: string, callback?: StreamingCallback): Promise<string> {
    const sessionId = `arjun-${Date.now()}`;
    const controller = new AbortController();
    this.activeSessions.set(sessionId, controller);

    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.SCAN_ARJUN}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, sessionId }),
        signal: controller.signal
      });

      if (!response.ok) throw new Error(`Arjun failed: ${response.statusText}`);
      return this.streamResults(sessionId, callback);
    } catch (error: any) {
      this.cleanup(sessionId);
      throw error;
    }
  }

  // ParamSpider - Parameter mining
  async runParamspiderScan(domain: string, callback?: StreamingCallback): Promise<string> {
    const sessionId = `paramspider-${Date.now()}`;
    const controller = new AbortController();
    this.activeSessions.set(sessionId, controller);

    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.SCAN_PARAMSPIDER}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain, sessionId }),
        signal: controller.signal
      });

      if (!response.ok) throw new Error(`ParamSpider failed: ${response.statusText}`);
      return this.streamResults(sessionId, callback);
    } catch (error: any) {
      this.cleanup(sessionId);
      throw error;
    }
  }

  // Waybackurls - Wayback Machine URLs
  async runWaybackurlsScan(domain: string, callback?: StreamingCallback): Promise<string> {
    const sessionId = `waybackurls-${Date.now()}`;
    const controller = new AbortController();
    this.activeSessions.set(sessionId, controller);

    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.SCAN_WAYBACKURLS}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain, sessionId }),
        signal: controller.signal
      });

      if (!response.ok) throw new Error(`Waybackurls failed: ${response.statusText}`);
      return this.streamResults(sessionId, callback);
    } catch (error: any) {
      this.cleanup(sessionId);
      throw error;
    }
  }

  // Hakrawler - Simple web crawler
  async runHakrawlerScan(target: string, callback?: StreamingCallback): Promise<string> {
    const sessionId = `hakrawler-${Date.now()}`;
    const controller = new AbortController();
    this.activeSessions.set(sessionId, controller);

    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.SCAN_HAKRAWLER}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, sessionId }),
        signal: controller.signal
      });

      if (!response.ok) throw new Error(`Hakrawler failed: ${response.statusText}`);
      return this.streamResults(sessionId, callback);
    } catch (error: any) {
      this.cleanup(sessionId);
      throw error;
    }
  }

  // Assetfinder - Asset discovery
  async runAssetfinderScan(domain: string, callback?: StreamingCallback): Promise<string> {
    const sessionId = `assetfinder-${Date.now()}`;
    const controller = new AbortController();
    this.activeSessions.set(sessionId, controller);

    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.SCAN_ASSETFINDER}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain, sessionId }),
        signal: controller.signal
      });

      if (!response.ok) throw new Error(`Assetfinder failed: ${response.statusText}`);
      return this.streamResults(sessionId, callback);
    } catch (error: any) {
      this.cleanup(sessionId);
      throw error;
    }
  }

  // LinkFinder - JS endpoint discovery
  async runLinkfinderScan(url: string, callback?: StreamingCallback): Promise<string> {
    const sessionId = `linkfinder-${Date.now()}`;
    const controller = new AbortController();
    this.activeSessions.set(sessionId, controller);

    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.SCAN_LINKFINDER}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, sessionId }),
        signal: controller.signal
      });

      if (!response.ok) throw new Error(`LinkFinder failed: ${response.statusText}`);
      return this.streamResults(sessionId, callback);
    } catch (error: any) {
      this.cleanup(sessionId);
      throw error;
    }
  }

  // SecretFinder - JS secret scanner
  async runSecretfinderScan(url: string, callback?: StreamingCallback): Promise<string> {
    const sessionId = `secretfinder-${Date.now()}`;
    const controller = new AbortController();
    this.activeSessions.set(sessionId, controller);

    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.SCAN_SECRETFINDER}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, sessionId }),
        signal: controller.signal
      });

      if (!response.ok) throw new Error(`SecretFinder failed: ${response.statusText}`);
      return this.streamResults(sessionId, callback);
    } catch (error: any) {
      this.cleanup(sessionId);
      throw error;
    }
  }

  // Gitleaks - Git secret scanner
  async runGitleaksScan(repo: string, callback?: StreamingCallback): Promise<string> {
    const sessionId = `gitleaks-${Date.now()}`;
    const controller = new AbortController();
    this.activeSessions.set(sessionId, controller);

    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.SCAN_GITLEAKS}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repo, sessionId }),
        signal: controller.signal
      });

      if (!response.ok) throw new Error(`Gitleaks failed: ${response.statusText}`);
      return this.streamResults(sessionId, callback);
    } catch (error: any) {
      this.cleanup(sessionId);
      throw error;
    }
  }

  // RustScan - Ultra-fast port scanner
  async runRustscanScan(target: string, callback?: StreamingCallback): Promise<string> {
    const sessionId = `rustscan-${Date.now()}`;
    const controller = new AbortController();
    this.activeSessions.set(sessionId, controller);

    try {
      const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.SCAN_RUSTSCAN}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, sessionId }),
        signal: controller.signal
      });

      if (!response.ok) throw new Error(`RustScan failed: ${response.statusText}`);
      return this.streamResults(sessionId, callback);
    } catch (error: any) {
      this.cleanup(sessionId);
      throw error;
    }
  }

  // Run automated scan sequence (sequential to avoid system overload)
  async runAutomatedScan(config: AutomatedScanConfig): Promise<void> {
    const {
      target,
      scanTypes = ['nmap', 'whatweb', 'nikto', 'nuclei', 'gobuster', 'sqlmap', 'amass', 'sublist3r'],
      onProgress,
      onToolComplete,
    } = config;

    const totalTools = scanTypes.length;
    let completedTools = 0;

    // Helper: strip protocol/path for domain-focused tools
    const toDomain = (t: string) => t.replace(/^https?:\/\//, '').split('/')[0];

    // Run tools sequentially to prevent system overload
    for (const toolType of scanTypes) {
      const startedAt = new Date();
      let result;

      try {
        console.log(`Starting ${toolType} scan on ${target}...`);
        
        switch (toolType) {
          case 'nmap':
            const nmapOutput = await this.runNmapScan(target, 'comprehensive');
            result = { toolType, status: 'completed' as const, output: nmapOutput, startTime: startedAt };
            break;
          case 'nikto':
            const niktoOutput = await this.runNiktoScan(target);
            result = { toolType, status: 'completed' as const, output: niktoOutput, startTime: startedAt };
            break;
          case 'nuclei':
            const nucleiOutput = await this.runNucleiScan(target);
            result = { toolType, status: 'completed' as const, output: nucleiOutput, startTime: startedAt };
            break;
          case 'whatweb':
            const whatwebOutput = await this.runWhatWebScan(target);
            result = { toolType, status: 'completed' as const, output: whatwebOutput, startTime: startedAt };
            break;
          case 'gobuster':
            const gobusterOutput = await this.runGobusterScan(target);
            result = { toolType, status: 'completed' as const, output: gobusterOutput, startTime: startedAt };
            break;
          case 'sqlmap':
            const sqlmapOutput = await this.runSQLMapScan(target);
            result = { toolType, status: 'completed' as const, output: sqlmapOutput, startTime: startedAt };
            break;
          case 'amass': {
            const domain = toDomain(target);
            const amassOutput = await this.runAmassEnum(domain);
            result = { toolType, status: 'completed' as const, output: amassOutput, startTime: startedAt };
            break;
          }
          case 'sublist3r': {
            const domain = toDomain(target);
            const sublist3rOutput = await this.runSublist3rScan(domain);
            result = { toolType, status: 'completed' as const, output: sublist3rOutput, startTime: startedAt };
            break;
          }
          default:
            result = { toolType, status: 'failed' as const, output: 'Unsupported tool', startTime: startedAt };
        }
      } catch (error: any) {
        console.error(`Error running ${toolType}:`, error);
        result = { toolType, status: 'failed' as const, output: `Error: ${error.message}`, startTime: startedAt };
      }

      // Update progress and notify completion
      completedTools++;
      const progress = (completedTools / totalTools) * 100;
      onProgress?.(progress, result.toolType);
      
      onToolComplete?.({
        id: `${result.toolType}-${Date.now()}`,
        tool: result.toolType,
        target,
        status: result.status,
        progress: result.status === 'completed' ? 100 : 0,
        findings: [],
        output: result.output,
        startTime: result.startTime,
        endTime: new Date(),
      });

      // Small delay between tools to prevent system overload
      if (completedTools < totalTools) {
        await new Promise(resolve => setTimeout(resolve, 2000)); // 2 second delay
      }
    }
  }

  // Run Gitleaks for secret detection in repositories
  async runGitleaks(
    repoUrl: string,
    callback?: StreamingCallback
  ): Promise<{ output: string; findings: any[] }> {
    const sessionId = `gitleaks-${Date.now()}`;
    let output = '';
    const findings: any[] = [];

    try {
      console.log(`[Gitleaks] Starting scan: ${repoUrl} - Session: ${sessionId}`);
      
      const response = await fetch(`${API_CONFIG.BASE_URL}/api/gitleaks`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repoUrl, sessionId })
      });

      if (!response.ok) {
        const errorText = await response.text().catch(() => response.statusText);
        throw new Error(`Gitleaks scan failed: ${errorText}`);
      }

      const result = await response.json();
      output = result.output || '';
      
      // Parse findings from output
      if (result.findings) {
        findings.push(...result.findings);
      }

      callback?.onOutput?.(output);
      callback?.onProgress?.(100);
      callback?.onComplete?.({
        id: sessionId,
        tool: 'gitleaks',
        target: repoUrl,
        status: 'completed',
        progress: 100,
        findings,
        output,
        startTime: new Date()
      });

      return { output, findings };

    } catch (error: any) {
      console.error('[Gitleaks] Error:', error);
      const errorMsg = `Gitleaks error: ${error.message}`;
      callback?.onError?.(errorMsg);
      callback?.onOutput?.(errorMsg);
      return { output: errorMsg, findings: [] };
    }
  }
}