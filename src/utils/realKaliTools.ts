// Real Kali Linux Tools Manager - Replaces the mocked version
import { ScanResult, ToolConfig, AutomatedScanConfig } from './kaliTools';
import { API_CONFIG, DEMO_OUTPUTS } from '@/config/apiConfig';

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
      const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.CHECK_KALI}`);
      const result = await response.json();
      return result.isKali;
    } catch {
      console.warn('Backend not available - running in demo mode');
      return false;
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
      const response = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.SCAN_NMAP}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, scanType, sessionId }),
        signal: controller.signal
      });

      if (!response.ok) {
        throw new Error(`Nmap scan failed: ${response.statusText}`);
      }

      // Setup WebSocket for real-time output streaming
      const ws = new WebSocket(`${API_CONFIG.WS_URL}/stream/${sessionId}`);
      this.wsConnections.set(sessionId, ws);

      let fullOutput = '';

      return new Promise((resolve, reject) => {
        ws.onmessage = (event) => {
          const data = JSON.parse(event.data);
          
          switch (data.type) {
            case 'output':
              fullOutput += data.content;
              callback?.onOutput?.(data.content);
              break;
            case 'progress':
              callback?.onProgress?.(data.progress);
              break;
            case 'complete':
              resolve(fullOutput);
              this.cleanup(sessionId);
              callback?.onComplete?.(data.result);
              break;
            case 'error':
              reject(new Error(data.message));
              this.cleanup(sessionId);
              callback?.onError?.(data.message);
              break;
          }
        };

        ws.onerror = () => {
          reject(new Error('WebSocket connection failed'));
          this.cleanup(sessionId);
        };
      });

    } catch (error: any) {
      this.cleanup(sessionId);
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

      const ws = new WebSocket(`${API_CONFIG.WS_URL}/stream/${sessionId}`);
      this.wsConnections.set(sessionId, ws);

      // Set timeout for WebSocket connection
      const timeout = setTimeout(() => {
        if (!resolved) {
          resolved = true;
          this.cleanup(sessionId);
          reject(new Error('WebSocket connection timeout - ensure backend is running'));
        }
      }, 30000); // 30 second timeout

      ws.onopen = () => {
        console.log(`WebSocket connected for session: ${sessionId}`);
        callback?.onOutput?.('Connected to scan server...\n');
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          
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
                resolve(fullOutput);
                this.cleanup(sessionId);
                callback?.onComplete?.(data.result);
              }
              break;
            case 'error':
              if (!resolved) {
                resolved = true;
                clearTimeout(timeout);
                reject(new Error(data.message));
                this.cleanup(sessionId);
                callback?.onError?.(data.message);
              }
              break;
          }
        } catch (error) {
          console.error('Error parsing WebSocket message:', error);
          callback?.onError?.('Error parsing server response');
        }
      };

      ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        if (!resolved) {
          resolved = true;
          clearTimeout(timeout);
          reject(new Error('WebSocket connection failed - ensure backend is running on port 8080'));
          this.cleanup(sessionId);
        }
      };

      ws.onclose = () => {
        console.log(`WebSocket closed for session: ${sessionId}`);
        if (!resolved) {
          resolved = true;
          clearTimeout(timeout);
          this.cleanup(sessionId);
          reject(new Error('Connection closed by server'));
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
}