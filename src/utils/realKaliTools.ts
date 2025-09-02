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

  // Common method to handle WebSocket streaming
  private streamResults(sessionId: string, callback?: StreamingCallback): Promise<string> {
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

  // Run automated scan sequence
  async runAutomatedScan(config: AutomatedScanConfig): Promise<void> {
    const { target, scanTypes = ['nmap', 'nikto', 'nuclei', 'whatweb'], onProgress, onToolComplete } = config;
    
    let completedTools = 0;
    const totalTools = scanTypes.length;

    for (const toolType of scanTypes) {
      try {
        let result: string;
        
        switch (toolType) {
          case 'nmap':
            result = await this.runNmapScan(target, 'comprehensive');
            break;
          case 'nikto':
            result = await this.runNiktoScan(target);
            break;
          case 'nuclei':
            result = await this.runNucleiScan(target);
            break;
          case 'whatweb':
            result = await this.runWhatWebScan(target);
            break;
          case 'gobuster':
            result = await this.runGobusterScan(target);
            break;
          case 'amass':
            result = await this.runAmassEnum(target);
            break;
          case 'sublist3r':
            result = await this.runSublist3rScan(target);
            break;
          default:
            continue;
        }

        completedTools++;
        const progress = (completedTools / totalTools) * 100;
        
        onProgress?.(progress, toolType);
        onToolComplete?.({
          id: `${toolType}-${Date.now()}`,
          tool: toolType,
          target,
          status: 'completed',
          progress: 100,
          findings: [],
          output: result,
          startTime: new Date(),
          endTime: new Date()
        });
        
      } catch (error: any) {
        console.error(`${toolType} scan failed:`, error.message);
        onToolComplete?.({
          id: `${toolType}-${Date.now()}`,
          tool: toolType,
          target,
          status: 'failed',
          progress: 0,
          findings: [],
          output: `Error: ${error.message}`,
          startTime: new Date(),
          endTime: new Date()
        });
      }
    }
  }
}