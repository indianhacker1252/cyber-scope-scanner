// Backend API handlers for real Kali tool execution
import { spawn, ChildProcess } from 'child_process';
import { WebSocket } from 'ws';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { join } from 'path';

interface ScanSession {
  id: string;
  process?: ChildProcess;
  ws?: WebSocket;
  tool: string;
  target: string;
  status: 'running' | 'completed' | 'failed';
  output: string;
  startTime: Date;
  endTime?: Date;
}

export class ScanningBackend {
  private sessions = new Map<string, ScanSession>();
  private wsServer?: any; // WebSocket server instance

  // Initialize WebSocket server for real-time streaming
  initializeWebSocketServer(port: number = 8080) {
    const WebSocketServer = require('ws').Server;
    this.wsServer = new WebSocketServer({ port });
    
    this.wsServer.on('connection', (ws: WebSocket, req: any) => {
      const sessionId = req.url?.split('/').pop();
      if (sessionId && this.sessions.has(sessionId)) {
        const session = this.sessions.get(sessionId)!;
        session.ws = ws;
        console.log(`WebSocket connected for session: ${sessionId}`);
      }
    });
  }

  // Check if running in Kali Linux
  async checkKaliEnvironment(): Promise<boolean> {
    return new Promise((resolve) => {
      const process = spawn('cat', ['/etc/os-release']);
      let output = '';
      
      process.stdout.on('data', (data) => {
        output += data.toString();
      });
      
      process.on('close', () => {
        resolve(output.includes('Kali') || output.includes('kali'));
      });
      
      process.on('error', () => resolve(false));
    });
  }

  // Get installed security tools
  async getInstalledTools(): Promise<any[]> {
    const tools = [
      { name: 'nmap', command: 'nmap', category: 'network' },
      { name: 'nikto', command: 'nikto', category: 'web' },
      { name: 'sqlmap', command: 'sqlmap', category: 'database' },
      { name: 'gobuster', command: 'gobuster', category: 'enumeration' },
      { name: 'amass', command: 'amass', category: 'reconnaissance' },
      { name: 'nuclei', command: 'nuclei', category: 'vulnerability' },
      { name: 'whatweb', command: 'whatweb', category: 'reconnaissance' },
      { name: 'sublist3r', command: 'sublist3r', category: 'reconnaissance' },
      { name: 'dirb', command: 'dirb', category: 'enumeration' },
      { name: 'ffuf', command: 'ffuf', category: 'enumeration' }
    ];

    const installedTools = [];
    
    for (const tool of tools) {
      try {
        const installed = await this.checkToolInstalled(tool.command);
        installedTools.push({
          ...tool,
          installed,
          version: installed ? await this.getToolVersion(tool.command) : null
        });
      } catch (error) {
        installedTools.push({ ...tool, installed: false, version: null });
      }
    }

    return installedTools;
  }

  // Check if a tool is installed
  private async checkToolInstalled(command: string): Promise<boolean> {
    return new Promise((resolve) => {
      const process = spawn('which', [command]);
      process.on('close', (code) => resolve(code === 0));
      process.on('error', () => resolve(false));
    });
  }

  // Get tool version
  private async getToolVersion(command: string): Promise<string> {
    return new Promise((resolve) => {
      const process = spawn(command, ['--version']);
      let output = '';
      
      process.stdout.on('data', (data) => {
        output += data.toString();
      });
      
      process.on('close', () => {
        const versionMatch = output.match(/\d+\.\d+(\.\d+)?/);
        resolve(versionMatch ? versionMatch[0] : 'unknown');
      });
      
      process.on('error', () => resolve('unknown'));
    });
  }

  // Execute Nmap scan
  async executeNmapScan(target: string, scanType: string, sessionId: string): Promise<void> {
    const scanArgs = this.buildNmapArgs(target, scanType);
    const session: ScanSession = {
      id: sessionId,
      tool: 'nmap',
      target,
      status: 'running',
      output: '',
      startTime: new Date()
    };

    this.sessions.set(sessionId, session);
    
    try {
      const process = spawn('nmap', scanArgs);
      session.process = process;

      process.stdout.on('data', (data) => {
        const output = data.toString();
        session.output += output;
        this.streamOutput(sessionId, output, 'output');
      });

      process.stderr.on('data', (data) => {
        const error = data.toString();
        session.output += error;
        this.streamOutput(sessionId, error, 'error');
      });

      process.on('close', (code) => {
        session.status = code === 0 ? 'completed' : 'failed';
        session.endTime = new Date();
        
        this.streamOutput(sessionId, '', 'complete', {
          result: {
            id: sessionId,
            tool: 'nmap',
            target,
            status: session.status,
            output: session.output,
            findings: this.parseNmapOutput(session.output)
          }
        });
      });

    } catch (error: any) {
      session.status = 'failed';
      session.endTime = new Date();
      this.streamOutput(sessionId, error.message, 'error');
    }
  }

  // Execute Nikto scan
  async executeNiktoScan(target: string, sessionId: string): Promise<void> {
    const session: ScanSession = {
      id: sessionId,
      tool: 'nikto',
      target,
      status: 'running',
      output: '',
      startTime: new Date()
    };

    this.sessions.set(sessionId, session);
    
    try {
      const process = spawn('nikto', ['-h', target, '-Format', 'txt']);
      session.process = process;

      process.stdout.on('data', (data) => {
        const output = data.toString();
        session.output += output;
        this.streamOutput(sessionId, output, 'output');
      });

      process.stderr.on('data', (data) => {
        const error = data.toString();
        session.output += error;
        this.streamOutput(sessionId, error, 'error');
      });

      process.on('close', (code) => {
        session.status = code === 0 ? 'completed' : 'failed';
        session.endTime = new Date();
        
        this.streamOutput(sessionId, '', 'complete', {
          result: {
            id: sessionId,
            tool: 'nikto',
            target,
            status: session.status,
            output: session.output,
            findings: this.parseNiktoOutput(session.output)
          }
        });
      });

    } catch (error: any) {
      session.status = 'failed';
      session.endTime = new Date();
      this.streamOutput(sessionId, error.message, 'error');
    }
  }

  // Execute SQLMap scan
  async executeSQLMapScan(target: string, options: string, sessionId: string): Promise<void> {
    const args = ['-u', target, '--batch', '--random-agent'];
    if (options) {
      args.push(...options.split(' '));
    }

    const session: ScanSession = {
      id: sessionId,
      tool: 'sqlmap',
      target,
      status: 'running',
      output: '',
      startTime: new Date()
    };

    this.sessions.set(sessionId, session);
    
    try {
      const process = spawn('sqlmap', args);
      session.process = process;

      process.stdout.on('data', (data) => {
        const output = data.toString();
        session.output += output;
        this.streamOutput(sessionId, output, 'output');
      });

      process.stderr.on('data', (data) => {
        const error = data.toString();
        session.output += error;
        this.streamOutput(sessionId, error, 'error');
      });

      process.on('close', (code) => {
        session.status = code === 0 ? 'completed' : 'failed';
        session.endTime = new Date();
        
        this.streamOutput(sessionId, '', 'complete', {
          result: {
            id: sessionId,
            tool: 'sqlmap',
            target,
            status: session.status,
            output: session.output,
            findings: this.parseSQLMapOutput(session.output)
          }
        });
      });

    } catch (error: any) {
      session.status = 'failed';
      session.endTime = new Date();
      this.streamOutput(sessionId, error.message, 'error');
    }
  }

  // Execute Gobuster scan
  async executeGobusterScan(target: string, wordlist: string, sessionId: string): Promise<void> {
    const wordlistPath = wordlist || '/usr/share/wordlists/dirb/common.txt';
    const args = ['dir', '-u', target, '-w', wordlistPath, '-t', '50'];

    const session: ScanSession = {
      id: sessionId,
      tool: 'gobuster',
      target,
      status: 'running',
      output: '',
      startTime: new Date()
    };

    this.sessions.set(sessionId, session);
    
    try {
      const process = spawn('gobuster', args);
      session.process = process;

      process.stdout.on('data', (data) => {
        const output = data.toString();
        session.output += output;
        this.streamOutput(sessionId, output, 'output');
      });

      process.stderr.on('data', (data) => {
        const error = data.toString();
        session.output += error;
        this.streamOutput(sessionId, error, 'error');
      });

      process.on('close', (code) => {
        session.status = code === 0 ? 'completed' : 'failed';
        session.endTime = new Date();
        
        this.streamOutput(sessionId, '', 'complete', {
          result: {
            id: sessionId,
            tool: 'gobuster',
            target,
            status: session.status,
            output: session.output,
            findings: this.parseGobusterOutput(session.output)
          }
        });
      });

    } catch (error: any) {
      session.status = 'failed';
      session.endTime = new Date();
      this.streamOutput(sessionId, error.message, 'error');
    }
  }

  // Execute Nuclei scan
  async executeNucleiScan(target: string, templates: string, sessionId: string): Promise<void> {
    const args = ['-u', target, '-json'];
    if (templates) {
      args.push('-t', templates);
    }

    const session: ScanSession = {
      id: sessionId,
      tool: 'nuclei',
      target,
      status: 'running',
      output: '',
      startTime: new Date()
    };

    this.sessions.set(sessionId, session);
    
    try {
      const process = spawn('nuclei', args);
      session.process = process;

      process.stdout.on('data', (data) => {
        const output = data.toString();
        session.output += output;
        this.streamOutput(sessionId, output, 'output');
      });

      process.stderr.on('data', (data) => {
        const error = data.toString();
        session.output += error;
        this.streamOutput(sessionId, error, 'error');
      });

      process.on('close', (code) => {
        session.status = code === 0 ? 'completed' : 'failed';
        session.endTime = new Date();
        
        this.streamOutput(sessionId, '', 'complete', {
          result: {
            id: sessionId,
            tool: 'nuclei',
            target,
            status: session.status,
            output: session.output,
            findings: this.parseNucleiOutput(session.output)
          }
        });
      });

    } catch (error: any) {
      session.status = 'failed';
      session.endTime = new Date();
      this.streamOutput(sessionId, error.message, 'error');
    }
  }

  // Execute WhatWeb scan
  async executeWhatWebScan(target: string, sessionId: string): Promise<void> {
    const args = [target, '--color=never', '--log-json=/tmp/whatweb.json'];

    const session: ScanSession = {
      id: sessionId,
      tool: 'whatweb',
      target,
      status: 'running',
      output: '',
      startTime: new Date()
    };

    this.sessions.set(sessionId, session);
    
    try {
      const process = spawn('whatweb', args);
      session.process = process;

      process.stdout.on('data', (data) => {
        const output = data.toString();
        session.output += output;
        this.streamOutput(sessionId, output, 'output');
      });

      process.stderr.on('data', (data) => {
        const error = data.toString();
        session.output += error;
        this.streamOutput(sessionId, error, 'error');
      });

      process.on('close', (code) => {
        session.status = code === 0 ? 'completed' : 'failed';
        session.endTime = new Date();
        
        this.streamOutput(sessionId, '', 'complete', {
          result: {
            id: sessionId,
            tool: 'whatweb',
            target,
            status: session.status,
            output: session.output,
            findings: this.parseWhatWebOutput(session.output)
          }
        });
      });

    } catch (error: any) {
      session.status = 'failed';
      session.endTime = new Date();
      this.streamOutput(sessionId, error.message, 'error');
    }
  }

  // Execute Sublist3r scan
  async executeSublist3rScan(domain: string, sessionId: string): Promise<void> {
    const args = ['-d', domain, '-v'];

    const session: ScanSession = {
      id: sessionId,
      tool: 'sublist3r',
      target: domain,
      status: 'running',
      output: '',
      startTime: new Date()
    };

    this.sessions.set(sessionId, session);
    
    try {
      const process = spawn('sublist3r', args);
      session.process = process;

      process.stdout.on('data', (data) => {
        const output = data.toString();
        session.output += output;
        this.streamOutput(sessionId, output, 'output');
      });

      process.stderr.on('data', (data) => {
        const error = data.toString();
        session.output += error;
        this.streamOutput(sessionId, error, 'error');
      });

      process.on('close', (code) => {
        session.status = code === 0 ? 'completed' : 'failed';
        session.endTime = new Date();
        
        this.streamOutput(sessionId, '', 'complete', {
          result: {
            id: sessionId,
            tool: 'sublist3r',
            target: domain,
            status: session.status,
            output: session.output,
            findings: this.parseSublist3rOutput(session.output)
          }
        });
      });

    } catch (error: any) {
      session.status = 'failed';
      session.endTime = new Date();
      this.streamOutput(sessionId, error.message, 'error');
    }
  }

  // Stream output to WebSocket
  private streamOutput(sessionId: string, content: string, type: string, extra?: any): void {
    const session = this.sessions.get(sessionId);
    if (session?.ws && session.ws.readyState === 1) {
      session.ws.send(JSON.stringify({
        type,
        content,
        timestamp: new Date().toISOString(),
        ...extra
      }));
    }
  }

  // Build Nmap arguments based on scan type
  private buildNmapArgs(target: string, scanType: string): string[] {
    const baseArgs = ['-v', target];
    
    switch (scanType) {
      case 'basic':
        return [...baseArgs, '-sS'];
      case 'comprehensive':
        return [...baseArgs, '-sS', '-sV', '-O', '-A', '--script=vuln'];
      case 'stealth':
        return [...baseArgs, '-sS', '-f', '-T2'];
      case 'aggressive':
        return [...baseArgs, '-sS', '-sV', '-O', '-A', '-T4'];
      default:
        return [...baseArgs, '-sS'];
    }
  }

  // Parse Nmap output
  private parseNmapOutput(output: string): any[] {
    const findings = [];
    const lines = output.split('\n');
    
    for (const line of lines) {
      if (line.includes('open')) {
        const portMatch = line.match(/(\d+)\/(\w+)\s+open\s+(\w+)/);
        if (portMatch) {
          findings.push({
            type: 'open_port',
            port: portMatch[1],
            protocol: portMatch[2],
            service: portMatch[3],
            severity: 'info'
          });
        }
      }
      
      if (line.includes('VULNERABLE')) {
        findings.push({
          type: 'vulnerability',
          description: line.trim(),
          severity: 'high'
        });
      }
    }
    
    return findings;
  }

  // Parse Nikto output
  private parseNiktoOutput(output: string): any[] {
    const findings = [];
    const lines = output.split('\n');
    
    for (const line of lines) {
      if (line.includes('+ OSVDB') || line.includes('+ CVE')) {
        findings.push({
          type: 'vulnerability',
          description: line.trim(),
          severity: 'medium'
        });
      }
    }
    
    return findings;
  }

  // Parse SQLMap output
  private parseSQLMapOutput(output: string): any[] {
    const findings = [];
    
    if (output.includes('injectable')) {
      findings.push({
        type: 'sql_injection',
        description: 'SQL injection vulnerability detected',
        severity: 'high'
      });
    }
    
    return findings;
  }

  // Parse Gobuster output
  private parseGobusterOutput(output: string): any[] {
    const findings = [];
    const lines = output.split('\n');
    
    for (const line of lines) {
      if (line.includes('Status: 200')) {
        const pathMatch = line.match(/(\S+)\s+\(Status: 200\)/);
        if (pathMatch) {
          findings.push({
            type: 'directory',
            path: pathMatch[1],
            severity: 'info'
          });
        }
      }
    }
    
    return findings;
  }

  // Parse Nuclei output
  private parseNucleiOutput(output: string): any[] {
    const findings = [];
    const lines = output.split('\n');
    
    for (const line of lines) {
      try {
        const parsed = JSON.parse(line);
        if (parsed.info) {
          findings.push({
            type: 'vulnerability',
            templateId: parsed.templateID,
            name: parsed.info.name,
            severity: parsed.info.severity,
            description: parsed.info.description
          });
        }
      } catch (e) {
        // Skip non-JSON lines
      }
    }
    
    return findings;
  }

  // Parse WhatWeb output
  private parseWhatWebOutput(output: string): any[] {
    const findings = [];
    
    if (output.includes('[')) {
      const techMatches = output.match(/\[([^\]]+)\]/g);
      if (techMatches) {
        for (const match of techMatches) {
          const tech = match.slice(1, -1);
          findings.push({
            type: 'technology',
            name: tech,
            severity: 'info'
          });
        }
      }
    }
    
    return findings;
  }

  // Parse Sublist3r output
  private parseSublist3rOutput(output: string): any[] {
    const findings = [];
    const lines = output.split('\n');
    
    for (const line of lines) {
      if (line.trim() && !line.includes('Starting enumeration') && !line.includes('Total Unique Subdomains Found')) {
        const subdomain = line.trim();
        if (subdomain.includes('.')) {
          findings.push({
            type: 'subdomain',
            name: subdomain,
            severity: 'info'
          });
        }
      }
    }
    
    return findings;
  }

  // Stop a specific scan
  stopScan(sessionId: string): void {
    const session = this.sessions.get(sessionId);
    if (session?.process) {
      session.process.kill('SIGTERM');
      session.status = 'failed';
      session.endTime = new Date();
    }
  }

  // Stop all scans
  stopAllScans(): void {
    for (const [sessionId, session] of this.sessions) {
      if (session.process) {
        session.process.kill('SIGTERM');
        session.status = 'failed';
        session.endTime = new Date();
      }
    }
  }

  // Get session info
  getSession(sessionId: string): ScanSession | undefined {
    return this.sessions.get(sessionId);
  }

  // Get all sessions
  getAllSessions(): ScanSession[] {
    return Array.from(this.sessions.values());
  }
}