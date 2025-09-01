#!/usr/bin/env node

const express = require('express');
const { createServer } = require('http');
const { WebSocketServer } = require('ws');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const cors = require('cors');

const app = express();
const server = createServer(app);
const wss = new WebSocketServer({ server });

// Middleware
app.use(cors());
app.use(express.json());

// Active scan sessions
const activeSessions = new Map();
const sessionOutputs = new Map();

// Check if running on Kali Linux
app.get('/api/check-kali', (req, res) => {
  try {
    const isKali = fs.existsSync('/etc/os-release') && 
                   fs.readFileSync('/etc/os-release', 'utf8').includes('Kali GNU/Linux');
    res.json({ isKali });
  } catch (error) {
    res.json({ isKali: false });
  }
});

// Get installed security tools
app.get('/api/tools/installed', (req, res) => {
  const tools = [
    { name: 'nmap', version: '7.94', category: 'Network Discovery', installed: checkTool('nmap') },
    { name: 'nikto', version: '2.5.0', category: 'Web Vulnerability', installed: checkTool('nikto') },
    { name: 'sqlmap', version: '1.7.2', category: 'SQL Injection', installed: checkTool('sqlmap') },
    { name: 'gobuster', version: '3.6', category: 'Directory Enumeration', installed: checkTool('gobuster') },
    { name: 'nuclei', version: '3.0.4', category: 'Vulnerability Scanner', installed: checkTool('nuclei') },
    { name: 'whatweb', version: '0.5.5', category: 'Technology Detection', installed: checkTool('whatweb') },
    { name: 'amass', version: '4.2.0', category: 'Subdomain Enumeration', installed: checkTool('amass') },
    { name: 'sublist3r', version: '1.1', category: 'Subdomain Enumeration', installed: checkTool('sublist3r') }
  ];
  res.json(tools);
});

function checkTool(toolName) {
  try {
    const result = spawn('which', [toolName], { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

// Nmap scan endpoint
app.post('/api/scan/nmap', async (req, res) => {
  const { target, scanType, sessionId } = req.body;
  
  if (!target) {
    return res.status(400).json({ error: 'Target is required' });
  }

  try {
    const nmapArgs = buildNmapArgs(target, scanType);
    console.log(`Starting Nmap scan: nmap ${nmapArgs.join(' ')}`);
    
    const process = spawn('nmap', nmapArgs);
    activeSessions.set(sessionId, process);
    sessionOutputs.set(sessionId, '');

    // Handle process output
    process.stdout.on('data', (data) => {
      const output = data.toString();
      sessionOutputs.set(sessionId, sessionOutputs.get(sessionId) + output);
      broadcastToSession(sessionId, {
        type: 'output',
        content: output
      });
    });

    process.stderr.on('data', (data) => {
      const output = data.toString();
      sessionOutputs.set(sessionId, sessionOutputs.get(sessionId) + output);
      broadcastToSession(sessionId, {
        type: 'output',
        content: output
      });
    });

    process.on('close', (code) => {
      const fullOutput = sessionOutputs.get(sessionId) || '';
      broadcastToSession(sessionId, {
        type: 'complete',
        result: {
          id: sessionId,
          tool: 'nmap',
          target,
          status: code === 0 ? 'completed' : 'failed',
          output: fullOutput,
          findings: parseNmapOutput(fullOutput)
        }
      });
      activeSessions.delete(sessionId);
      sessionOutputs.delete(sessionId);
    });

    res.json({ success: true, sessionId });
  } catch (error) {
    console.error('Nmap scan error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Nikto scan endpoint
app.post('/api/scan/nikto', async (req, res) => {
  const { target, sessionId } = req.body;
  
  try {
    const niktoArgs = ['-h', target, '-Format', 'txt'];
    console.log(`Starting Nikto scan: nikto ${niktoArgs.join(' ')}`);
    
    const process = spawn('nikto', niktoArgs);
    activeSessions.set(sessionId, process);
    sessionOutputs.set(sessionId, '');

    process.stdout.on('data', (data) => {
      const output = data.toString();
      sessionOutputs.set(sessionId, sessionOutputs.get(sessionId) + output);
      broadcastToSession(sessionId, {
        type: 'output',
        content: output
      });
    });

    process.stderr.on('data', (data) => {
      const output = data.toString();
      sessionOutputs.set(sessionId, sessionOutputs.get(sessionId) + output);
      broadcastToSession(sessionId, {
        type: 'output',
        content: output
      });
    });

    process.on('close', (code) => {
      const fullOutput = sessionOutputs.get(sessionId) || '';
      broadcastToSession(sessionId, {
        type: 'complete',
        result: {
          id: sessionId,
          tool: 'nikto',
          target,
          status: code === 0 ? 'completed' : 'failed',
          output: fullOutput,
          findings: parseNiktoOutput(fullOutput)
        }
      });
      activeSessions.delete(sessionId);
      sessionOutputs.delete(sessionId);
    });

    res.json({ success: true, sessionId });
  } catch (error) {
    console.error('Nikto scan error:', error);
    res.status(500).json({ error: error.message });
  }
});

// SQLMap scan endpoint
app.post('/api/scan/sqlmap', async (req, res) => {
  const { target, options, sessionId } = req.body;
  
  try {
    const sqlmapArgs = ['-u', target, '--batch', '--random-agent'];
    if (options) {
      sqlmapArgs.push(...options.split(' '));
    }
    
    console.log(`Starting SQLMap scan: sqlmap ${sqlmapArgs.join(' ')}`);
    
    const process = spawn('sqlmap', sqlmapArgs);
    activeSessions.set(sessionId, process);
    sessionOutputs.set(sessionId, '');

    process.stdout.on('data', (data) => {
      const output = data.toString();
      sessionOutputs.set(sessionId, sessionOutputs.get(sessionId) + output);
      broadcastToSession(sessionId, {
        type: 'output',
        content: output
      });
    });

    process.stderr.on('data', (data) => {
      const output = data.toString();
      sessionOutputs.set(sessionId, sessionOutputs.get(sessionId) + output);
      broadcastToSession(sessionId, {
        type: 'output',
        content: output
      });
    });

    process.on('close', (code) => {
      const fullOutput = sessionOutputs.get(sessionId) || '';
      broadcastToSession(sessionId, {
        type: 'complete',
        result: {
          id: sessionId,
          tool: 'sqlmap',
          target,
          status: code === 0 ? 'completed' : 'failed',
          output: fullOutput,
          findings: parseSQLMapOutput(fullOutput)
        }
      });
      activeSessions.delete(sessionId);
      sessionOutputs.delete(sessionId);
    });

    res.json({ success: true, sessionId });
  } catch (error) {
    console.error('SQLMap scan error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Gobuster scan endpoint
app.post('/api/scan/gobuster', async (req, res) => {
  const { target, wordlist, sessionId } = req.body;
  
  try {
    const wordlistPath = wordlist || '/usr/share/wordlists/dirb/common.txt';
    const gobusterArgs = ['dir', '-u', target, '-w', wordlistPath, '-t', '10'];
    
    console.log(`Starting Gobuster scan: gobuster ${gobusterArgs.join(' ')}`);
    
    const process = spawn('gobuster', gobusterArgs);
    activeSessions.set(sessionId, process);
    sessionOutputs.set(sessionId, '');

    process.stdout.on('data', (data) => {
      const output = data.toString();
      sessionOutputs.set(sessionId, sessionOutputs.get(sessionId) + output);
      broadcastToSession(sessionId, {
        type: 'output',
        content: output
      });
    });

    process.stderr.on('data', (data) => {
      const output = data.toString();
      sessionOutputs.set(sessionId, sessionOutputs.get(sessionId) + output);
      broadcastToSession(sessionId, {
        type: 'output',
        content: output
      });
    });

    process.on('close', (code) => {
      const fullOutput = sessionOutputs.get(sessionId) || '';
      broadcastToSession(sessionId, {
        type: 'complete',
        result: {
          id: sessionId,
          tool: 'gobuster',
          target,
          status: code === 0 ? 'completed' : 'failed',
          output: fullOutput,
          findings: parseGobusterOutput(fullOutput)
        }
      });
      activeSessions.delete(sessionId);
      sessionOutputs.delete(sessionId);
    });

    res.json({ success: true, sessionId });
  } catch (error) {
    console.error('Gobuster scan error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Nuclei scan endpoint
app.post('/api/scan/nuclei', async (req, res) => {
  const { target, templates, sessionId } = req.body;
  
  try {
    const nucleiArgs = ['-target', target, '-v'];
    if (templates) {
      nucleiArgs.push('-t', templates);
    }
    
    console.log(`Starting Nuclei scan: nuclei ${nucleiArgs.join(' ')}`);
    
    const process = spawn('nuclei', nucleiArgs);
    activeSessions.set(sessionId, process);
    sessionOutputs.set(sessionId, '');

    process.stdout.on('data', (data) => {
      const output = data.toString();
      sessionOutputs.set(sessionId, sessionOutputs.get(sessionId) + output);
      broadcastToSession(sessionId, {
        type: 'output',
        content: output
      });
    });

    process.stderr.on('data', (data) => {
      const output = data.toString();
      sessionOutputs.set(sessionId, sessionOutputs.get(sessionId) + output);
      broadcastToSession(sessionId, {
        type: 'output',
        content: output
      });
    });

    process.on('close', (code) => {
      const fullOutput = sessionOutputs.get(sessionId) || '';
      broadcastToSession(sessionId, {
        type: 'complete',
        result: {
          id: sessionId,
          tool: 'nuclei',
          target,
          status: code === 0 ? 'completed' : 'failed',
          output: fullOutput,
          findings: parseNucleiOutput(fullOutput)
        }
      });
      activeSessions.delete(sessionId);
      sessionOutputs.delete(sessionId);
    });

    res.json({ success: true, sessionId });
  } catch (error) {
    console.error('Nuclei scan error:', error);
    res.status(500).json({ error: error.message });
  }
});

// WebSocket connections for real-time streaming
const sessionConnections = new Map();

wss.on('connection', (ws, req) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const sessionId = url.pathname.split('/').pop();
  
  console.log(`WebSocket connected for session: ${sessionId}`);
  
  if (!sessionConnections.has(sessionId)) {
    sessionConnections.set(sessionId, new Set());
  }
  sessionConnections.get(sessionId).add(ws);

  ws.on('close', () => {
    if (sessionConnections.has(sessionId)) {
      sessionConnections.get(sessionId).delete(ws);
      if (sessionConnections.get(sessionId).size === 0) {
        sessionConnections.delete(sessionId);
      }
    }
  });
});

function broadcastToSession(sessionId, message) {
  if (sessionConnections.has(sessionId)) {
    sessionConnections.get(sessionId).forEach(ws => {
      if (ws.readyState === ws.OPEN) {
        ws.send(JSON.stringify(message));
      }
    });
  }
}

// Helper functions
function buildNmapArgs(target, scanType) {
  const baseArgs = ['-v'];
  
  switch (scanType) {
    case 'basic':
      return [...baseArgs, target];
    case 'stealth':
      return [...baseArgs, '-sS', target];
    case 'comprehensive':
      return [...baseArgs, '-sS', '-sV', '-O', '-A', target];
    case 'udp':
      return [...baseArgs, '-sU', '--top-ports', '1000', target];
    default:
      return [...baseArgs, target];
  }
}

function parseNmapOutput(output) {
  const findings = [];
  const lines = output.split('\n');
  
  lines.forEach(line => {
    if (line.includes('/tcp') && line.includes('open')) {
      const parts = line.trim().split(/\s+/);
      findings.push({
        type: 'open_port',
        severity: 'info',
        port: parts[0],
        service: parts[2] || 'unknown',
        description: `Open port: ${parts[0]} (${parts[2] || 'unknown'})`
      });
    }
  });
  
  return findings;
}

function parseNiktoOutput(output) {
  const findings = [];
  const lines = output.split('\n');
  
  lines.forEach(line => {
    if (line.includes('OSVDB') || line.includes('CVE')) {
      findings.push({
        type: 'web_vulnerability',
        severity: 'medium',
        description: line.trim()
      });
    }
  });
  
  return findings;
}

function parseSQLMapOutput(output) {
  const findings = [];
  
  if (output.includes('injectable')) {
    findings.push({
      type: 'sql_injection',
      severity: 'high',
      description: 'SQL injection vulnerability detected'
    });
  }
  
  return findings;
}

function parseGobusterOutput(output) {
  const findings = [];
  const lines = output.split('\n');
  
  lines.forEach(line => {
    if (line.includes('Status: 200') || line.includes('Status: 301') || line.includes('Status: 302')) {
      findings.push({
        type: 'directory',
        severity: 'info',
        description: line.trim()
      });
    }
  });
  
  return findings;
}

function parseNucleiOutput(output) {
  const findings = [];
  const lines = output.split('\n');
  
  lines.forEach(line => {
    if (line.includes('[') && (line.includes('critical') || line.includes('high') || line.includes('medium'))) {
      let severity = 'info';
      if (line.includes('critical')) severity = 'critical';
      else if (line.includes('high')) severity = 'high';
      else if (line.includes('medium')) severity = 'medium';
      
      findings.push({
        type: 'vulnerability',
        severity,
        description: line.trim()
      });
    }
  });
  
  return findings;
}

// Start server
const PORT = process.env.PORT || 8080;
server.listen(PORT, () => {
  console.log(`🔥 VAPT Backend Server running on port ${PORT}`);
  console.log(`📡 WebSocket server ready for real-time scanning`);
  console.log(`🐉 Kali Linux Tool Integration Active`);
});