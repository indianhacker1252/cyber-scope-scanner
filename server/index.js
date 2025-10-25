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

const { execSync } = require('child_process');

function checkTool(toolName) {
  try {
    execSync(`which ${toolName}`, { stdio: 'ignore' });
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
    // Check if nmap is installed
    if (!checkTool('nmap')) {
      return res.status(500).json({ error: 'Nmap is not installed on this system' });
    }

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
    // Check if nikto is installed
    if (!checkTool('nikto')) {
      return res.status(500).json({ error: 'Nikto is not installed on this system' });
    }

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

// SQLMap scan endpoint with full automation
app.post('/api/scan/sqlmap', async (req, res) => {
  const { target, options, sessionId, scanMode } = req.body;
  
  try {
    // Check if sqlmap is installed
    if (!checkTool('sqlmap')) {
      return res.status(500).json({ error: 'SQLMap is not installed on this system' });
    }

    // Build automated SQLMap arguments
    const sqlmapArgs = [
      '-u', target,
      '--batch',              // Never ask for user input
      '--random-agent',       // Use random User-Agent
      '--threads', '4',       // Faster scanning
      '--timeout', '30',      // Request timeout
      '--retries', '2',       // Retry failed requests
      '--answers', 'crack=N,dict=N,continue=Y', // Auto-answer prompts
      '--tamper', 'space2comment',  // Basic evasion
      '-v', '3'               // Verbose output
    ];

    // Adjust parameters based on scan mode
    if (scanMode === 'passive') {
      sqlmapArgs.push('--level', '1', '--risk', '1', '--technique', 'E');
    } else {
      sqlmapArgs.push('--level', '2', '--risk', '2');
    }

    if (options) {
      sqlmapArgs.push(...options.split(' '));
    }
    
    console.log(`Starting SQLMap scan: sqlmap ${sqlmapArgs.join(' ')}`);
    
    const process = spawn('sqlmap', sqlmapArgs);
    activeSessions.set(sessionId, process);
    sessionOutputs.set(sessionId, '');

    // Set timeout to prevent hanging (15 minutes)
    const timeout = setTimeout(() => {
      console.log(`SQLMap scan timeout for session ${sessionId}`);
      if (process && !process.killed) {
        process.kill('SIGTERM');
        broadcastToSession(sessionId, {
          type: 'output',
          content: '\n[TIMEOUT] Scan exceeded maximum duration (15 minutes)\n'
        });
      }
    }, 15 * 60 * 1000);

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
      clearTimeout(timeout);
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

// DNS Lookup endpoint
app.post('/api/scan/dns', async (req, res) => {
  const { domain, sessionId } = req.body;
  
  try {
    if (!domain) {
      return res.status(400).json({ error: 'Domain is required' });
    }

    console.log(`Starting DNS lookup for: ${domain}`);
    
    const dnsArgs = [domain, 'ANY'];
    const process = spawn('dig', dnsArgs);
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
          tool: 'dns',
          target: domain,
          status: code === 0 ? 'completed' : 'failed',
          output: fullOutput,
          findings: parseDNSOutput(fullOutput)
        }
      });
      activeSessions.delete(sessionId);
      sessionOutputs.delete(sessionId);
    });

    res.json({ success: true, sessionId });
  } catch (error) {
    console.error('DNS lookup error:', error);
    res.status(500).json({ error: error.message });
  }
});

// WHOIS Lookup endpoint
app.post('/api/scan/whois', async (req, res) => {
  const { domain, sessionId } = req.body;
  
  try {
    if (!domain) {
      return res.status(400).json({ error: 'Domain is required' });
    }

    console.log(`Starting WHOIS lookup for: ${domain}`);
    
    const process = spawn('whois', [domain]);
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
          tool: 'whois',
          target: domain,
          status: code === 0 ? 'completed' : 'failed',
          output: fullOutput,
          findings: []
        }
      });
      activeSessions.delete(sessionId);
      sessionOutputs.delete(sessionId);
    });

    res.json({ success: true, sessionId });
  } catch (error) {
    console.error('WHOIS lookup error:', error);
    res.status(500).json({ error: error.message });
  }
});

// SSL Certificate Analysis endpoint
app.post('/api/scan/ssl', async (req, res) => {
  const { domain, sessionId } = req.body;
  
  try {
    if (!domain) {
      return res.status(400).json({ error: 'Domain is required' });
    }

    console.log(`Starting SSL analysis for: ${domain}`);
    
    const process = spawn('openssl', ['s_client', '-connect', `${domain}:443`, '-servername', domain]);
    activeSessions.set(sessionId, process);
    sessionOutputs.set(sessionId, '');

    // Send empty input and close stdin
    process.stdin.write('\n');
    process.stdin.end();

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
          tool: 'ssl',
          target: domain,
          status: 'completed',
          output: fullOutput,
          findings: parseSSLOutput(fullOutput)
        }
      });
      activeSessions.delete(sessionId);
      sessionOutputs.delete(sessionId);
    });

    // Timeout after 10 seconds
    setTimeout(() => {
      if (activeSessions.has(sessionId)) {
        process.kill();
      }
    }, 10000);

    res.json({ success: true, sessionId });
  } catch (error) {
    console.error('SSL analysis error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Gobuster scan endpoint
app.post('/api/scan/gobuster', async (req, res) => {
  const { target, wordlist, sessionId } = req.body;
  
  try {
    // Check if gobuster is installed
    if (!checkTool('gobuster')) {
      return res.status(500).json({ error: 'Gobuster is not installed on this system' });
    }

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
    // Check if nuclei is installed
    if (!checkTool('nuclei')) {
      return res.status(500).json({ error: 'Nuclei is not installed on this system' });
    }

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

// WhatWeb scan endpoint
app.post('/api/scan/whatweb', async (req, res) => {
  const { target, sessionId } = req.body;
  
  try {
    // Check if whatweb is installed
    if (!checkTool('whatweb')) {
      return res.status(500).json({ error: 'WhatWeb is not installed on this system' });
    }

    const whatwebArgs = ['-a', '3', target];
    console.log(`Starting WhatWeb scan: whatweb ${whatwebArgs.join(' ')}`);
    
    const process = spawn('whatweb', whatwebArgs);
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
          tool: 'whatweb',
          target,
          status: code === 0 ? 'completed' : 'failed',
          output: fullOutput,
          findings: parseWhatWebOutput(fullOutput)
        }
      });
      activeSessions.delete(sessionId);
      sessionOutputs.delete(sessionId);
    });

    res.json({ success: true, sessionId });
  } catch (error) {
    console.error('WhatWeb scan error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Amass scan endpoint
app.post('/api/scan/amass', async (req, res) => {
  const { domain, sessionId } = req.body;
  
  try {
    // Check if amass is installed
    if (!checkTool('amass')) {
      return res.status(500).json({ error: 'Amass is not installed on this system' });
    }

    const amassArgs = ['enum', '-d', domain];
    console.log(`Starting Amass scan: amass ${amassArgs.join(' ')}`);
    
    const process = spawn('amass', amassArgs);
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
          tool: 'amass',
          target: domain,
          status: code === 0 ? 'completed' : 'failed',
          output: fullOutput,
          findings: parseAmassOutput(fullOutput)
        }
      });
      activeSessions.delete(sessionId);
      sessionOutputs.delete(sessionId);
    });

    res.json({ success: true, sessionId });
  } catch (error) {
    console.error('Amass scan error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Sublist3r scan endpoint
app.post('/api/scan/sublist3r', async (req, res) => {
  const { domain, sessionId } = req.body;
  
  try {
    // Check if sublist3r is installed  
    if (!checkTool('sublist3r')) {
      return res.status(500).json({ error: 'Sublist3r is not installed on this system' });
    }

    const sublist3rArgs = ['-d', domain];
    console.log(`Starting Sublist3r scan: sublist3r ${sublist3rArgs.join(' ')}`);
    
    const process = spawn('sublist3r', sublist3rArgs);
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
          tool: 'sublist3r',
          target: domain,
          status: code === 0 ? 'completed' : 'failed',
          output: fullOutput,
          findings: parseSublist3rOutput(fullOutput)
        }
      });
      activeSessions.delete(sessionId);
      sessionOutputs.delete(sessionId);
    });

    res.json({ success: true, sessionId });
  } catch (error) {
    console.error('Sublist3r scan error:', error);
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

function parseWhatWebOutput(output) {
  const findings = [];
  const lines = output.split('\n');
  
  lines.forEach(line => {
    if (line.includes('200 OK') || line.includes('Title')) {
      findings.push({
        type: 'technology',
        severity: 'info',
        description: line.trim()
      });
    }
  });
  
  return findings;
}

function parseAmassOutput(output) {
  const findings = [];
  const lines = output.split('\n');
  
  lines.forEach(line => {
    if (line.trim() && !line.includes('OWASP Amass')) {
      findings.push({
        type: 'subdomain',
        severity: 'info',
        description: `Subdomain found: ${line.trim()}`
      });
    }
  });
  
  return findings;
}

function parseSublist3rOutput(output) {
  const findings = [];
  const lines = output.split('\n');
  
  lines.forEach(line => {
    if (line.trim() && !line.includes('Sublist3r')) {
      findings.push({
        type: 'subdomain',
        severity: 'info',
        description: `Subdomain enumerated: ${line.trim()}`
      });
    }
  });
  
  return findings;
}

// ============================================================
// ADVANCED TOOLS ENDPOINTS
// ============================================================

// Masscan - Ultra-fast port scanner
app.post('/api/scan/masscan', (req, res) => {
  const { target, ports = '1-65535', rate = '1000', sessionId } = req.body;
  
  if (!target) {
    return res.status(400).json({ error: 'Target is required' });
  }

  const masscanArgs = [
    '-p', ports,
    '--rate', rate,
    target,
    '--wait', '0',
    '--open'
  ];

  spawnToolSession('masscan', masscanArgs, sessionId, res);
});

// Hydra - Password cracking
app.post('/api/scan/hydra', (req, res) => {
  const { target, service = 'ssh', username, passwordList, sessionId } = req.body;
  
  if (!target || !username) {
    return res.status(400).json({ error: 'Target and username required' });
  }

  const hydraArgs = [
    '-l', username,
    '-P', passwordList || '/usr/share/wordlists/rockyou.txt',
    service + '://' + target,
    '-V',
    '-f'
  ];

  spawnToolSession('hydra', hydraArgs, sessionId, res);
});

// WPScan - WordPress security scanner
app.post('/api/scan/wpscan', (req, res) => {
  const { target, apiToken, sessionId } = req.body;
  
  if (!target) {
    return res.status(400).json({ error: 'Target is required' });
  }

  const wpscanArgs = [
    '--url', target,
    '--enumerate', 'vp,vt,u',
    '--random-user-agent',
    '--verbose'
  ];

  if (apiToken) {
    wpscanArgs.push('--api-token', apiToken);
  }

  spawnToolSession('wpscan', wpscanArgs, sessionId, res);
});

// Enum4linux - SMB enumeration
app.post('/api/scan/enum4linux', (req, res) => {
  const { target, sessionId } = req.body;
  
  if (!target) {
    return res.status(400).json({ error: 'Target is required' });
  }

  const enum4linuxArgs = ['-a', target];
  spawnToolSession('enum4linux', enum4linuxArgs, sessionId, res);
});

// theHarvester - OSINT tool
app.post('/api/scan/theharvester', (req, res) => {
  const { domain, sources = 'google,bing,duckduckgo', sessionId } = req.body;
  
  if (!domain) {
    return res.status(400).json({ error: 'Domain is required' });
  }

  const harvesterArgs = [
    '-d', domain,
    '-b', sources,
    '-l', '500'
  ];

  spawnToolSession('theHarvester', harvesterArgs, sessionId, res);
});

// SSLyze - SSL/TLS scanner
app.post('/api/scan/sslyze', (req, res) => {
  const { target, sessionId } = req.body;
  
  if (!target) {
    return res.status(400).json({ error: 'Target is required' });
  }

  const sslyzeArgs = ['--regular', target];
  spawnToolSession('sslyze', sslyzeArgs, sessionId, res);
});

// Wafw00f - WAF detection
app.post('/api/scan/wafw00f', (req, res) => {
  const { target, sessionId } = req.body;
  
  if (!target) {
    return res.status(400).json({ error: 'Target is required' });
  }

  const wafArgs = [target, '-a'];
  spawnToolSession('wafw00f', wafArgs, sessionId, res);
});

// Wapiti - Web vulnerability scanner
app.post('/api/scan/wapiti', (req, res) => {
  const { target, sessionId } = req.body;
  
  if (!target) {
    return res.status(400).json({ error: 'Target is required' });
  }

  const wapitiArgs = [
    '-u', target,
    '--flush-session',
    '-v', '2',
    '-m', 'all'
  ];

  spawnToolSession('wapiti', wapitiArgs, sessionId, res);
});

// Commix - Command injection tester
app.post('/api/scan/commix', (req, res) => {
  const { target, sessionId } = req.body;
  
  if (!target) {
    return res.status(400).json({ error: 'Target is required' });
  }

  const commixArgs = [
    '--url', target,
    '--batch',
    '--all',
    '-v', '1'
  ];

  spawnToolSession('commix', commixArgs, sessionId, res);
});

// XSStrike - XSS scanner
app.post('/api/scan/xsstrike', (req, res) => {
  const { target, sessionId } = req.body;
  
  if (!target) {
    return res.status(400).json({ error: 'Target is required' });
  }

  const xsstrikeArgs = [
    '/usr/share/xsstrike/xsstrike.py',
    '-u', target,
    '--crawl',
    '-v'
  ];

  spawnToolSession('python3', xsstrikeArgs, sessionId, res);
});

// Dnsenum - DNS enumeration
app.post('/api/scan/dnsenum', (req, res) => {
  const { domain, sessionId } = req.body;
  
  if (!domain) {
    return res.status(400).json({ error: 'Domain is required' });
  }

  const dnsenumArgs = ['--enum', '--noreverse', domain];
  spawnToolSession('dnsenum', dnsenumArgs, sessionId, res);
});

// Fierce - DNS reconnaissance
app.post('/api/scan/fierce', (req, res) => {
  const { domain, sessionId } = req.body;
  
  if (!domain) {
    return res.status(400).json({ error: 'Domain is required' });
  }

  const fierceArgs = [
    '--domain', domain,
    '--subdomains', 'hosts',
    '--traverse', '5'
  ];

  spawnToolSession('fierce', fierceArgs, sessionId, res);
});

// CrackMapExec - Network pentesting
app.post('/api/scan/crackmapexec', (req, res) => {
  const { target, protocol = 'smb', username, password, sessionId } = req.body;
  
  if (!target) {
    return res.status(400).json({ error: 'Target is required' });
  }

  const cmexecArgs = [protocol, target];
  
  if (username && password) {
    cmexecArgs.push('-u', username, '-p', password);
  } else {
    cmexecArgs.push('--gen-relay-list', 'relays.txt');
  }

  spawnToolSession('crackmapexec', cmexecArgs, sessionId, res);
});

// Metasploit - Exploitation framework
app.post('/api/scan/metasploit', (req, res) => {
  const { commands, sessionId } = req.body;
  
  if (!commands || !Array.isArray(commands)) {
    return res.status(400).json({ error: 'Commands array is required' });
  }

  const fs = require('fs');
  const resourceScript = commands.join('\n') + '\nexit\n';
  const scriptPath = `/tmp/msf-${sessionId}.rc`;
  
  fs.writeFileSync(scriptPath, resourceScript);

  const msfArgs = ['-q', '-r', scriptPath];
  spawnToolSession('msfconsole', msfArgs, sessionId, res);
});

// John the Ripper - Password cracker
app.post('/api/scan/john', (req, res) => {
  const { hashFile, wordlist, format, sessionId } = req.body;
  
  if (!hashFile) {
    return res.status(400).json({ error: 'Hash file is required' });
  }

  const johnArgs = [hashFile];
  
  if (wordlist) {
    johnArgs.push('--wordlist=' + wordlist);
  }
  
  if (format) {
    johnArgs.push('--format=' + format);
  }

  spawnToolSession('john', johnArgs, sessionId, res);
});

// Hashcat - GPU password cracker
app.post('/api/scan/hashcat', (req, res) => {
  const { hashFile, wordlist, mode = '0', sessionId } = req.body;
  
  if (!hashFile) {
    return res.status(400).json({ error: 'Hash file is required' });
  }

  const hashcatArgs = [
    '-m', mode,
    '-a', '0',
    hashFile,
    wordlist || '/usr/share/wordlists/rockyou.txt',
    '--force'
  ];

  spawnToolSession('hashcat', hashcatArgs, sessionId, res);
});

// Recon-ng - Reconnaissance framework
app.post('/api/scan/reconng', (req, res) => {
  const { workspace, modules, target, sessionId } = req.body;
  
  if (!target || !modules) {
    return res.status(400).json({ error: 'Target and modules required' });
  }

  const reconArgs = [
    '-w', workspace || 'default',
    '-m', modules,
    '-x', `set SOURCE ${target}`
  ];

  spawnToolSession('recon-ng', reconArgs, sessionId, res);
});

// Start server
const PORT = process.env.PORT || 8080;
server.listen(PORT, () => {
  console.log(`🔥 VAPT Backend Server running on port ${PORT}`);
  console.log(`📡 WebSocket server ready for real-time scanning`);
  console.log(`🐉 Kali Linux Tool Integration Active`);
});