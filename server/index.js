#!/usr/bin/env node

const express = require('express');
const { createServer } = require('http');
const { WebSocketServer } = require('ws');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const crypto = require('crypto');
const { createRemoteJWKSet, jwtVerify } = require('jose');

const app = express();
const server = createServer(app);
const wss = new WebSocketServer({ server });

// Middleware
app.use(cors());
app.use(express.json());

// JWT Authentication middleware with proper Supabase verification
const SUPABASE_URL = process.env.SUPABASE_URL || 'https://uyqzmpjcazxakyzjkfxc.supabase.co';
const SUPABASE_JWT_SECRET = process.env.SUPABASE_JWT_SECRET;

// Create JWKS (JSON Web Key Set) for Supabase
const JWKS = createRemoteJWKSet(new URL(`${SUPABASE_URL}/auth/v1/jwks`));

const authenticateJWT = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  const token = authHeader.substring(7);
  
  try {
    // Verify JWT token with Supabase JWKS
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: `${SUPABASE_URL}/auth/v1`,
      audience: 'authenticated'
    });
    
    // Store user info from verified token
    req.user = {
      id: payload.sub,
      email: payload.email,
      role: payload.role
    };
    
    console.log(`[AUTH] User ${payload.email} (${payload.sub}) authenticated`);
    next();
  } catch (error) {
    console.error('[AUTH] Token verification failed:', error.message);
    return res.status(401).json({ error: 'Invalid or expired authentication token' });
  }
};

// Input validation helpers
const validateTarget = (target) => {
  if (!target || typeof target !== 'string') {
    throw new Error('Invalid target');
  }
  // Allow only alphanumeric, dots, hyphens, colons (for ports), and slashes (for URLs)
  if (!/^[a-zA-Z0-9.:\/-]+$/.test(target)) {
    throw new Error('Target contains invalid characters');
  }
  if (target.length > 500) {
    throw new Error('Target too long');
  }
  return target;
};

const validateFilePath = (filePath, allowedDir = '/usr/share/wordlists') => {
  if (!filePath || typeof filePath !== 'string') {
    throw new Error('Invalid file path');
  }
  
  // Remove path traversal attempts
  const basename = path.basename(filePath);
  const resolvedPath = path.resolve(allowedDir, basename);
  
  // Ensure the resolved path is within the allowed directory
  if (!resolvedPath.startsWith(path.resolve(allowedDir))) {
    throw new Error('Path traversal attempt detected');
  }
  
  // Check file exists
  if (!fs.existsSync(resolvedPath)) {
    throw new Error('File not found');
  }
  
  return resolvedPath;
};

const sanitizeSessionId = () => {
  // Generate secure random session ID instead of using user input
  return crypto.randomUUID();
};

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
app.post('/api/scan/nmap', authenticateJWT, async (req, res) => {
  const { target, scanType } = req.body;
  
  try {
    const validatedTarget = validateTarget(target);
    const safeSessionId = sanitizeSessionId();

    // Check if nmap is installed
    if (!checkTool('nmap')) {
      return res.status(503).json({ error: 'Service temporarily unavailable' });
    }

    const nmapArgs = buildNmapArgs(validatedTarget, scanType);
    console.log(`[${req.user.token.substring(0, 10)}...] Starting Nmap scan on ${validatedTarget}`);
    
    const process = spawn('nmap', nmapArgs);
    activeSessions.set(safeSessionId, process);
    sessionOutputs.set(safeSessionId, '');

    // Handle process output
    process.stdout.on('data', (data) => {
      const output = data.toString();
      sessionOutputs.set(safeSessionId, sessionOutputs.get(safeSessionId) + output);
      broadcastToSession(safeSessionId, {
        type: 'output',
        content: output
      });
    });

    process.stderr.on('data', (data) => {
      const output = data.toString();
      sessionOutputs.set(safeSessionId, sessionOutputs.get(safeSessionId) + output);
      broadcastToSession(safeSessionId, {
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
    res.status(500).json({ error: 'An error occurred while initiating the scan' });
  }
});

// Nikto scan endpoint
app.post('/api/scan/nikto', authenticateJWT, async (req, res) => {
  const { target, sessionId } = req.body;
  
  try {
    // Validate target
    const validatedTarget = validateTarget(target);
    const safeSessionId = sanitizeSessionId(sessionId);
    
    // Check if nikto is installed
    if (!checkTool('nikto')) {
      console.error('[SERVER] Tool check failed: Nikto not installed');
      return res.status(503).json({ error: 'Scanning service temporarily unavailable' });
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
    res.status(500).json({ error: 'An error occurred while initiating the scan' });
  }
});

// SQLMap scan endpoint with full automation
app.post('/api/scan/sqlmap', authenticateJWT, async (req, res) => {
  const { target, options, sessionId, scanMode } = req.body;
  
  try {
    // Validate target
    const validatedTarget = validateTarget(target);
    const safeSessionId = sanitizeSessionId(sessionId);
    
    // Check if sqlmap is installed
    if (!checkTool('sqlmap')) {
      console.error('[SERVER] Tool check failed: SQLMap not installed');
      return res.status(503).json({ error: 'SQL injection testing service temporarily unavailable' });
    }

    // Build automated SQLMap arguments
    const sqlmapArgs = [
      '-u', validatedTarget,
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

    // DO NOT allow arbitrary options - major security risk
    // If options needed, implement strict allowlist
    
    console.log(`[${req.user.email}] Starting SQLMap scan: sqlmap ${sqlmapArgs.join(' ')}`);
    
    const process = spawn('sqlmap', sqlmapArgs);
    activeSessions.set(safeSessionId, process);
    sessionOutputs.set(safeSessionId, '');

    // Set timeout to prevent hanging (15 minutes)
    const timeout = setTimeout(() => {
      console.log(`SQLMap scan timeout for session ${safeSessionId}`);
      if (process && !process.killed) {
        process.kill('SIGTERM');
        broadcastToSession(safeSessionId, {
          type: 'output',
          content: '\n[TIMEOUT] Scan exceeded maximum duration (15 minutes)\n'
        });
      }
    }, 15 * 60 * 1000);

    process.stdout.on('data', (data) => {
      const output = data.toString();
      sessionOutputs.set(safeSessionId, sessionOutputs.get(safeSessionId) + output);
      broadcastToSession(safeSessionId, {
        type: 'output',
        content: output
      });
    });

    process.stderr.on('data', (data) => {
      const output = data.toString();
      sessionOutputs.set(safeSessionId, sessionOutputs.get(safeSessionId) + output);
      broadcastToSession(safeSessionId, {
        type: 'output',
        content: output
      });
    });

    process.on('close', (code) => {
      clearTimeout(timeout);
      const fullOutput = sessionOutputs.get(safeSessionId) || '';
      broadcastToSession(safeSessionId, {
        type: 'complete',
        result: {
          id: safeSessionId,
          tool: 'sqlmap',
          target: validatedTarget,
          status: code === 0 ? 'completed' : 'failed',
          output: fullOutput,
          findings: parseSQLMapOutput(fullOutput)
        }
      });
      activeSessions.delete(safeSessionId);
      sessionOutputs.delete(safeSessionId);
    });

    res.json({ success: true, sessionId: safeSessionId });
  } catch (error) {
    console.error('SQLMap scan error:', error);
    res.status(500).json({ error: 'An error occurred while initiating SQL injection test' });
  }
});

// DNS Lookup endpoint
app.post('/api/scan/dns', authenticateJWT, async (req, res) => {
  const { domain, sessionId } = req.body;
  
  try {
    if (!domain) {
      return res.status(400).json({ error: 'Domain is required' });
    }

    // Validate inputs
    const validatedDomain = validateTarget(domain);
    const safeSessionId = sanitizeSessionId(sessionId);

    console.log(`[${req.user.email}] Starting DNS lookup for: ${validatedDomain}`);
    
    const dnsArgs = [validatedDomain, 'ANY'];
    const process = spawn('dig', dnsArgs);
    activeSessions.set(safeSessionId, process);
    sessionOutputs.set(safeSessionId, '');

    process.stdout.on('data', (data) => {
      const output = data.toString();
      sessionOutputs.set(safeSessionId, sessionOutputs.get(safeSessionId) + output);
      broadcastToSession(safeSessionId, {
        type: 'output',
        content: output
      });
    });

    process.stderr.on('data', (data) => {
      const output = data.toString();
      sessionOutputs.set(safeSessionId, sessionOutputs.get(safeSessionId) + output);
      broadcastToSession(safeSessionId, {
        type: 'output',
        content: output
      });
    });

    process.on('close', (code) => {
      const fullOutput = sessionOutputs.get(safeSessionId) || '';
      broadcastToSession(safeSessionId, {
        type: 'complete',
        result: {
          id: safeSessionId,
          tool: 'dns',
          target: validatedDomain,
          status: code === 0 ? 'completed' : 'failed',
          output: fullOutput,
          findings: parseDNSOutput(fullOutput)
        }
      });
      activeSessions.delete(safeSessionId);
      sessionOutputs.delete(safeSessionId);
    });

    res.json({ success: true, sessionId: safeSessionId });
  } catch (error) {
    console.error('DNS lookup error:', error);
    res.status(500).json({ error: 'An error occurred during DNS lookup' });
  }
});

// WHOIS Lookup endpoint
app.post('/api/scan/whois', authenticateJWT, async (req, res) => {
  const { domain, sessionId } = req.body;
  
  try {
    if (!domain) {
      return res.status(400).json({ error: 'Domain is required' });
    }

    // Validate inputs
    const validatedDomain = validateTarget(domain);
    const safeSessionId = sanitizeSessionId(sessionId);

    console.log(`[${req.user.email}] Starting WHOIS lookup for: ${validatedDomain}`);
    
    const process = spawn('whois', [validatedDomain]);
    activeSessions.set(safeSessionId, process);
    sessionOutputs.set(safeSessionId, '');

    process.stdout.on('data', (data) => {
      const output = data.toString();
      sessionOutputs.set(safeSessionId, sessionOutputs.get(safeSessionId) + output);
      broadcastToSession(safeSessionId, {
        type: 'output',
        content: output
      });
    });

    process.stderr.on('data', (data) => {
      const output = data.toString();
      sessionOutputs.set(safeSessionId, sessionOutputs.get(safeSessionId) + output);
      broadcastToSession(safeSessionId, {
        type: 'output',
        content: output
      });
    });

    process.on('close', (code) => {
      const fullOutput = sessionOutputs.get(safeSessionId) || '';
      broadcastToSession(safeSessionId, {
        type: 'complete',
        result: {
          id: safeSessionId,
          tool: 'whois',
          target: validatedDomain,
          status: code === 0 ? 'completed' : 'failed',
          output: fullOutput,
          findings: []
        }
      });
      activeSessions.delete(safeSessionId);
      sessionOutputs.delete(safeSessionId);
    });

    res.json({ success: true, sessionId: safeSessionId });
        }
      });
      activeSessions.delete(sessionId);
      sessionOutputs.delete(sessionId);
    });

    res.json({ success: true, sessionId });
  } catch (error) {
    console.error('WHOIS lookup error:', error);
    res.status(500).json({ error: 'An error occurred during WHOIS lookup' });
  }
});

// SSL Certificate Analysis endpoint
app.post('/api/scan/ssl', authenticateJWT, async (req, res) => {
  const { domain, sessionId } = req.body;
  
  try {
    if (!domain) {
      return res.status(400).json({ error: 'Domain is required' });
    }

    // Validate inputs
    const validatedDomain = validateTarget(domain);
    const safeSessionId = sanitizeSessionId(sessionId);

    console.log(`[${req.user.email}] Starting SSL analysis for: ${validatedDomain}`);
    
    const process = spawn('openssl', ['s_client', '-connect', `${validatedDomain}:443`, '-servername', validatedDomain]);
    activeSessions.set(safeSessionId, process);
    sessionOutputs.set(safeSessionId, '');

    // Send empty input and close stdin
    process.stdin.write('\n');
    process.stdin.end();

    process.stdout.on('data', (data) => {
      const output = data.toString();
      sessionOutputs.set(safeSessionId, sessionOutputs.get(safeSessionId) + output);
      broadcastToSession(safeSessionId, {
        type: 'output',
        content: output
      });
    });

    process.stderr.on('data', (data) => {
      const output = data.toString();
      sessionOutputs.set(safeSessionId, sessionOutputs.get(safeSessionId) + output);
      broadcastToSession(safeSessionId, {
        type: 'output',
        content: output
      });
    });

    process.on('close', (code) => {
      const fullOutput = sessionOutputs.get(safeSessionId) || '';
      broadcastToSession(safeSessionId, {
        type: 'complete',
        result: {
          id: safeSessionId,
          tool: 'ssl',
          target: validatedDomain,
          status: 'completed',
          output: fullOutput,
          findings: parseSSLOutput(fullOutput)
        }
      });
      activeSessions.delete(safeSessionId);
      sessionOutputs.delete(safeSessionId);
    });

    // Timeout after 10 seconds
    setTimeout(() => {
      if (activeSessions.has(safeSessionId)) {
        process.kill();
      }
    }, 10000);

    res.json({ success: true, sessionId: safeSessionId });
  } catch (error) {
    console.error('SSL analysis error:', error);
    res.status(500).json({ error: 'An error occurred during SSL analysis' });
  }
});

// Gobuster scan endpoint
app.post('/api/scan/gobuster', authenticateJWT, async (req, res) => {
  const { target, wordlist, sessionId } = req.body;
  
  try {
    // Validate inputs
    const validatedTarget = validateTarget(target);
    const safeSessionId = sanitizeSessionId(sessionId);
    
    // Check if gobuster is installed
    if (!checkTool('gobuster')) {
      console.error('[SERVER] Tool check failed: Gobuster not installed');
      return res.status(503).json({ error: 'Directory enumeration service temporarily unavailable' });
    }

    // Validate wordlist path
    let wordlistPath = '/usr/share/wordlists/dirb/common.txt';
    if (wordlist) {
      wordlistPath = validateFilePath(wordlist, '/usr/share/wordlists');
    }
    
    const gobusterArgs = ['dir', '-u', validatedTarget, '-w', wordlistPath, '-t', '10'];
    
    console.log(`[${req.user.email}] Starting Gobuster scan: gobuster ${gobusterArgs.join(' ')}`);
    
    const process = spawn('gobuster', gobusterArgs);
    activeSessions.set(safeSessionId, process);
    sessionOutputs.set(safeSessionId, '');

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
    res.status(500).json({ error: 'An error occurred while initiating directory enumeration' });
  }
});

// Nuclei scan endpoint
app.post('/api/scan/nuclei', authenticateJWT, async (req, res) => {
  const { target, templates, sessionId } = req.body;
  
  try {
    const validatedTarget = validateTarget(target);
    const safeSessionId = sanitizeSessionId(sessionId);
  
  try {
    // Check if nuclei is installed
    if (!checkTool('nuclei')) {
      console.error('[SERVER] Tool check failed: Nuclei not installed');
      return res.status(503).json({ error: 'Vulnerability scanning service temporarily unavailable' });
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
    res.status(500).json({ error: 'An error occurred while initiating vulnerability scan' });
  }
});

// WhatWeb scan endpoint
app.post('/api/scan/whatweb', authenticateJWT, async (req, res) => {
  const { target, sessionId } = req.body;
  
  try {
    const validatedTarget = validateTarget(target);
    const safeSessionId = sanitizeSessionId(sessionId);
  
  try {
    // Check if whatweb is installed
    if (!checkTool('whatweb')) {
      console.error('[SERVER] Tool check failed: WhatWeb not installed');
      return res.status(503).json({ error: 'Web technology detection service temporarily unavailable' });
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
    res.status(500).json({ error: 'An error occurred while initiating web technology detection' });
  }
});

// Amass scan endpoint
app.post('/api/scan/amass', authenticateJWT, async (req, res) => {
  const { domain, sessionId } = req.body;
  
  try {
    // Validate inputs
    const validatedDomain = validateTarget(domain);
    const safeSessionId = sanitizeSessionId(sessionId);

    // Check if amass is installed
    if (!checkTool('amass')) {
      console.error('[SERVER] Tool check failed: Amass not installed');
      return res.status(503).json({ error: 'Subdomain enumeration service temporarily unavailable' });
    }

    const amassArgs = ['enum', '-d', validatedDomain];
    console.log(`[${req.user.email}] Starting Amass scan: amass ${amassArgs.join(' ')}`);
    
    const process = spawn('amass', amassArgs);
    activeSessions.set(safeSessionId, process);
    sessionOutputs.set(safeSessionId, '');

    process.stdout.on('data', (data) => {
      const output = data.toString();
      sessionOutputs.set(safeSessionId, sessionOutputs.get(safeSessionId) + output);
      broadcastToSession(safeSessionId, {
        type: 'output',
        content: output
      });
    });

    process.stderr.on('data', (data) => {
      const output = data.toString();
      sessionOutputs.set(safeSessionId, sessionOutputs.get(safeSessionId) + output);
      broadcastToSession(safeSessionId, {
        type: 'output',
        content: output
      });
    });

    process.on('close', (code) => {
      const fullOutput = sessionOutputs.get(safeSessionId) || '';
      broadcastToSession(safeSessionId, {
        type: 'complete',
        result: {
          id: safeSessionId,
          tool: 'amass',
          target: validatedDomain,
          status: code === 0 ? 'completed' : 'failed',
          output: fullOutput,
          findings: parseAmassOutput(fullOutput)
        }
      });
      activeSessions.delete(safeSessionId);
      sessionOutputs.delete(safeSessionId);
    });

    res.json({ success: true, sessionId: safeSessionId });
  } catch (error) {
    console.error('Amass scan error:', error);
    res.status(500).json({ error: 'An error occurred while initiating subdomain enumeration' });
  }
});

// Sublist3r scan endpoint
app.post('/api/scan/sublist3r', authenticateJWT, async (req, res) => {
  const { domain, sessionId } = req.body;
  
  try {
    // Validate inputs
    const validatedDomain = validateTarget(domain);
    const safeSessionId = sanitizeSessionId(sessionId);

    // Check if sublist3r is installed  
    if (!checkTool('sublist3r')) {
      console.error('[SERVER] Tool check failed: Sublist3r not installed');
      return res.status(503).json({ error: 'Subdomain discovery service temporarily unavailable' });
    }

    const sublist3rArgs = ['-d', validatedDomain];
    console.log(`[${req.user.email}] Starting Sublist3r scan: sublist3r ${sublist3rArgs.join(' ')}`);
    
    const process = spawn('sublist3r', sublist3rArgs);
    activeSessions.set(safeSessionId, process);
    sessionOutputs.set(safeSessionId, '');

    process.stdout.on('data', (data) => {
      const output = data.toString();
      sessionOutputs.set(safeSessionId, sessionOutputs.get(safeSessionId) + output);
      broadcastToSession(safeSessionId, {
        type: 'output',
        content: output
      });
    });

    process.stderr.on('data', (data) => {
      const output = data.toString();
      sessionOutputs.set(safeSessionId, sessionOutputs.get(safeSessionId) + output);
      broadcastToSession(safeSessionId, {
        type: 'output',
        content: output
      });
    });

    process.on('close', (code) => {
      const fullOutput = sessionOutputs.get(safeSessionId) || '';
      broadcastToSession(safeSessionId, {
        type: 'complete',
        result: {
          id: safeSessionId,
          tool: 'sublist3r',
          target: validatedDomain,
          status: code === 0 ? 'completed' : 'failed',
          output: fullOutput,
          findings: parseSublist3rOutput(fullOutput)
        }
      });
      activeSessions.delete(safeSessionId);
      sessionOutputs.delete(safeSessionId);
    });

    res.json({ success: true, sessionId: safeSessionId });
  } catch (error) {
    console.error('Sublist3r scan error:', error);
    res.status(500).json({ error: 'An error occurred while initiating subdomain discovery' });
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
app.post('/api/scan/masscan', authenticateJWT, (req, res) => {
  const { target, ports = '1-65535', rate = '1000', sessionId } = req.body;
  
  if (!target) {
    return res.status(400).json({ error: 'Target is required' });
  }

  // Validate inputs
  const validatedTarget = validateTarget(target);
  const safeSessionId = sanitizeSessionId(sessionId);

  // Additional validation for Masscan
  // Validate ports is numeric range
  if (!/^\d+-\d+$/.test(ports)) {
    return res.status(400).json({ error: 'Invalid port range format. Use format: 1-65535' });
  }

  // Validate rate is reasonable
  const maxRate = 10000;
  if (parseInt(rate) > maxRate) {
    return res.status(400).json({ error: `Rate exceeds maximum allowed (${maxRate})` });
  }

  // Validate target is not too broad
  if (validatedTarget.includes('/8') || validatedTarget === '0.0.0.0' || validatedTarget.includes('0.0.0.0/')) {
    return res.status(400).json({ error: 'Target range too broad. Use more specific targets.' });
  }

  console.log(`[${req.user.email}] Starting Masscan: ${validatedTarget} ports ${ports} rate ${rate}`);

  const masscanArgs = [
    '-p', ports,
    '--rate', rate,
    validatedTarget,
    '--wait', '0',
    '--open'
  ];

  spawnToolSession('masscan', masscanArgs, safeSessionId, res);
});

// Hydra - Password cracking
app.post('/api/scan/hydra', authenticateJWT, (req, res) => {
  const { target, service = 'ssh', usernameList, passwordList, sessionId } = req.body;
  
  if (!target) {
    return res.status(400).json({ error: 'Target is required' });
  }

  try {
    const validatedTarget = validateTarget(target);
    const safeSessionId = sanitizeSessionId(sessionId);
    
    const hydraArgs = [];
    
    // Support both single username and username list
    if (usernameList) {
      const validatedUserList = validateFilePath(usernameList, '/usr/share/wordlists');
      hydraArgs.push('-L', validatedUserList);
    } else {
      hydraArgs.push('-l', 'admin'); // Default username if none provided
    }
    
    // Support password list
    if (passwordList) {
      const validatedPassList = validateFilePath(passwordList, '/usr/share/wordlists');
      hydraArgs.push('-P', validatedPassList);
    } else {
      hydraArgs.push('-P', '/usr/share/wordlists/rockyou.txt');
    }
    
    // Validate service is alphanumeric
    if (!/^[a-z0-9-]+$/.test(service)) {
      return res.status(400).json({ error: 'Invalid service name' });
    }
    
    hydraArgs.push(
      service + '://' + validatedTarget,
      '-V',
      '-f',
      '-t', '4'
    );

    console.log(`[${req.user.email}] Starting Hydra: hydra ${hydraArgs.join(' ')}`);
    spawnToolSession('hydra', hydraArgs, safeSessionId, res);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// WPScan - WordPress security scanner
app.post('/api/scan/wpscan', authenticateJWT, (req, res) => {
  const { target, apiToken, sessionId } = req.body;
  
  if (!target) {
    return res.status(400).json({ error: 'Target is required' });
  }

  try {
    const validatedTarget = validateTarget(target);
    const safeSessionId = sanitizeSessionId(sessionId);
    
    const wpscanArgs = [
      '--url', validatedTarget,
      '--enumerate', 'vp,vt,u',
      '--random-user-agent',
      '--verbose'
    ];

    if (apiToken) {
      wpscanArgs.push('--api-token', apiToken);
    }

    console.log(`[${req.user.email}] Starting WPScan`);
    spawnToolSession('wpscan', wpscanArgs, safeSessionId, res);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Enum4linux - SMB enumeration
app.post('/api/scan/enum4linux', authenticateJWT, (req, res) => {
  const { target, sessionId } = req.body;
  
  if (!target) {
    return res.status(400).json({ error: 'Target is required' });
  }

  try {
    const validatedTarget = validateTarget(target);
    const safeSessionId = sanitizeSessionId(sessionId);
    const enum4linuxArgs = ['-a', validatedTarget];
    console.log(`[${req.user.email}] Starting Enum4linux`);
    spawnToolSession('enum4linux', enum4linuxArgs, safeSessionId, res);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// theHarvester - OSINT tool
app.post('/api/scan/theharvester', authenticateJWT, (req, res) => {
  const { domain, sources = 'google,bing,duckduckgo', sessionId } = req.body;
  
  if (!domain) {
    return res.status(400).json({ error: 'Domain is required' });
  }

  try {
    const validatedDomain = validateTarget(domain);
    const safeSessionId = sanitizeSessionId(sessionId);
    
    const harvesterArgs = [
      '-d', validatedDomain,
      '-b', sources,
      '-l', '500'
    ];

    console.log(`[${req.user.email}] Starting theHarvester`);
    spawnToolSession('theHarvester', harvesterArgs, safeSessionId, res);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// SSLyze - SSL/TLS scanner
app.post('/api/scan/sslyze', authenticateJWT, (req, res) => {
  const { target, sessionId } = req.body;
  
  if (!target) {
    return res.status(400).json({ error: 'Target is required' });
  }

  try {
    const validatedTarget = validateTarget(target);
    const safeSessionId = sanitizeSessionId(sessionId);
    const sslyzeArgs = ['--regular', validatedTarget];
    console.log(`[${req.user.email}] Starting SSLyze`);
    spawnToolSession('sslyze', sslyzeArgs, safeSessionId, res);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Wafw00f - WAF detection
app.post('/api/scan/wafw00f', authenticateJWT, (req, res) => {
  const { target, sessionId } = req.body;
  
  if (!target) {
    return res.status(400).json({ error: 'Target is required' });
  }

  try {
    const validatedTarget = validateTarget(target);
    const safeSessionId = sanitizeSessionId(sessionId);
    const wafArgs = [validatedTarget, '-a'];
    console.log(`[${req.user.email}] Starting Wafw00f`);
    spawnToolSession('wafw00f', wafArgs, safeSessionId, res);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Wapiti - Web vulnerability scanner
app.post('/api/scan/wapiti', authenticateJWT, (req, res) => {
  const { target, sessionId } = req.body;
  
  if (!target) {
    return res.status(400).json({ error: 'Target is required' });
  }

  try {
    const validatedTarget = validateTarget(target);
    const safeSessionId = sanitizeSessionId(sessionId);
    
    const wapitiArgs = [
      '-u', validatedTarget,
      '--flush-session',
      '-v', '2',
      '-m', 'all'
    ];

    console.log(`[${req.user.email}] Starting Wapiti`);
    spawnToolSession('wapiti', wapitiArgs, safeSessionId, res);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Commix - Command injection tester
app.post('/api/scan/commix', authenticateJWT, (req, res) => {
  const { target, sessionId } = req.body;
  
  if (!target) {
    return res.status(400).json({ error: 'Target is required' });
  }

  try {
    const validatedTarget = validateTarget(target);
    const safeSessionId = sanitizeSessionId(sessionId);
    
    const commixArgs = [
      '--url', validatedTarget,
      '--batch',
      '--all',
      '-v', '1'
    ];

    console.log(`[${req.user.email}] Starting Commix`);
    spawnToolSession('commix', commixArgs, safeSessionId, res);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// XSStrike - XSS scanner
app.post('/api/scan/xsstrike', authenticateJWT, (req, res) => {
  const { target, sessionId } = req.body;
  
  if (!target) {
    return res.status(400).json({ error: 'Target is required' });
  }

  try {
    const validatedTarget = validateTarget(target);
    const safeSessionId = sanitizeSessionId(sessionId);
    
    const xsstrikeArgs = [
      '/usr/share/xsstrike/xsstrike.py',
      '-u', validatedTarget,
      '--crawl',
      '-v'
    ];

    console.log(`[${req.user.email}] Starting XSStrike`);
    spawnToolSession('python3', xsstrikeArgs, safeSessionId, res);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Dnsenum - DNS enumeration
app.post('/api/scan/dnsenum', authenticateJWT, (req, res) => {
  const { domain, sessionId } = req.body;
  
  if (!domain) {
    return res.status(400).json({ error: 'Domain is required' });
  }

  try {
    const validatedDomain = validateTarget(domain);
    const safeSessionId = sanitizeSessionId(sessionId);
    const dnsenumArgs = ['--enum', '--noreverse', validatedDomain];
    console.log(`[${req.user.email}] Starting Dnsenum`);
    spawnToolSession('dnsenum', dnsenumArgs, safeSessionId, res);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Fierce - DNS reconnaissance
app.post('/api/scan/fierce', authenticateJWT, (req, res) => {
  const { domain, sessionId } = req.body;
  
  if (!domain) {
    return res.status(400).json({ error: 'Domain is required' });
  }

  try {
    const validatedDomain = validateTarget(domain);
    const safeSessionId = sanitizeSessionId(sessionId);
    const fierceArgs = ['--domain', validatedDomain];
    console.log(`[${req.user.email}] Starting Fierce`);
    spawnToolSession('fierce', fierceArgs, safeSessionId, res);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// CrackMapExec - Network pentesting
app.post('/api/scan/crackmapexec', authenticateJWT, (req, res) => {
  const { target, protocol = 'smb', sessionId } = req.body;
  
  if (!target) {
    return res.status(400).json({ error: 'Target is required' });
  }

  try {
    const validatedTarget = validateTarget(target);
    const safeSessionId = sanitizeSessionId(sessionId);
    
    // Validate protocol
    if (!/^[a-z]+$/.test(protocol)) {
      return res.status(400).json({ error: 'Invalid protocol' });
    }
    
    const cmexecArgs = [protocol, validatedTarget, '--shares'];
    console.log(`[${req.user.email}] Starting CrackMapExec`);
    spawnToolSession('crackmapexec', cmexecArgs, safeSessionId, res);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Metasploit - Exploitation framework
app.post('/api/scan/metasploit', authenticateJWT, (req, res) => {
  const { commands, sessionId } = req.body;
  
  if (!commands) {
    return res.status(400).json({ error: 'Commands are required' });
  }

  try {
    const safeSessionId = sanitizeSessionId(sessionId);
    // Limit command length to prevent abuse
    if (commands.length > 1000) {
      return res.status(400).json({ error: 'Commands too long' });
    }
    
    const msfArgs = ['-q', '-x', commands];
    console.log(`[${req.user.email}] Starting Metasploit (CRITICAL TOOL)`);
    spawnToolSession('msfconsole', msfArgs, safeSessionId, res);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// John the Ripper - Password cracking
app.post('/api/scan/john', authenticateJWT, (req, res) => {
  const { hashFile, wordlist, sessionId } = req.body;
  
  if (!hashFile) {
    return res.status(400).json({ error: 'Hash file is required' });
  }

  try {
    const safeSessionId = sanitizeSessionId(sessionId);
    const validatedHashFile = validateFilePath(hashFile, '/tmp');
    
    let wordlistPath = '/usr/share/wordlists/rockyou.txt';
    if (wordlist) {
      wordlistPath = validateFilePath(wordlist, '/usr/share/wordlists');
    }
    
    const johnArgs = [
      validatedHashFile,
      '--wordlist=' + wordlistPath,
      '--format=raw-md5'
    ];
    
    console.log(`[${req.user.email}] Starting John the Ripper (PASSWORD CRACKING)`);
    spawnToolSession('john', johnArgs, safeSessionId, res);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Hashcat - Advanced password recovery
app.post('/api/scan/hashcat', authenticateJWT, (req, res) => {
  const { hashFile, wordlist, attackMode = '0', hashType = '0', sessionId } = req.body;
  
  if (!hashFile) {
    return res.status(400).json({ error: 'Hash file is required' });
  }

  try {
    const safeSessionId = sanitizeSessionId(sessionId);
    const validatedHashFile = validateFilePath(hashFile, '/tmp');
    
    let wordlistPath = '/usr/share/wordlists/rockyou.txt';
    if (wordlist) {
      wordlistPath = validateFilePath(wordlist, '/usr/share/wordlists');
    }
    
    const hashcatArgs = [
      '-m', hashType,
      '-a', attackMode,
      validatedHashFile,
      wordlistPath,
      '--force'
    ];
    
    console.log(`[${req.user.email}] Starting Hashcat (GPU PASSWORD CRACKING)`);
    spawnToolSession('hashcat', hashcatArgs, safeSessionId, res);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Recon-ng - Reconnaissance framework
app.post('/api/scan/reconng', authenticateJWT, (req, res) => {
  const { domain, sessionId } = req.body;
  
  if (!domain) {
    return res.status(400).json({ error: 'Domain is required' });
  }

  try {
    const validatedDomain = validateTarget(domain);
    const safeSessionId = sanitizeSessionId(sessionId);
    const reconArgs = ['-w', 'default', '-C', `add domains ${validatedDomain}; run`];
    console.log(`[${req.user.email}] Starting Recon-ng`);
    spawnToolSession('recon-ng', reconArgs, safeSessionId, res);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Helper function to spawn tool sessions
function spawnToolSession(tool, args, sessionId, res) {
  try {
    if (!checkTool(tool)) {
      console.error(`[SERVER] Tool check failed: ${tool} not installed`);
      return res.status(503).json({ 
        error: 'Scanning service temporarily unavailable',
        installed: false 
      });
    }

    console.log(`Starting ${tool}: ${tool} ${args.join(' ')}`);
    
    const process = spawn(tool, args);
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
          tool,
          status: code === 0 ? 'completed' : 'failed',
          output: fullOutput,
          exitCode: code
        }
      });
      activeSessions.delete(sessionId);
      sessionOutputs.delete(sessionId);
    });

    res.json({ success: true, sessionId });
  } catch (error) {
    console.error(`${tool} error:`, error);
    res.status(500).json({ error: 'An error occurred while initiating the scan' });
  }
}
// ===== DUPLICATE ENDPOINTS BELOW - REMOVE OR UPDATE =====
// Note: These duplicate endpoints need to be removed or consolidated

// Fierce - DNS reconnaissance (DUPLICATE)
app.post('/api/scan/fierce', authenticateJWT, (req, res) => {
  const { domain, sessionId } = req.body;
  
  if (!domain) {
    return res.status(400).json({ error: 'Domain is required' });
  }

  try {
    const validatedDomain = validateTarget(domain);
    const safeSessionId = sanitizeSessionId(sessionId);
    
    const fierceArgs = [
      '--domain', validatedDomain,
      '--subdomains', 'hosts',
      '--traverse', '5'
    ];

    console.log(`[${req.user.email}] Starting Fierce`);
    spawnToolSession('fierce', fierceArgs, safeSessionId, res);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// CrackMapExec - Network pentesting (DUPLICATE)
app.post('/api/scan/crackmapexec', authenticateJWT, (req, res) => {
  const { target, protocol = 'smb', username, password, sessionId } = req.body;
  
  if (!target) {
    return res.status(400).json({ error: 'Target is required' });
  }

  try {
    const validatedTarget = validateTarget(target);
    const safeSessionId = sanitizeSessionId(sessionId);
    
    // Validate protocol
    if (!/^[a-z]+$/.test(protocol)) {
      return res.status(400).json({ error: 'Invalid protocol' });
    }
    
    const cmexecArgs = [protocol, validatedTarget];
    
    if (username && password) {
      cmexecArgs.push('-u', username, '-p', password);
    } else {
      cmexecArgs.push('--gen-relay-list', 'relays.txt');
    }

    console.log(`[${req.user.email}] Starting CrackMapExec`);
    spawnToolSession('crackmapexec', cmexecArgs, safeSessionId, res);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Metasploit - Exploitation framework (DUPLICATE)
app.post('/api/scan/metasploit', authenticateJWT, (req, res) => {
  const { commands, sessionId } = req.body;
  
  if (!commands || !Array.isArray(commands)) {
    return res.status(400).json({ error: 'Commands array is required' });
  }

  try {
    const safeSessionId = sanitizeSessionId(sessionId);
    
    // Limit command length
    const resourceScript = commands.join('\n') + '\nexit\n';
    if (resourceScript.length > 5000) {
      return res.status(400).json({ error: 'Commands too long' });
    }
    
    // Use safe session ID for file path
    const scriptPath = `/tmp/msf-${safeSessionId}.rc`;
    
    fs.writeFileSync(scriptPath, resourceScript);

    const msfArgs = ['-q', '-r', scriptPath];
    console.log(`[${req.user.email}] Starting Metasploit (CRITICAL TOOL - ARRAY MODE)`);
    spawnToolSession('msfconsole', msfArgs, safeSessionId, res);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// John the Ripper - Password cracker (DUPLICATE)
app.post('/api/scan/john', authenticateJWT, (req, res) => {
  const { hashFile, wordlist, format, sessionId } = req.body;
  
  if (!hashFile) {
    return res.status(400).json({ error: 'Hash file is required' });
  }

  try {
    const safeSessionId = sanitizeSessionId(sessionId);
    const validatedHashFile = validateFilePath(hashFile, '/tmp');
    
    const johnArgs = [validatedHashFile];
    
    if (wordlist) {
      const validatedWordlist = validateFilePath(wordlist, '/usr/share/wordlists');
      johnArgs.push('--wordlist=' + validatedWordlist);
    }
    
    if (format) {
      // Validate format is alphanumeric
      if (!/^[a-z0-9_-]+$/i.test(format)) {
        return res.status(400).json({ error: 'Invalid format' });
      }
      johnArgs.push('--format=' + format);
    }

    console.log(`[${req.user.email}] Starting John the Ripper`);
    spawnToolSession('john', johnArgs, safeSessionId, res);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Hashcat - GPU password cracker (DUPLICATE)
app.post('/api/scan/hashcat', authenticateJWT, (req, res) => {
  const { hashFile, wordlist, mode = '0', sessionId } = req.body;
  
  if (!hashFile) {
    return res.status(400).json({ error: 'Hash file is required' });
  }

  try {
    const safeSessionId = sanitizeSessionId(sessionId);
    const validatedHashFile = validateFilePath(hashFile, '/tmp');
    
    let wordlistPath = '/usr/share/wordlists/rockyou.txt';
    if (wordlist) {
      wordlistPath = validateFilePath(wordlist, '/usr/share/wordlists');
    }
    
    const hashcatArgs = [
      '-m', mode,
      '-a', '0',
      validatedHashFile,
      wordlistPath,
      '--force'
    ];

    console.log(`[${req.user.email}] Starting Hashcat`);
    spawnToolSession('hashcat', hashcatArgs, safeSessionId, res);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Recon-ng - Reconnaissance framework (DUPLICATE)
app.post('/api/scan/reconng', authenticateJWT, (req, res) => {
  const { workspace, modules, target, sessionId } = req.body;
  
  if (!target || !modules) {
    return res.status(400).json({ error: 'Target and modules required' });
  }

  try {
    const validatedTarget = validateTarget(target);
    const safeSessionId = sanitizeSessionId(sessionId);
    
    const reconArgs = [
      '-w', workspace || 'default',
      '-m', modules,
      '-x', `set SOURCE ${validatedTarget}`
    ];

    console.log(`[${req.user.email}] Starting Recon-ng`);
    spawnToolSession('recon-ng', reconArgs, safeSessionId, res);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ============================================================================
// WebHackersWeapons Integration - Modern Pentesting Tools
// ============================================================================

// Subfinder - Fast subdomain enumeration
app.post('/api/scan/subfinder', authenticateJWT, (req, res) => {
  const { domain, sessionId } = req.body;
  
  if (!domain) {
    return res.status(400).json({ error: 'Domain is required' });
  }

  try {
    const validatedDomain = validateTarget(domain);
    const safeSessionId = sanitizeSessionId(sessionId);
    
    const subfinderArgs = [
      '-d', validatedDomain,
      '-all',
      '-recursive',
      '-silent'
    ];

    console.log(`[${req.user.email}] Subfinder scan: ${validatedDomain}`);
    spawnToolSession('subfinder', subfinderArgs, safeSessionId, res);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// httpx - HTTP toolkit for probing
app.post('/api/scan/httpx', authenticateJWT, (req, res) => {
  const { target, sessionId } = req.body;
  
  if (!target) {
    return res.status(400).json({ error: 'Target is required' });
  }

  try {
    const validatedTarget = validateTarget(target);
    const safeSessionId = sanitizeSessionId(sessionId);
    
    const httpxArgs = [
      '-u', validatedTarget,
      '-status-code',
      '-title',
      '-tech-detect',
      '-web-server',
      '-follow-redirects',
      '-silent'
    ];

    console.log(`[${req.user.email}] httpx probe: ${validatedTarget}`);
    spawnToolSession('httpx', httpxArgs, safeSessionId, res);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Katana - Modern web crawler
app.post('/api/scan/katana', authenticateJWT, (req, res) => {
  const { target, depth = '2', sessionId } = req.body;
  
  if (!target) {
    return res.status(400).json({ error: 'Target is required' });
  }

  try {
    const validatedTarget = validateTarget(target);
    const safeSessionId = sanitizeSessionId(sessionId);
    
    const katanaArgs = [
      '-u', validatedTarget,
      '-d', depth,
      '-jc',
      '-fx',
      '-ef', 'css,png,jpg,jpeg,gif,svg,woff,woff2',
      '-silent'
    ];

    console.log(`[${req.user.email}] Katana crawl: ${validatedTarget}`);
    spawnToolSession('katana', katanaArgs, safeSessionId, res);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Dalfox - XSS scanner and parameter analysis
app.post('/api/scan/dalfox', authenticateJWT, (req, res) => {
  const { target, sessionId } = req.body;
  
  if (!target) {
    return res.status(400).json({ error: 'Target URL is required' });
  }

  try {
    const validatedTarget = validateTarget(target);
    const safeSessionId = sanitizeSessionId(sessionId);
    
    const dalfoxArgs = [
      'url', validatedTarget,
      '--skip-bav',
      '--silence',
      '--mining-dict'
    ];

    console.log(`[${req.user.email}] Dalfox XSS scan: ${validatedTarget}`);
    spawnToolSession('dalfox', dalfoxArgs, safeSessionId, res);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// GAU - GetAllUrls from web archives
app.post('/api/scan/gau', authenticateJWT, (req, res) => {
  const { domain, sessionId } = req.body;
  
  if (!domain) {
    return res.status(400).json({ error: 'Domain is required' });
  }

  try {
    const validatedDomain = validateTarget(domain);
    const safeSessionId = sanitizeSessionId(sessionId);
    
    const gauArgs = [
      validatedDomain,
      '--subs',
      '--threads', '5'
    ];

    console.log(`[${req.user.email}] GAU URL fetch: ${validatedDomain}`);
    spawnToolSession('gau', gauArgs, safeSessionId, res);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// FFUF - Fast web fuzzer
app.post('/api/scan/ffuf', authenticateJWT, (req, res) => {
  const { target, wordlist = '/usr/share/seclists/Discovery/Web-Content/common.txt', sessionId } = req.body;
  
  if (!target) {
    return res.status(400).json({ error: 'Target URL is required' });
  }

  try {
    const validatedTarget = validateTarget(target);
    const safeSessionId = sanitizeSessionId(sessionId);
    let wordlistPath = '/usr/share/seclists/Discovery/Web-Content/common.txt';
    
    if (wordlist && wordlist !== wordlistPath) {
      wordlistPath = validateFilePath(wordlist, '/usr/share');
    }
    
    const ffufArgs = [
      '-u', validatedTarget + '/FUZZ',
      '-w', wordlistPath,
      '-mc', 'all',
      '-fc', '404',
      '-sf',
      '-s'
    ];

    console.log(`[${req.user.email}] FFUF fuzzing: ${validatedTarget}`);
    spawnToolSession('ffuf', ffufArgs, safeSessionId, res);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Arjun - HTTP parameter discovery
app.post('/api/scan/arjun', authenticateJWT, (req, res) => {
  const { target, sessionId } = req.body;
  
  if (!target) {
    return res.status(400).json({ error: 'Target URL is required' });
  }

  try {
    const validatedTarget = validateTarget(target);
    const safeSessionId = sanitizeSessionId(sessionId);
    
    const arjunArgs = [
      '-u', validatedTarget,
      '--stable'
    ];

    console.log(`[${req.user.email}] Arjun parameter discovery: ${validatedTarget}`);
    spawnToolSession('arjun', arjunArgs, safeSessionId, res);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ParamSpider - Parameter mining from web archives
app.post('/api/scan/paramspider', authenticateJWT, (req, res) => {
  const { domain, sessionId } = req.body;
  
  if (!domain) {
    return res.status(400).json({ error: 'Domain is required' });
  }

  try {
    const validatedDomain = validateTarget(domain);
    const safeSessionId = sanitizeSessionId(sessionId);
    
    const paramspiderArgs = [
      '-d', validatedDomain,
      '--level', 'high',
      '--quiet'
    ];

    console.log(`[${req.user.email}] ParamSpider mining: ${validatedDomain}`);
    spawnToolSession('paramspider', paramspiderArgs, safeSessionId, res);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Waybackurls - Fetch URLs from Wayback Machine
app.post('/api/scan/waybackurls', authenticateJWT, (req, res) => {
  const { domain, sessionId } = req.body;
  
  if (!domain) {
    return res.status(400).json({ error: 'Domain is required' });
  }

  try {
    const validatedDomain = validateTarget(domain);
    const safeSessionId = sanitizeSessionId(sessionId);
    
    // waybackurls reads from stdin
    const waybackArgs = [];

    console.log(`[${req.user.email}] Waybackurls fetch: ${validatedDomain}`);
    
    // Special handling for waybackurls - it reads domain from stdin
    const tool = spawn('waybackurls', waybackArgs);
    const safeId = safeSessionId;
    sessions.set(safeId, { tool, sessionId: safeId, startTime: Date.now() });
    
    tool.stdin.write(validatedDomain + '\n');
    tool.stdin.end();
    
    let output = '';
    
    tool.stdout.on('data', (data) => {
      const chunk = data.toString();
      output += chunk;
      broadcast(safeId, { type: 'output', data: chunk });
    });
    
    tool.stderr.on('data', (data) => {
      const error = data.toString();
      broadcast(safeId, { type: 'error', data: error });
    });
    
    tool.on('close', (code) => {
      broadcast(safeId, { 
        type: 'complete', 
        code, 
        output,
        sessionId: safeId 
      });
      sessions.delete(safeId);
    });
    
    res.json({ sessionId: safeId, message: 'Waybackurls started' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Hakrawler - Simple web crawler
app.post('/api/scan/hakrawler', authenticateJWT, (req, res) => {
  const { target, depth = '2', sessionId } = req.body;
  
  if (!target) {
    return res.status(400).json({ error: 'Target URL is required' });
  }

  try {
    const validatedTarget = validateTarget(target);
    const safeSessionId = sanitizeSessionId(sessionId);
    
    const hakrawlerArgs = [
      '-url', validatedTarget,
      '-depth', depth,
      '-plain'
    ];

    console.log(`[${req.user.email}] Hakrawler crawl: ${validatedTarget}`);
    spawnToolSession('hakrawler', hakrawlerArgs, safeSessionId, res);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Assetfinder - Find domains and subdomains
app.post('/api/scan/assetfinder', authenticateJWT, (req, res) => {
  const { domain, sessionId } = req.body;
  
  if (!domain) {
    return res.status(400).json({ error: 'Domain is required' });
  }

  try {
    const validatedDomain = validateTarget(domain);
    const safeSessionId = sanitizeSessionId(sessionId);
    
    const assetfinderArgs = [
      '--subs-only',
      validatedDomain
    ];

    console.log(`[${req.user.email}] Assetfinder scan: ${validatedDomain}`);
    spawnToolSession('assetfinder', assetfinderArgs, safeSessionId, res);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// LinkFinder - Discover endpoints in JavaScript files
app.post('/api/scan/linkfinder', authenticateJWT, (req, res) => {
  const { url, sessionId } = req.body;
  
  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }

  try {
    const validatedUrl = validateTarget(url);
    const safeSessionId = sanitizeSessionId(sessionId);
    
    const linkfinderArgs = [
      '-i', validatedUrl,
      '-o', 'cli'
    ];

    console.log(`[${req.user.email}] LinkFinder scan: ${validatedUrl}`);
    spawnToolSession('linkfinder', linkfinderArgs, safeSessionId, res);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// SecretFinder - Find sensitive data in JS files
app.post('/api/scan/secretfinder', authenticateJWT, (req, res) => {
  const { url, sessionId } = req.body;
  
  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }

  try {
    const validatedUrl = validateTarget(url);
    const safeSessionId = sanitizeSessionId(sessionId);
    
    const secretfinderArgs = [
      '-i', validatedUrl,
      '-o', 'cli'
    ];

    console.log(`[${req.user.email}] SecretFinder scan: ${validatedUrl}`);
    spawnToolSession('python3', ['/usr/share/secretfinder/SecretFinder.py', ...secretfinderArgs], safeSessionId, res);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Gitleaks - Scan for secrets in git repos
app.post('/api/scan/gitleaks', authenticateJWT, (req, res) => {
  const { repo, sessionId } = req.body;
  
  if (!repo) {
    return res.status(400).json({ error: 'Repository URL is required' });
  }

  try {
    const validatedRepo = validateTarget(repo);
    const safeSessionId = sanitizeSessionId(sessionId);
    
    const gitleaksArgs = [
      'detect',
      '--source', validatedRepo,
      '--verbose',
      '--no-git'
    ];

    console.log(`[${req.user.email}] Gitleaks scan: ${validatedRepo}`);
    spawnToolSession('gitleaks', gitleaksArgs, safeSessionId, res);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// RustScan - Ultra-fast port scanner
app.post('/api/scan/rustscan', authenticateJWT, (req, res) => {
  const { target, sessionId } = req.body;
  
  if (!target) {
    return res.status(400).json({ error: 'Target is required' });
  }

  try {
    const validatedTarget = validateTarget(target);
    const safeSessionId = sanitizeSessionId(sessionId);
    
    const rustscanArgs = [
      '-a', validatedTarget,
      '--ulimit', '5000',
      '--batch-size', '15000'
    ];

    console.log(`[${req.user.email}] RustScan: ${validatedTarget}`);
    spawnToolSession('rustscan', rustscanArgs, safeSessionId, res);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Start server
const PORT = process.env.PORT || 8080;
server.listen(PORT, () => {
  console.log(`🔥 VAPT Backend Server running on port ${PORT}`);
  console.log(`📡 WebSocket server ready for real-time scanning`);
  console.log(`🐉 Kali Linux Tool Integration Active`);
  console.log(`⚔️  WebHackersWeapons Tools Integrated`);
});