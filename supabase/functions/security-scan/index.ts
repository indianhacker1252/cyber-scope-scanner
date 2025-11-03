import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { target, scanType, options } = await req.json();
    
    const supabase = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? ''
    );

    const { data: { user } } = await supabase.auth.getUser(
      req.headers.get('Authorization')?.replace('Bearer ', '') ?? ''
    );

    if (!user) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    console.log(`[Security Scan] User ${user.id} scanning ${target} with ${scanType}`);

    // Cloud-based security scanning logic
    const findings: any[] = [];
    let scanOutput = '';

    switch (scanType) {
      case 'port-scan':
        scanOutput = await performPortScan(target);
        findings.push(...parsePortScanResults(scanOutput));
        break;
      case 'ssl-check':
        scanOutput = await performSSLCheck(target);
        findings.push(...parseSSLResults(scanOutput));
        break;
      case 'header-analysis':
        scanOutput = await performHeaderAnalysis(target);
        findings.push(...parseHeaderResults(scanOutput));
        break;
      case 'dns-enum':
        scanOutput = await performDNSEnumeration(target);
        findings.push(...parseDNSResults(scanOutput));
        break;
      default:
        scanOutput = `Cloud-based ${scanType} scan initiated for ${target}`;
    }

    // Save scan results
    for (const finding of findings) {
      await supabase.from('scan_reports').insert({
        user_id: user.id,
        target,
        scan_type: scanType,
        vulnerability_name: finding.name,
        severity: finding.severity,
        proof_of_concept: finding.poc,
        request_data: finding.request,
        response_data: finding.response,
        scan_output: scanOutput,
      });
    }

    return new Response(JSON.stringify({ 
      success: true, 
      findings,
      output: scanOutput,
      message: `Scan completed: ${findings.length} findings`
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });

  } catch (error) {
    console.error('[Security Scan Error]', error);
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
});

async function performPortScan(target: string): Promise<string> {
  try {
    const commonPorts = [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 5432, 8080, 8443];
    const results: string[] = [];
    
    for (const port of commonPorts) {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 2000);
        
        await fetch(`http://${target}:${port}`, { 
          signal: controller.signal,
          method: 'HEAD'
        });
        
        clearTimeout(timeout);
        results.push(`Port ${port}: OPEN`);
      } catch {
        // Port closed or filtered
      }
    }
    
    return results.length > 0 ? results.join('\n') : 'No open ports detected in common range';
  } catch (error) {
    return `Port scan error: ${error.message}`;
  }
}

async function performSSLCheck(target: string): Promise<string> {
  try {
    const url = target.startsWith('http') ? target : `https://${target}`;
    const response = await fetch(url);
    
    const issues: string[] = [];
    const headers = response.headers;
    
    if (!headers.get('strict-transport-security')) {
      issues.push('Missing HSTS header');
    }
    
    if (url.startsWith('http://')) {
      issues.push('No HTTPS redirect detected');
    }
    
    return issues.length > 0 
      ? `SSL/TLS Issues Found:\n${issues.join('\n')}`
      : 'SSL/TLS configuration appears secure';
  } catch (error) {
    return `SSL check error: ${error.message}`;
  }
}

async function performHeaderAnalysis(target: string): Promise<string> {
  try {
    const url = target.startsWith('http') ? target : `https://${target}`;
    const response = await fetch(url);
    
    const securityHeaders = [
      'X-Frame-Options',
      'X-Content-Type-Options',
      'Content-Security-Policy',
      'X-XSS-Protection',
      'Strict-Transport-Security',
      'Referrer-Policy',
      'Permissions-Policy'
    ];
    
    const results: string[] = ['Security Headers Analysis:'];
    
    for (const header of securityHeaders) {
      const value = response.headers.get(header);
      results.push(`${header}: ${value || 'MISSING ⚠️'}`);
    }
    
    return results.join('\n');
  } catch (error) {
    return `Header analysis error: ${error.message}`;
  }
}

async function performDNSEnumeration(target: string): Promise<string> {
  try {
    const cleanTarget = target.replace(/^https?:\/\//, '').split('/')[0];
    const subdomains = ['www', 'api', 'mail', 'ftp', 'admin', 'dev', 'staging'];
    const results: string[] = ['DNS Enumeration Results:'];
    
    for (const sub of subdomains) {
      try {
        const testDomain = `${sub}.${cleanTarget}`;
        await fetch(`https://${testDomain}`, { method: 'HEAD' });
        results.push(`${testDomain}: FOUND ✓`);
      } catch {
        // Subdomain not found
      }
    }
    
    return results.join('\n');
  } catch (error) {
    return `DNS enumeration error: ${error.message}`;
  }
}

function parsePortScanResults(output: string): any[] {
  const findings: any[] = [];
  const lines = output.split('\n');
  
  for (const line of lines) {
    if (line.includes('OPEN')) {
      const port = line.match(/Port (\d+)/)?.[1];
      findings.push({
        name: `Open Port Detected: ${port}`,
        severity: ['21', '23', '445', '3389'].includes(port || '') ? 'high' : 'medium',
        poc: line,
        request: `Port scan on port ${port}`,
        response: 'Port is open and accepting connections'
      });
    }
  }
  
  return findings;
}

function parseSSLResults(output: string): any[] {
  const findings: any[] = [];
  
  if (output.includes('Missing HSTS')) {
    findings.push({
      name: 'Missing HSTS Header',
      severity: 'medium',
      poc: 'Strict-Transport-Security header not found',
      request: 'HTTPS connection attempt',
      response: output
    });
  }
  
  if (output.includes('No HTTPS redirect')) {
    findings.push({
      name: 'HTTP Not Redirecting to HTTPS',
      severity: 'high',
      poc: 'Site accessible over HTTP without redirect',
      request: 'HTTP connection',
      response: output
    });
  }
  
  return findings;
}

function parseHeaderResults(output: string): any[] {
  const findings: any[] = [];
  const lines = output.split('\n');
  
  for (const line of lines) {
    if (line.includes('MISSING')) {
      const header = line.split(':')[0];
      findings.push({
        name: `Missing Security Header: ${header}`,
        severity: 'medium',
        poc: line,
        request: 'HTTP headers check',
        response: 'Header not present in response'
      });
    }
  }
  
  return findings;
}

function parseDNSResults(output: string): any[] {
  const findings: any[] = [];
  const lines = output.split('\n');
  
  for (const line of lines) {
    if (line.includes('FOUND')) {
      const subdomain = line.split(':')[0];
      findings.push({
        name: `Subdomain Discovered: ${subdomain}`,
        severity: 'info',
        poc: line,
        request: `DNS lookup for ${subdomain}`,
        response: 'Subdomain resolves and responds'
      });
    }
  }
  
  return findings;
}
