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

// Red Team Agent State Machine
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
}

interface Correlation {
  id: string;
  findings: string[];
  attack_path: string;
  risk_amplification: number;
  exploitation_probability: number;
  description: string;
}

interface AttackChain {
  id: string;
  name: string;
  steps: AttackStep[];
  success_probability: number;
  impact: string;
  mitre_mapping: string[];
}

interface AttackStep {
  order: number;
  tool: string;
  action: string;
  target_component: string;
  expected_outcome: string;
  dependencies: string[];
}

interface LearningContext {
  successful_techniques: TechniqueRecord[];
  failed_techniques: TechniqueRecord[];
  target_signatures: TargetSignature[];
  adaptation_history: Adaptation[];
  model_confidence: number;
}

interface TechniqueRecord {
  technique: string;
  target_type: string;
  success_count: number;
  failure_count: number;
  avg_execution_time: number;
  last_used: string;
}

interface TargetSignature {
  signature: string;
  tech_stack: string[];
  common_vulnerabilities: string[];
  recommended_approach: string;
}

interface Adaptation {
  trigger: string;
  original_approach: string;
  adapted_approach: string;
  outcome: string;
  timestamp: string;
}

// MITRE ATT&CK Mapping
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

// Scan types mapped to security-scan edge function
const PHASE_SCAN_TYPES: Record<string, string[]> = {
  recon: ['dns', 'headers', 'tech'],
  scanning: ['port', 'directory'],
  exploitation: ['sqli', 'xss'],
  'post-exploit': ['cookies'],
  learning: []
};

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { action, data } = await req.json();
    
    // Require authentication
    const authHeader = req.headers.get('Authorization');
    if (!authHeader?.startsWith('Bearer ')) {
      return new Response(JSON.stringify({ error: 'Authentication required' }), {
        status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
      global: { headers: { Authorization: authHeader } }
    });
    
    // Use getUser() for auth verification (getClaims doesn't exist)
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

        // Execute real continuous operation with security-scan integration
        const result = await executeContinuousOperation(agentState, objective, config, authHeader);

        // Persist session
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
        const { target, phase, config: phaseConfig } = data;
        
        // Run a single phase with real scans
        const phaseResult = await executePhase(phase, target, authHeader);
        
        // Record learning for AI fine-tuning
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
        
        return new Response(JSON.stringify({
          success: true,
          phase,
          ...phaseResult
        }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      case 'correlate-findings': {
        const { findings, target_context } = data;
        
        const correlations = await correlateFindings(findings, target_context);
        const attackChains = await generateAttackChains(correlations, target_context);

        return new Response(JSON.stringify({
          success: true,
          correlations,
          attack_chains: attackChains,
          risk_score: calculateRiskScore(correlations)
        }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      case 'adaptive-learning': {
        const { execution_result, technique, target_type, context } = data;
        
        const learningUpdate = await processLearning(execution_result, technique, target_type, context);

        await supabase.from('ai_learnings').insert({
          user_id: userId,
          tool_used: technique,
          target: target_type,
          findings: execution_result.findings || [],
          success: execution_result.success,
          execution_time: execution_result.execution_time,
          ai_analysis: learningUpdate.analysis,
          improvement_strategy: learningUpdate.adaptation_strategy
        });

        return new Response(JSON.stringify({
          success: true,
          learning: learningUpdate,
          next_recommended_action: learningUpdate.next_action,
          model_confidence: learningUpdate.confidence
        }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      case 'get-agent-recommendations': {
        const { target, current_phase, existing_findings } = data;

        let historicalData: any[] = [];
        const { data: learnings } = await supabase
          .from('ai_learnings')
          .select('*')
          .eq('user_id', userId)
          .order('created_at', { ascending: false })
          .limit(50);
        historicalData = learnings || [];

        const recommendations = await generateAgentRecommendations(
          target, current_phase, existing_findings, historicalData
        );

        return new Response(JSON.stringify({
          success: true,
          recommendations,
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

// ===== Real Security Scan Integration =====

async function callSecurityScan(scanType: string, target: string, authHeader: string): Promise<any> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 25000); // 25s timeout per scan

    const response = await fetch(`${SUPABASE_URL}/functions/v1/security-scan`, {
      method: 'POST',
      headers: {
        'Authorization': authHeader,
        'Content-Type': 'application/json',
        'apikey': SUPABASE_ANON_KEY,
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
      console.warn(`[security-scan ${scanType}] Timed out after 25s`);
      return { success: false, error: 'Scan timed out', scanType, target };
    }
    console.error(`[security-scan ${scanType}] Error:`, error);
    return { success: false, error: error.message, scanType, target };
  }
}

async function executePhase(phase: string, target: string, authHeader: string): Promise<any> {
  const scanTypes = PHASE_SCAN_TYPES[phase] || [];
  const phaseOutput: string[] = [];
  const startTime = Date.now();

  phaseOutput.push(`[${phase}] Running ${scanTypes.length} scans in parallel against ${target}...`);

  // Run all scans in parallel for speed
  const scanPromises = scanTypes.map(scanType => 
    callSecurityScan(scanType, target, authHeader).then(result => ({ scanType, result }))
  );

  const results = await Promise.all(scanPromises);
  const findings: Finding[] = [];

  for (const { scanType, result } of results) {
    if (result.success !== false && result.results) {
      const scanFindings = extractFindings(result, scanType, phase, target);
      findings.push(...scanFindings);
      phaseOutput.push(`[${phase}] ${scanType}: ${scanFindings.length} findings`);
    } else {
      phaseOutput.push(`[${phase}] ${scanType}: ${result.error || 'no results'}`);
    }
  }

  return {
    findings,
    output: phaseOutput,
    execution_time: Date.now() - startTime,
    scans_completed: scanTypes.length
  };
}

function extractFindings(scanResult: any, scanType: string, phase: string, target: string): Finding[] {
  const findings: Finding[] = [];
  const results = scanResult.results || scanResult;
  
  // Parse structured results from security-scan
  if (results.vulnerabilities && Array.isArray(results.vulnerabilities)) {
    for (const vuln of results.vulnerabilities) {
      findings.push({
        id: crypto.randomUUID(),
        type: vuln.type || scanType,
        severity: mapSeverity(vuln.severity || vuln.risk || 'info'),
        title: vuln.name || vuln.title || `${scanType} finding`,
        description: vuln.description || vuln.detail || `Discovered via ${scanType}`,
        evidence: { raw: vuln, scanType, target },
        timestamp: new Date().toISOString(),
        phase,
        tool_used: scanType,
        exploitable: vuln.exploitable ?? (vuln.severity === 'critical' || vuln.severity === 'high')
      });
    }
  }

  // Parse flat results (ports, services, headers, etc.)
  if (results.ports && Array.isArray(results.ports)) {
    for (const port of results.ports) {
      findings.push({
        id: crypto.randomUUID(),
        type: 'open_port',
        severity: port.service?.includes('http') ? 'info' : 'low',
        title: `Open port ${port.port}/${port.protocol || 'tcp'}`,
        description: `Service: ${port.service || 'unknown'} | Version: ${port.version || 'unknown'}`,
        evidence: { port, scanType, target },
        timestamp: new Date().toISOString(),
        phase,
        tool_used: scanType,
        exploitable: false
      });
    }
  }

  // Generic findings from scan output
  if (results.findings && Array.isArray(results.findings)) {
    for (const f of results.findings) {
      findings.push({
        id: crypto.randomUUID(),
        type: f.type || scanType,
        severity: mapSeverity(f.severity || 'info'),
        title: f.title || f.name || `${scanType} discovery`,
        description: f.description || f.detail || JSON.stringify(f).slice(0, 200),
        evidence: { raw: f, scanType, target },
        timestamp: new Date().toISOString(),
        phase,
        tool_used: scanType,
        exploitable: f.exploitable ?? false
      });
    }
  }

  // If scan returned data but no structured findings, create a summary finding
  if (findings.length === 0 && results && typeof results === 'object') {
    const keys = Object.keys(results).filter(k => k !== 'scanType' && k !== 'target');
    if (keys.length > 0) {
      findings.push({
        id: crypto.randomUUID(),
        type: 'scan_data',
        severity: 'info',
        title: `${scanType} scan data collected`,
        description: `Collected: ${keys.join(', ')}`,
        evidence: { data: results, scanType, target },
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

// ===== Continuous Operation =====

async function executeContinuousOperation(
  state: AgentState, objective: string, config: any, authHeader: string
): Promise<any> {
  const allFindings: Finding[] = [];
  const allCorrelations: Correlation[] = [];
  const learningUpdates: any[] = [];
  const phaseOutputs: Record<string, string[]> = {};

  // Run recon + scanning in parallel (they're independent)
  console.log(`[Red Team] Running recon + scanning in parallel | Target: ${state.target}`);
  const [reconResult, scanningResult] = await Promise.all([
    executePhase('recon', state.target, authHeader),
    executePhase('scanning', state.target, authHeader)
  ]);

  allFindings.push(...reconResult.findings, ...scanningResult.findings);
  phaseOutputs['recon'] = reconResult.output;
  phaseOutputs['scanning'] = scanningResult.output;

  // Run exploitation + post-exploit in parallel
  console.log(`[Red Team] Running exploitation + post-exploit in parallel | Findings so far: ${allFindings.length}`);
  const [exploitResult, postExploitResult] = await Promise.all([
    executePhase('exploitation', state.target, authHeader),
    executePhase('post-exploit', state.target, authHeader)
  ]);

  allFindings.push(...exploitResult.findings, ...postExploitResult.findings);
  phaseOutputs['exploitation'] = exploitResult.output;
  phaseOutputs['post-exploit'] = postExploitResult.output;

  // Run correlation locally (no AI call needed)
  if (allFindings.length >= 2) {
    const correlations = await correlateFindings(allFindings, { target: state.target });
    allCorrelations.push(...correlations);
  }

  // Generate attack chains locally
  const attackChains = await generateAttackChains(allCorrelations, { target: state.target });

  // Generate lightweight learning updates (no AI calls)
  for (const phase of ['recon', 'scanning', 'exploitation', 'post-exploit']) {
    const phaseFindings = allFindings.filter(f => f.phase === phase);
    learningUpdates.push({
      phase,
      success: phaseFindings.length > 0,
      findings_count: phaseFindings.length,
      confidence: 0.5 + (phaseFindings.length > 0 ? 0.1 : 0),
      adaptation_strategy: phaseFindings.length === 0 ? 'expand_scan_scope' : 'deepen_analysis'
    });
  }

  return {
    findings: allFindings,
    correlations: allCorrelations,
    attack_chains: attackChains,
    learning_updates: learningUpdates,
    phase_outputs: phaseOutputs,
    iterations_completed: 4,
    total_scans: Object.values(PHASE_SCAN_TYPES).flat().length
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
          { role: 'system', content: 'You are an expert red team AI agent. Provide strategic guidance for each VAPT phase. Respond with brief JSON.' },
          { role: 'user', content: `Phase: ${phase}\nTarget: ${target}\nObjective: ${objective}\nFindings so far: ${currentFindings.length}\n\nProvide strategy as JSON: {"priority_scans":["scan1"],"reasoning":"brief","risk_areas":["area1"]}` }
        ],
        max_tokens: 300
      })
    });
    if (!response.ok) { await response.text(); return { strategy: 'default' }; }
    const result = await response.json();
    const content = result.choices?.[0]?.message?.content || '';
    const jsonMatch = content.match(/\{[\s\S]*\}/);
    if (jsonMatch) return JSON.parse(jsonMatch[0]);
  } catch (e) { console.warn('Strategy AI error:', e); }
  return { strategy: 'default' };
}

// ===== Learning Context =====

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

// ===== Correlation Engine =====

async function correlateFindings(findings: Finding[], context: any): Promise<Correlation[]> {
  const correlations: Correlation[] = [];
  
  const criticalFindings = findings.filter(f => f.severity === 'critical' || f.severity === 'high');
  const exploitableFindings = findings.filter(f => f.exploitable);
  
  if (criticalFindings.length >= 2) {
    correlations.push({
      id: crypto.randomUUID(),
      findings: criticalFindings.map(f => f.id),
      attack_path: 'Critical vulnerability chain',
      risk_amplification: 1.5,
      exploitation_probability: 0.8,
      description: `${criticalFindings.length} critical findings can be chained for maximum impact`
    });
  }

  if (exploitableFindings.length >= 3) {
    correlations.push({
      id: crypto.randomUUID(),
      findings: exploitableFindings.map(f => f.id),
      attack_path: 'Multi-stage exploitation',
      risk_amplification: 1.3,
      exploitation_probability: 0.7,
      description: `${exploitableFindings.length} exploitable vulnerabilities enable lateral movement`
    });
  }

  // Group findings by type for pattern detection
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

  // AI-enhanced correlation
  if (LOVABLE_API_KEY && findings.length >= 5) {
    try {
      const aiCorrelation = await getAICorrelation(findings, context);
      if (aiCorrelation) correlations.push(aiCorrelation);
    } catch (error) { console.error('AI correlation error:', error); }
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
        { role: 'system', content: 'You are a security expert analyzing vulnerability correlations. Identify attack paths and risk amplification patterns.' },
        { role: 'user', content: `Analyze findings and identify correlations:\n${JSON.stringify(findings.slice(0, 10), null, 2)}\nContext: ${JSON.stringify(context)}\nRespond JSON: {"attack_path":"desc","risk_amplification":number,"exploitation_probability":number,"description":"explanation"}` }
      ],
      max_tokens: 400
    })
  });

  if (!response.ok) { await response.text(); return null; }
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

// ===== Attack Chain Generation =====

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
    { order: 1, tool: 'reconnaissance', action: 'Information gathering', target_component: 'External surface', expected_outcome: 'Target mapping complete', dependencies: [] },
    { order: 2, tool: 'vulnerability-scanner', action: 'Vulnerability assessment', target_component: 'Identified services', expected_outcome: 'Vulnerability list', dependencies: ['1'] },
    { order: 3, tool: 'exploit-framework', action: 'Exploitation attempt', target_component: 'Vulnerable service', expected_outcome: 'Initial access', dependencies: ['2'] }
  ];
  if (correlation.risk_amplification > 1.3) {
    steps.push({ order: 4, tool: 'privilege-escalation', action: 'Privilege escalation', target_component: 'Compromised system', expected_outcome: 'Elevated privileges', dependencies: ['3'] });
  }
  return steps;
}

function getMitreMapping(attackPath: string): string[] {
  const mappings: string[] = [];
  if (attackPath.includes('Critical') || attackPath.includes('chain')) {
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

// ===== Learning Engine =====

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
    learning.analysis = `Technique ${technique} successful with ${result.findings?.length || 0} findings - reinforcing pattern`;
    learning.next_action = 'continue_with_variations';
  }

  learning.confidence = calculateTechniqueConfidence(result);
  return learning;
}

async function generateAdaptationStrategy(technique: string, targetType: string, context: any): Promise<any> {
  if (!LOVABLE_API_KEY) {
    return { recommended_action: 'try_alternative_technique', alternative_techniques: ['nuclei', 'nikto', 'whatweb'], parameter_adjustments: { intensity: 'lower', stealth: 'higher' } };
  }

  try {
    const response = await fetch(AI_GATEWAY_URL, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${LOVABLE_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'google/gemini-2.5-flash',
        messages: [
          { role: 'system', content: 'You are a security expert adapting attack strategies. Respond with brief JSON.' },
          { role: 'user', content: `Technique "${technique}" produced no results against "${targetType}". Context: ${JSON.stringify(context)}\nSuggest adaptations as JSON: {"recommended_action":"action","alternative_techniques":["t1"],"reasoning":"brief"}` }
        ],
        max_tokens: 300
      })
    });

    if (!response.ok) { await response.text(); throw new Error('AI API error'); }
    const result = await response.json();
    const content = result.choices?.[0]?.message?.content || '';
    const jsonMatch = content.match(/\{[\s\S]*\}/);
    if (jsonMatch) return JSON.parse(jsonMatch[0]);
  } catch (error) { console.error('Adaptation strategy error:', error); }

  return { recommended_action: 'try_alternative_technique', alternative_techniques: ['nuclei', 'nikto'], parameter_adjustments: {} };
}

function calculateTechniqueConfidence(result: any): number {
  let confidence = 0.5;
  if (result.success) confidence += 0.2;
  if (result.findings?.length > 0) confidence += 0.1 * Math.min(result.findings.length, 3);
  if (result.execution_time < 5000) confidence += 0.1;
  return Math.min(0.95, confidence);
}

// ===== Fine-Tuning =====

async function fineTuneAgentModel(trainingData: any[], modelType: string): Promise<any> {
  const patterns = extractPatterns(trainingData);
  return {
    model_type: modelType,
    training_samples: trainingData.length,
    patterns_extracted: patterns.length,
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

// ===== Recommendations =====

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
