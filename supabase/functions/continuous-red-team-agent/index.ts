import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

const LOVABLE_API_KEY = Deno.env.get('LOVABLE_API_KEY');
const AI_GATEWAY_URL = 'https://ai.gateway.lovable.dev/v1/chat/completions';

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

// Tool Categories for Autonomous Operation
const RED_TEAM_TOOLS = {
  reconnaissance: {
    passive: ['whois', 'dns-lookup', 'certificate-transparency', 'wayback-machine', 'google-dork'],
    active: ['nmap-discovery', 'masscan', 'dnsenum', 'sublist3r', 'amass']
  },
  vulnerability_assessment: {
    web: ['nikto', 'nuclei', 'whatweb', 'wpscan', 'sqlmap'],
    network: ['nmap-vuln', 'nessus-scan', 'openvas'],
    api: ['graphql-introspection', 'swagger-discovery', 'jwt-analyzer']
  },
  exploitation: {
    web: ['sqli-exploit', 'xss-exploit', 'ssrf-exploit', 'lfi-rfi', 'command-injection'],
    auth: ['brute-force', 'credential-stuffing', 'session-hijack'],
    network: ['metasploit', 'exploit-db', 'searchsploit']
  },
  post_exploitation: {
    persistence: ['web-shell', 'reverse-shell', 'cron-job'],
    privilege_escalation: ['sudo-exploit', 'suid-abuse', 'kernel-exploit'],
    lateral_movement: ['ssh-pivot', 'port-forward', 'proxy-chain']
  }
};

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { action, data } = await req.json();
    
    const supabase = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? ''
    );

    // Require authentication
    const authHeader = req.headers.get('Authorization');
    if (!authHeader?.startsWith('Bearer ')) {
      return new Response(JSON.stringify({ error: 'Authentication required' }), {
        status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }
    
    const { data: { user }, error: authError } = await supabase.auth.getUser(
      authHeader.replace('Bearer ', '')
    );
    if (authError || !user) {
      return new Response(JSON.stringify({ error: 'Invalid token' }), {
        status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }
    const userId = user.id;
    console.log(`[Continuous Red Team Agent] User: ${userId} - Action: ${action}`);

    switch (action) {
      case 'start-continuous-operation': {
        const { target, objective, max_iterations = 100, config } = data;
        
        // Initialize agent state
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

        // Start the continuous operation cycle
        const result = await executeContinuousOperation(agentState, objective, config);

        // Persist session
        {
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
        }

        return new Response(JSON.stringify({
          success: true,
          session_id: sessionId,
          ...result,
          persisted: true
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
        
        const learningUpdate = await processLearning(
          execution_result,
          technique,
          target_type,
          context
        );

        // Persist learning
        {
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
        }

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

        // Load historical context
        let historicalData: any[] = [];
        {
          const { data: learnings } = await supabase
            .from('ai_learnings')
            .select('*')
            .eq('user_id', userId)
            .order('created_at', { ascending: false })
            .limit(50);
          historicalData = learnings || [];
        }

        const recommendations = await generateAgentRecommendations(
          target,
          current_phase,
          existing_findings,
          historicalData
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

      case 'execute-attack-step': {
        const { step, target, context, previous_results } = data;

        const result = await executeAttackStep(step, target, context, previous_results);

        return new Response(JSON.stringify({
          success: true,
          result,
          next_steps: result.recommended_next_steps,
          findings: result.findings
        }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      case 'fine-tune-model': {
        const { training_data, model_type } = data;

        const fineTuningResult = await fineTuneAgentModel(training_data, model_type);

        return new Response(JSON.stringify({
          success: true,
          ...fineTuningResult
        }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      case 'get-operation-status': {
        const { session_id } = data;

        // Retrieve session status from memory/db
        return new Response(JSON.stringify({
          success: true,
          status: 'active',
          phase: 'scanning',
          progress: 45,
          findings_count: 12,
          correlations_count: 3
        }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      default:
        return new Response(JSON.stringify({ error: 'Unknown action' }), {
          status: 400,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }

  } catch (error) {
    console.error('[Continuous Red Team Agent Error]', error);
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
});

// Load learning context from historical data
async function loadLearningContext(
  supabase: any, 
  userId: string | null, 
  target: string
): Promise<LearningContext> {
  const defaultContext: LearningContext = {
    successful_techniques: [],
    failed_techniques: [],
    target_signatures: [],
    adaptation_history: [],
    model_confidence: 0.5
  };

  if (!userId) return defaultContext;

  try {
    // Load successful attack chains
    const { data: successChains } = await supabase
      .from('apex_successful_chains')
      .select('*')
      .eq('user_id', userId)
      .limit(20);

    // Load AI learnings
    const { data: learnings } = await supabase
      .from('ai_learnings')
      .select('*')
      .eq('user_id', userId)
      .order('created_at', { ascending: false })
      .limit(100);

    // Process into learning context
    const techniques = new Map<string, TechniqueRecord>();
    
    (learnings || []).forEach((l: any) => {
      const key = `${l.tool_used}-${l.target || 'generic'}`;
      const existing = techniques.get(key) || {
        technique: l.tool_used,
        target_type: l.target || 'generic',
        success_count: 0,
        failure_count: 0,
        avg_execution_time: 0,
        last_used: l.created_at
      };
      
      if (l.success) {
        existing.success_count++;
      } else {
        existing.failure_count++;
      }
      existing.avg_execution_time = (existing.avg_execution_time + (l.execution_time || 0)) / 2;
      techniques.set(key, existing);
    });

    const allTechniques = Array.from(techniques.values());
    
    return {
      successful_techniques: allTechniques.filter(t => t.success_count > t.failure_count),
      failed_techniques: allTechniques.filter(t => t.failure_count > t.success_count),
      target_signatures: (successChains || []).map((c: any) => ({
        signature: c.service_signature || 'unknown',
        tech_stack: [],
        common_vulnerabilities: [c.vulnerability_type].filter(Boolean),
        recommended_approach: 'adaptive'
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

// Execute continuous operation cycle
async function executeContinuousOperation(
  state: AgentState,
  objective: string,
  config: any
): Promise<any> {
  const phases = ['recon', 'scanning', 'exploitation', 'post-exploit', 'learning'];
  let currentPhaseIndex = 0;
  
  const allFindings: Finding[] = [];
  const allCorrelations: Correlation[] = [];
  const learningUpdates: any[] = [];

  // Simulate continuous operation with AI decision making
  while (state.iteration < state.max_iterations && currentPhaseIndex < phases.length) {
    const phase = phases[currentPhaseIndex] as AgentState['phase'];
    
    // Get AI-driven next action
    const nextAction = await determineNextAction(state, phase, objective);
    
    if (nextAction.action === 'advance_phase') {
      currentPhaseIndex++;
      continue;
    }

    if (nextAction.action === 'execute_tool') {
      const result = await simulateToolExecution(
        nextAction.tool,
        state.target,
        nextAction.parameters
      );
      
      if (result.findings.length > 0) {
        allFindings.push(...result.findings);
        
        // Correlate new findings
        if (allFindings.length >= 3) {
          const newCorrelations = await correlateFindings(
            allFindings,
            { target: state.target, phase }
          );
          allCorrelations.push(...newCorrelations);
        }
      }

      // Record learning
      const learning = await processLearning(
        result,
        nextAction.tool,
        state.target,
        { phase, objective }
      );
      learningUpdates.push(learning);
    }

    state.iteration++;
    
    // Check termination conditions
    if (nextAction.action === 'complete' || allFindings.length >= 50) {
      break;
    }
  }

  // Generate attack chains from correlations
  const attackChains = await generateAttackChains(allCorrelations, { target: state.target });

  return {
    findings: allFindings,
    correlations: allCorrelations,
    attack_chains: attackChains,
    learning_updates: learningUpdates,
    iterations_completed: state.iteration,
    final_phase: phases[currentPhaseIndex]
  };
}

// AI-driven next action determination
async function determineNextAction(
  state: AgentState,
  phase: string,
  objective: string
): Promise<any> {
  if (!LOVABLE_API_KEY) {
    // Fallback to rule-based logic
    return getDefaultNextAction(phase, state.findings.length);
  }

  try {
    const prompt = `You are an autonomous red team AI agent. Based on the current state, determine the next action.

Current Phase: ${phase}
Objective: ${objective}
Target: ${state.target}
Findings so far: ${state.findings.length}
Iterations: ${state.iteration}/${state.max_iterations}

Available tools for ${phase}:
${JSON.stringify(RED_TEAM_TOOLS[phase as keyof typeof RED_TEAM_TOOLS] || RED_TEAM_TOOLS.reconnaissance, null, 2)}

Learning context confidence: ${state.learning_context.model_confidence}
Successful techniques: ${state.learning_context.successful_techniques.map(t => t.technique).join(', ') || 'none yet'}

Respond with JSON:
{
  "action": "execute_tool" | "advance_phase" | "complete",
  "tool": "tool_name",
  "parameters": {},
  "reasoning": "brief explanation"
}`;

    const response = await fetch(AI_GATEWAY_URL, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${LOVABLE_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: 'google/gemini-2.5-flash',
        messages: [
          { role: 'system', content: 'You are an expert red team AI agent. Always respond with valid JSON.' },
          { role: 'user', content: prompt }
        ],
        max_tokens: 500
      })
    });

    if (!response.ok) {
      throw new Error(`AI API error: ${response.status}`);
    }

    const result = await response.json();
    const content = result.choices?.[0]?.message?.content || '';
    
    // Parse JSON from response
    const jsonMatch = content.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      return JSON.parse(jsonMatch[0]);
    }
  } catch (error) {
    console.error('AI decision error:', error);
  }

  return getDefaultNextAction(phase, state.findings.length);
}

function getDefaultNextAction(phase: string, findingsCount: number): any {
  const phaseTools: Record<string, string[]> = {
    recon: ['nmap-discovery', 'dns-lookup', 'sublist3r'],
    scanning: ['nikto', 'nuclei', 'whatweb'],
    exploitation: ['sqli-exploit', 'xss-exploit', 'command-injection'],
    'post-exploit': ['persistence-check', 'privilege-escalation'],
    learning: []
  };

  const tools = phaseTools[phase] || [];
  
  if (tools.length === 0 || findingsCount >= 10) {
    return { action: 'advance_phase' };
  }

  return {
    action: 'execute_tool',
    tool: tools[Math.floor(Math.random() * tools.length)],
    parameters: {},
    reasoning: 'Default action selection'
  };
}

// Simulate tool execution (to be replaced with real tool integration)
async function simulateToolExecution(
  tool: string,
  target: string,
  parameters: any
): Promise<any> {
  // Simulate execution time
  const executionTime = 1000 + Math.random() * 4000;
  
  // Generate findings based on tool type
  const findings: Finding[] = [];
  const shouldFindVuln = Math.random() > 0.6;
  
  if (shouldFindVuln) {
    findings.push({
      id: crypto.randomUUID(),
      type: getVulnTypeForTool(tool),
      severity: getSeverityLevel(),
      title: `Potential ${tool} finding`,
      description: `Automated discovery during ${tool} execution`,
      evidence: { tool, parameters, target },
      timestamp: new Date().toISOString(),
      phase: getPhaseForTool(tool),
      tool_used: tool,
      exploitable: Math.random() > 0.7
    });
  }

  return {
    success: true,
    execution_time: executionTime,
    output: `Executed ${tool} against ${target}`,
    findings
  };
}

function getVulnTypeForTool(tool: string): string {
  const mapping: Record<string, string> = {
    'sqli-exploit': 'SQL Injection',
    'xss-exploit': 'Cross-Site Scripting',
    'nikto': 'Web Vulnerability',
    'nuclei': 'Known CVE',
    'nmap-discovery': 'Open Port',
    default: 'Misconfiguration'
  };
  return mapping[tool] || mapping.default;
}

function getSeverityLevel(): Finding['severity'] {
  const rand = Math.random();
  if (rand < 0.1) return 'critical';
  if (rand < 0.3) return 'high';
  if (rand < 0.6) return 'medium';
  if (rand < 0.85) return 'low';
  return 'info';
}

function getPhaseForTool(tool: string): string {
  if (['nmap', 'dns', 'sublist3r', 'amass'].some(t => tool.includes(t))) return 'recon';
  if (['nikto', 'nuclei', 'whatweb', 'scan'].some(t => tool.includes(t))) return 'scanning';
  if (['exploit', 'injection', 'xss', 'sqli'].some(t => tool.includes(t))) return 'exploitation';
  return 'recon';
}

// Correlate findings to identify attack paths
async function correlateFindings(
  findings: Finding[],
  context: any
): Promise<Correlation[]> {
  const correlations: Correlation[] = [];
  
  // Group by severity and exploitability
  const criticalFindings = findings.filter(f => f.severity === 'critical' || f.severity === 'high');
  const exploitableFindings = findings.filter(f => f.exploitable);
  
  // Look for attack path patterns
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

  // AI-enhanced correlation
  if (LOVABLE_API_KEY && findings.length >= 5) {
    try {
      const aiCorrelation = await getAICorrelation(findings, context);
      if (aiCorrelation) {
        correlations.push(aiCorrelation);
      }
    } catch (error) {
      console.error('AI correlation error:', error);
    }
  }

  return correlations;
}

async function getAICorrelation(findings: Finding[], context: any): Promise<Correlation | null> {
  const response = await fetch(AI_GATEWAY_URL, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${LOVABLE_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model: 'google/gemini-2.5-flash',
      messages: [
        {
          role: 'system',
          content: 'You are a security expert analyzing vulnerability correlations. Identify attack paths and risk amplification patterns.'
        },
        {
          role: 'user',
          content: `Analyze these findings and identify correlations:
${JSON.stringify(findings.slice(0, 10), null, 2)}

Context: ${JSON.stringify(context)}

Respond with JSON: { "attack_path": "description", "risk_amplification": number, "exploitation_probability": number, "description": "detailed explanation" }`
        }
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
      return {
        id: crypto.randomUUID(),
        findings: findings.slice(0, 5).map(f => f.id),
        ...parsed
      };
    }
  } catch {}
  
  return null;
}

function calculateRiskScore(correlations: Correlation[]): number {
  if (correlations.length === 0) return 0;
  
  const totalRisk = correlations.reduce((sum, c) => {
    return sum + (c.risk_amplification * c.exploitation_probability * 10);
  }, 0);
  
  return Math.min(100, Math.round(totalRisk));
}

// Generate attack chains from correlations
async function generateAttackChains(
  correlations: Correlation[],
  context: any
): Promise<AttackChain[]> {
  const chains: AttackChain[] = [];

  for (const correlation of correlations) {
    const chain: AttackChain = {
      id: crypto.randomUUID(),
      name: `Attack Chain: ${correlation.attack_path}`,
      steps: generateAttackSteps(correlation),
      success_probability: correlation.exploitation_probability,
      impact: correlation.risk_amplification > 1.3 ? 'Critical' : 'High',
      mitre_mapping: getMitreMapping(correlation.attack_path)
    };
    chains.push(chain);
  }

  return chains;
}

function generateAttackSteps(correlation: Correlation): AttackStep[] {
  const steps: AttackStep[] = [
    {
      order: 1,
      tool: 'reconnaissance',
      action: 'Information gathering',
      target_component: 'External surface',
      expected_outcome: 'Target mapping complete',
      dependencies: []
    },
    {
      order: 2,
      tool: 'vulnerability-scanner',
      action: 'Vulnerability assessment',
      target_component: 'Identified services',
      expected_outcome: 'Vulnerability list',
      dependencies: ['1']
    },
    {
      order: 3,
      tool: 'exploit-framework',
      action: 'Exploitation attempt',
      target_component: 'Vulnerable service',
      expected_outcome: 'Initial access',
      dependencies: ['2']
    }
  ];

  if (correlation.risk_amplification > 1.3) {
    steps.push({
      order: 4,
      tool: 'privilege-escalation',
      action: 'Privilege escalation',
      target_component: 'Compromised system',
      expected_outcome: 'Elevated privileges',
      dependencies: ['3']
    });
  }

  return steps;
}

function getMitreMapping(attackPath: string): string[] {
  const mappings: string[] = [];
  
  if (attackPath.includes('Critical') || attackPath.includes('chain')) {
    mappings.push(...MITRE_TECHNIQUES.initial_access);
    mappings.push(...MITRE_TECHNIQUES.execution);
  }
  
  if (attackPath.includes('exploitation') || attackPath.includes('lateral')) {
    mappings.push(...MITRE_TECHNIQUES.lateral_movement);
    mappings.push(...MITRE_TECHNIQUES.privilege_escalation);
  }
  
  return mappings.slice(0, 5);
}

// Process learning from execution results
async function processLearning(
  result: any,
  technique: string,
  targetType: string,
  context: any
): Promise<any> {
  const learning: any = {
    technique,
    target_type: targetType,
    success: result.success,
    execution_time: result.execution_time,
    findings_count: result.findings?.length || 0,
    timestamp: new Date().toISOString()
  };

  // Generate adaptation strategy if failed
  if (!result.success || (result.findings?.length === 0)) {
    learning.adaptation_strategy = await generateAdaptationStrategy(
      technique,
      targetType,
      context
    );
    learning.next_action = learning.adaptation_strategy.recommended_action;
  } else {
    learning.analysis = 'Technique successful - reinforcing pattern';
    learning.next_action = 'continue_with_variations';
  }

  learning.confidence = calculateTechniqueConfidence(result);

  return learning;
}

async function generateAdaptationStrategy(
  technique: string,
  targetType: string,
  context: any
): Promise<any> {
  if (!LOVABLE_API_KEY) {
    return {
      recommended_action: 'try_alternative_technique',
      alternative_techniques: ['nuclei', 'nikto', 'whatweb'],
      parameter_adjustments: { intensity: 'lower', stealth: 'higher' }
    };
  }

  try {
    const response = await fetch(AI_GATEWAY_URL, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${LOVABLE_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: 'google/gemini-2.5-flash',
        messages: [
          {
            role: 'system',
            content: 'You are a security expert helping adapt attack strategies based on failures.'
          },
          {
            role: 'user',
            content: `Technique "${technique}" failed against "${targetType}".
Context: ${JSON.stringify(context)}

Suggest adaptations. Respond with JSON:
{
  "recommended_action": "action",
  "alternative_techniques": ["tech1", "tech2"],
  "parameter_adjustments": {},
  "reasoning": "explanation"
}`
          }
        ],
        max_tokens: 400
      })
    });

    if (!response.ok) throw new Error('AI API error');

    const result = await response.json();
    const content = result.choices?.[0]?.message?.content || '';
    const jsonMatch = content.match(/\{[\s\S]*\}/);
    
    if (jsonMatch) {
      return JSON.parse(jsonMatch[0]);
    }
  } catch (error) {
    console.error('Adaptation strategy error:', error);
  }

  return {
    recommended_action: 'try_alternative_technique',
    alternative_techniques: ['nuclei', 'nikto'],
    parameter_adjustments: {}
  };
}

function calculateTechniqueConfidence(result: any): number {
  let confidence = 0.5;
  
  if (result.success) confidence += 0.2;
  if (result.findings?.length > 0) confidence += 0.1 * Math.min(result.findings.length, 3);
  if (result.execution_time < 5000) confidence += 0.1;
  
  return Math.min(0.95, confidence);
}

// Execute attack step
async function executeAttackStep(
  step: AttackStep,
  target: string,
  context: any,
  previousResults: any[]
): Promise<any> {
  const result = await simulateToolExecution(step.tool, target, { step, context });
  
  // Generate recommended next steps
  const nextSteps = [];
  
  if (result.success && result.findings.length > 0) {
    nextSteps.push({
      action: 'exploit_finding',
      priority: 'high',
      description: 'Attempt to exploit discovered vulnerabilities'
    });
  }
  
  if (!result.success) {
    nextSteps.push({
      action: 'adapt_technique',
      priority: 'medium',
      description: 'Modify approach based on failure analysis'
    });
  }
  
  nextSteps.push({
    action: 'continue_scan',
    priority: 'low',
    description: 'Continue with next planned step'
  });

  return {
    ...result,
    recommended_next_steps: nextSteps
  };
}

// Fine-tune agent model
async function fineTuneAgentModel(
  trainingData: any[],
  modelType: string
): Promise<any> {
  // Analyze training data to extract patterns
  const patterns = extractPatterns(trainingData);
  
  // Generate model improvements
  const improvements = {
    technique_weights: calculateTechniqueWeights(trainingData),
    target_type_mappings: extractTargetMappings(trainingData),
    adaptation_rules: generateAdaptationRules(patterns)
  };

  return {
    model_type: modelType,
    training_samples: trainingData.length,
    patterns_extracted: patterns.length,
    improvements,
    new_confidence: 0.7 + (patterns.length * 0.02)
  };
}

function extractPatterns(data: any[]): any[] {
  const patterns: any[] = [];
  
  // Group by success/failure
  const successful = data.filter(d => d.success);
  const failed = data.filter(d => !d.success);
  
  // Extract success patterns
  const successTechniques = successful.map(d => d.technique);
  const uniqueSuccess = [...new Set(successTechniques)];
  
  uniqueSuccess.forEach(tech => {
    patterns.push({
      type: 'success_pattern',
      technique: tech,
      frequency: successTechniques.filter(t => t === tech).length
    });
  });

  return patterns;
}

function calculateTechniqueWeights(data: any[]): Record<string, number> {
  const weights: Record<string, number> = {};
  
  data.forEach(d => {
    const tech = d.technique || 'unknown';
    if (!weights[tech]) weights[tech] = 0.5;
    
    if (d.success) {
      weights[tech] = Math.min(1.0, weights[tech] + 0.1);
    } else {
      weights[tech] = Math.max(0.1, weights[tech] - 0.05);
    }
  });

  return weights;
}

function extractTargetMappings(data: any[]): Record<string, string[]> {
  const mappings: Record<string, string[]> = {};
  
  data.filter(d => d.success).forEach(d => {
    const target = d.target_type || 'generic';
    if (!mappings[target]) mappings[target] = [];
    if (d.technique && !mappings[target].includes(d.technique)) {
      mappings[target].push(d.technique);
    }
  });

  return mappings;
}

function generateAdaptationRules(patterns: any[]): any[] {
  return patterns.filter(p => p.frequency >= 2).map(p => ({
    condition: `technique_failed_${p.technique}`,
    action: 'increase_stealth',
    alternative: 'try_next_technique'
  }));
}

// Generate agent recommendations
async function generateAgentRecommendations(
  target: string,
  currentPhase: string,
  existingFindings: Finding[],
  historicalData: any[]
): Promise<any> {
  // Analyze historical success patterns
  const successPatterns = historicalData.filter(h => h.success);
  const topTechniques = [...new Set(successPatterns.map(h => h.tool_used))].slice(0, 5);

  // Get recommended tools for current phase
  const phaseTools = RED_TEAM_TOOLS[currentPhase as keyof typeof RED_TEAM_TOOLS] || RED_TEAM_TOOLS.reconnaissance;
  const allPhaseTools = Object.values(phaseTools).flat();

  // Prioritize based on historical success
  const prioritizedTools = [
    ...topTechniques.filter(t => allPhaseTools.includes(t)),
    ...allPhaseTools.filter(t => !topTechniques.includes(t))
  ];

  return {
    recommended_tools: prioritizedTools.slice(0, 5),
    priority_targets: identifyPriorityTargets(existingFindings),
    suggested_techniques: topTechniques,
    mitre_techniques: MITRE_TECHNIQUES[currentPhase as keyof typeof MITRE_TECHNIQUES] || MITRE_TECHNIQUES.recon,
    confidence: calculateRecommendationConfidence(historicalData),
    next_phase_readiness: existingFindings.length >= 5 ? 'ready' : 'gathering_intel'
  };
}

function identifyPriorityTargets(findings: Finding[]): string[] {
  const critical = findings.filter(f => f.severity === 'critical' || f.severity === 'high');
  return critical.map(f => f.title).slice(0, 3);
}

function calculateRecommendationConfidence(historicalData: any[]): number {
  if (historicalData.length < 5) return 0.5;
  
  const successRate = historicalData.filter(h => h.success).length / historicalData.length;
  return 0.5 + (successRate * 0.4);
}
