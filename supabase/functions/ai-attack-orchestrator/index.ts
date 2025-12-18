import "https://deno.land/x/xhr@0.1.0/mod.ts";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.7.1';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

// MITRE ATT&CK Framework Mapping
const MITRE_ATTACK = {
  reconnaissance: {
    tactic: 'TA0043',
    techniques: {
      'active_scanning': 'T1595',
      'gather_victim_info': 'T1592',
      'search_victim_infra': 'T1590',
      'phishing_for_info': 'T1598'
    }
  },
  resource_development: {
    tactic: 'TA0042',
    techniques: {
      'acquire_infrastructure': 'T1583',
      'develop_capabilities': 'T1587',
      'obtain_capabilities': 'T1588'
    }
  },
  initial_access: {
    tactic: 'TA0001',
    techniques: {
      'exploit_public_facing': 'T1190',
      'phishing': 'T1566',
      'supply_chain': 'T1195',
      'valid_accounts': 'T1078'
    }
  },
  execution: {
    tactic: 'TA0002',
    techniques: {
      'command_scripting': 'T1059',
      'exploitation_for_execution': 'T1203',
      'user_execution': 'T1204'
    }
  },
  persistence: {
    tactic: 'TA0003',
    techniques: {
      'create_account': 'T1136',
      'scheduled_task': 'T1053',
      'web_shell': 'T1505.003'
    }
  },
  privilege_escalation: {
    tactic: 'TA0004',
    techniques: {
      'exploitation_for_priv_esc': 'T1068',
      'access_token_manipulation': 'T1134',
      'sudo_caching': 'T1548.003'
    }
  },
  credential_access: {
    tactic: 'TA0006',
    techniques: {
      'brute_force': 'T1110',
      'credential_dumping': 'T1003',
      'input_capture': 'T1056'
    }
  },
  lateral_movement: {
    tactic: 'TA0008',
    techniques: {
      'remote_services': 'T1021',
      'exploitation_of_remote': 'T1210',
      'internal_spearphishing': 'T1534'
    }
  },
  exfiltration: {
    tactic: 'TA0010',
    techniques: {
      'exfil_over_c2': 'T1041',
      'exfil_over_web': 'T1567',
      'automated_exfil': 'T1020'
    }
  }
};

// PTES (Penetration Testing Execution Standard) Phases
const PTES_PHASES = [
  'pre_engagement',
  'intelligence_gathering', 
  'threat_modeling',
  'vulnerability_analysis',
  'exploitation',
  'post_exploitation',
  'reporting'
];

// OWASP Testing Guide v5 Categories
const OWASP_TESTS = {
  info_gathering: ['WSTG-INFO-01', 'WSTG-INFO-02', 'WSTG-INFO-03'],
  config_testing: ['WSTG-CONF-01', 'WSTG-CONF-02', 'WSTG-CONF-03'],
  identity_management: ['WSTG-IDNT-01', 'WSTG-IDNT-02'],
  authentication: ['WSTG-ATHN-01', 'WSTG-ATHN-02', 'WSTG-ATHN-03'],
  authorization: ['WSTG-ATHZ-01', 'WSTG-ATHZ-02'],
  session_management: ['WSTG-SESS-01', 'WSTG-SESS-02'],
  input_validation: ['WSTG-INPV-01', 'WSTG-INPV-02', 'WSTG-INPV-03'],
  error_handling: ['WSTG-ERRH-01', 'WSTG-ERRH-02'],
  cryptography: ['WSTG-CRYP-01', 'WSTG-CRYP-02'],
  business_logic: ['WSTG-BUSL-01', 'WSTG-BUSL-02'],
  client_side: ['WSTG-CLNT-01', 'WSTG-CLNT-02']
};

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const supabaseClient = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_ANON_KEY') ?? '',
      { global: { headers: { Authorization: req.headers.get('Authorization')! } } }
    );

    const { data: { user } } = await supabaseClient.auth.getUser();
    if (!user) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    const { action, data: requestData } = await req.json();
    const LOVABLE_API_KEY = Deno.env.get('LOVABLE_API_KEY');

    if (!LOVABLE_API_KEY) {
      throw new Error('LOVABLE_API_KEY not configured');
    }

    console.log(`AI Orchestrator - Action: ${action}`);

    switch (action) {
      case 'analyze-target': {
        const { target, reconnaissance_data } = requestData;

        // Fetch previous learnings for this target type
        const { data: previousLearnings } = await supabaseClient
          .from('ai_learnings')
          .select('*')
          .order('success_rate', { ascending: false })
          .limit(10);

        const prompt = `You are an elite offensive security AI following PTES methodology and MITRE ATT&CK framework.

TARGET: ${target}

RECONNAISSANCE DATA:
${JSON.stringify(reconnaissance_data, null, 2)}

PREVIOUS LEARNINGS (use to improve strategy):
${JSON.stringify(previousLearnings || [], null, 2)}

MITRE ATT&CK FRAMEWORK REFERENCE:
${JSON.stringify(MITRE_ATTACK, null, 2)}

OWASP TESTING GUIDE v5 CATEGORIES:
${JSON.stringify(OWASP_TESTS, null, 2)}

Provide a comprehensive analysis following PTES phases. Return JSON:
{
  "ptes_phase": "current phase recommendation",
  "tech_stack": ["detected technologies with versions"],
  "vulnerabilities": [
    {
      "name": "vulnerability name",
      "cve": "CVE-XXXX-XXXX if known",
      "severity": "critical/high/medium/low",
      "owasp_category": "relevant OWASP test ID",
      "mitre_technique": "relevant T-code"
    }
  ],
  "attack_surface": ["exposed services, ports, endpoints"],
  "weak_points": ["prioritized weak points"],
  "kill_chain": [
    {
      "phase": "reconnaissance/weaponization/delivery/exploitation/installation/c2/actions",
      "action": "specific action",
      "mitre_tactic": "TA code",
      "mitre_technique": "T code"
    }
  ],
  "recommended_attack_chain": [
    {
      "step": 1,
      "technique": "technique name",
      "tool": "tool to use",
      "command": "exact command",
      "mitre_mapping": "T-code",
      "owasp_test": "WSTG-XXX-XX",
      "success_indicators": ["what indicates success"],
      "evasion_tips": ["how to avoid detection"]
    }
  ],
  "ai_confidence": "high/medium/low",
  "estimated_difficulty": "trivial/easy/medium/hard/expert",
  "defensive_gaps": ["detected security weaknesses in defenses"]
}`;

        const aiResponse = await fetch('https://ai.gateway.lovable.dev/v1/chat/completions', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${LOVABLE_API_KEY}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            model: 'google/gemini-2.5-flash',
            messages: [{ role: 'user', content: prompt }],
          }),
        });

        const aiData = await aiResponse.json();
        let analysis;
        try {
          const content = aiData.choices[0].message.content;
          const jsonMatch = content.match(/\{[\s\S]*\}/);
          analysis = jsonMatch ? JSON.parse(jsonMatch[0]) : { raw: content };
        } catch {
          analysis = { raw: aiData.choices[0].message.content };
        }

        // Store target intelligence
        await supabaseClient.from('target_intelligence').upsert({
          user_id: user.id,
          target,
          tech_stack: analysis.tech_stack,
          vulnerabilities: analysis.vulnerabilities,
          attack_surface: analysis.attack_surface,
          weak_points: analysis.weak_points,
          ai_recommendations: analysis.recommended_attack_chain,
          last_scanned: new Date().toISOString()
        });

        return new Response(JSON.stringify({ success: true, analysis }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      case 'learn-from-failure': {
        // AI learns from failed attack and suggests adaptations
        const { attack_attempt_id, attack_output, error } = requestData;

        const prompt = `You are an elite penetration testing AI with deep learning capabilities. Analyze this failed attack and learn from it:

ATTACK OUTPUT:
${attack_output}

ERROR/FAILURE:
${error}

Analyze why the attack failed and provide adaptive strategies in JSON:
{
  "failure_analysis": "detailed root cause analysis",
  "defense_mechanisms_detected": ["WAF", "IDS", "rate limiting", etc],
  "adaptation_strategies": [
    {
      "strategy": "strategy name",
      "modified_payload": "adapted payload/command",
      "evasion_technique": "technique to bypass defenses",
      "probability_of_success": "0.0-1.0"
    }
  ],
  "alternative_attack_vectors": ["other approaches to try"],
  "learnings": "key insights for future attacks"
}`;

        const aiResponse = await fetch('https://ai.gateway.lovable.dev/v1/chat/completions', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${LOVABLE_API_KEY}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            model: 'google/gemini-2.5-flash',
            messages: [{ role: 'user', content: prompt }],
            response_format: { type: "json_object" }
          }),
        });

        const aiData = await aiResponse.json();
        const learning = JSON.parse(aiData.choices[0].message.content);

        // Store learning
        await supabaseClient.from('attack_learnings').insert({
          attack_attempt_id,
          failure_reason: learning.failure_analysis,
          adaptation_strategy: JSON.stringify(learning.adaptation_strategies),
          ai_analysis: learning.learnings
        });

        return new Response(JSON.stringify({ success: true, learning }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      case 'generate-adaptive-payload': {
        // Generate payload that adapts based on previous failures
        const { target, vulnerability_type, previous_failures } = requestData;

        const prompt = `You are an expert exploit developer. Generate an adaptive payload:

TARGET: ${target}
VULNERABILITY: ${vulnerability_type}

PREVIOUS FAILED ATTEMPTS:
${JSON.stringify(previous_failures, null, 2)}

Generate an advanced, adaptive payload that learns from failures. Return JSON:
{
  "payload": "the actual payload/exploit code",
  "delivery_method": "how to deliver it",
  "evasion_techniques": ["techniques used to bypass defenses"],
  "success_indicators": ["how to know if it worked"],
  "fallback_payloads": ["alternative payloads if this fails"],
  "obfuscation_level": "none/low/medium/high/extreme"
}`;

        const aiResponse = await fetch('https://ai.gateway.lovable.dev/v1/chat/completions', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${LOVABLE_API_KEY}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            model: 'google/gemini-2.5-flash',
            messages: [{ role: 'user', content: prompt }],
            response_format: { type: "json_object" }
          }),
        });

        const aiData = await aiResponse.json();
        const payload = JSON.parse(aiData.choices[0].message.content);

        return new Response(JSON.stringify({ success: true, payload }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      case 'create-attack-chain': {
        const { target, objective, intelligence } = requestData;

        // Fetch learnings to improve attack strategy
        const { data: successfulAttacks } = await supabaseClient
          .from('attack_attempts')
          .select('*')
          .eq('success', true)
          .order('created_at', { ascending: false })
          .limit(20);

        const prompt = `You are an advanced penetration testing AI following PTES and MITRE ATT&CK framework.

TARGET: ${target}
OBJECTIVE: ${objective}

INTELLIGENCE:
${JSON.stringify(intelligence, null, 2)}

PREVIOUS SUCCESSFUL ATTACKS (learn from these):
${JSON.stringify(successfulAttacks || [], null, 2)}

MITRE ATT&CK FRAMEWORK:
${JSON.stringify(MITRE_ATTACK, null, 2)}

PTES PHASES: ${PTES_PHASES.join(' -> ')}

Create a multi-stage attack chain with MITRE mapping. Return JSON:
{
  "chain_name": "descriptive name",
  "methodology": "PTES/OWASP/custom",
  "attack_sequence": [
    {
      "stage": 1,
      "ptes_phase": "relevant PTES phase",
      "name": "stage name",
      "technique": "technique",
      "tool": "tool name",
      "command": "exact command with parameters",
      "mitre_tactic": "TA code",
      "mitre_technique": "T code",
      "expected_output": "what to expect",
      "success_criteria": "how to verify success",
      "on_success": "next stage number or 'complete'",
      "on_failure": "adaptation: describe how AI should adapt",
      "timeout": "max execution time in seconds",
      "stealth_level": "loud/moderate/quiet/silent",
      "evasion_techniques": ["techniques to avoid detection"]
    }
  ],
  "total_stages": number,
  "estimated_time": "estimated time to complete",
  "risk_level": "low/medium/high/critical",
  "detection_probability": "low/medium/high",
  "kill_chain_coverage": ["phases covered"],
  "fallback_strategies": ["if main chain fails"]
}`;

        const aiResponse = await fetch('https://ai.gateway.lovable.dev/v1/chat/completions', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${LOVABLE_API_KEY}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            model: 'google/gemini-2.5-flash',
            messages: [{ role: 'user', content: prompt }],
          }),
        });

        const aiData = await aiResponse.json();
        let chain;
        try {
          const content = aiData.choices[0].message.content;
          const jsonMatch = content.match(/\{[\s\S]*\}/);
          chain = jsonMatch ? JSON.parse(jsonMatch[0]) : { raw: content };
        } catch {
          chain = { raw: aiData.choices[0].message.content };
        }

        const { data: chainData } = await supabaseClient.from('attack_chains').insert({
          user_id: user.id,
          target,
          chain_name: chain.chain_name || `Attack on ${target}`,
          attack_sequence: chain.attack_sequence || chain,
          status: 'ready'
        }).select().single();

        return new Response(JSON.stringify({ 
          success: true, 
          chain, 
          chain_id: chainData?.id,
          mitre_framework: MITRE_ATTACK,
          ptes_phases: PTES_PHASES
        }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      default:
        return new Response(JSON.stringify({ error: 'Unknown action' }), {
          status: 400,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
    }
  } catch (error) {
    console.error('AI Orchestrator error:', error);
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
});