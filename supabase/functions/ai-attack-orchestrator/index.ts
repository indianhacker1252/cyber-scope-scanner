import "https://deno.land/x/xhr@0.1.0/mod.ts";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.7.1';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const supabaseClient = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_ANON_KEY') ?? '',
      {
        global: {
          headers: { Authorization: req.headers.get('Authorization')! },
        },
      }
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
        // Deep target analysis with AI
        const { target, reconnaissance_data } = requestData;
        
        const prompt = `You are an elite offensive security AI. Analyze this target and reconnaissance data:

TARGET: ${target}

RECONNAISSANCE DATA:
${JSON.stringify(reconnaissance_data, null, 2)}

Provide a comprehensive analysis in JSON format:
{
  "tech_stack": ["detected technologies with versions"],
  "vulnerabilities": ["potential vulnerabilities with CVEs if applicable"],
  "attack_surface": ["exposed services, ports, endpoints"],
  "weak_points": ["prioritized weak points to exploit"],
  "recommended_attack_chain": [
    {
      "step": 1,
      "technique": "technique name",
      "tool": "tool to use",
      "command": "exact command",
      "reason": "why this step",
      "success_indicators": ["what indicates success"]
    }
  ],
  "ai_confidence": "high/medium/low",
  "estimated_difficulty": "trivial/easy/medium/hard/expert"
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
        const analysis = JSON.parse(aiData.choices[0].message.content);

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
        // Create intelligent multi-stage attack chain
        const { target, objective, intelligence } = requestData;

        const prompt = `You are an advanced penetration testing AI. Create a sophisticated attack chain:

TARGET: ${target}
OBJECTIVE: ${objective}

INTELLIGENCE:
${JSON.stringify(intelligence, null, 2)}

Create a multi-stage attack chain that automatically adapts. Return JSON:
{
  "chain_name": "descriptive name",
  "attack_sequence": [
    {
      "stage": 1,
      "name": "stage name",
      "technique": "technique",
      "tool": "tool name",
      "command": "exact command with parameters",
      "expected_output": "what to expect",
      "success_criteria": "how to verify success",
      "on_success": "next stage number or 'complete'",
      "on_failure": "alternative stage number or adaptation needed",
      "timeout": "max execution time in seconds"
    }
  ],
  "total_stages": "number",
  "estimated_time": "estimated time to complete",
  "risk_level": "low/medium/high/critical"
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
        const chain = JSON.parse(aiData.choices[0].message.content);

        // Store attack chain
        const { data: chainData } = await supabaseClient.from('attack_chains').insert({
          user_id: user.id,
          target,
          chain_name: chain.chain_name,
          attack_sequence: chain.attack_sequence,
          status: 'ready'
        }).select().single();

        return new Response(JSON.stringify({ success: true, chain, chain_id: chainData.id }), {
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