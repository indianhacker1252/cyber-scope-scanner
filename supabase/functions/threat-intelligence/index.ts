import "https://deno.land/x/xhr@0.1.0/mod.ts";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { query, type } = await req.json();
    const LOVABLE_API_KEY = Deno.env.get('LOVABLE_API_KEY');

    if (!LOVABLE_API_KEY) {
      throw new Error('LOVABLE_API_KEY not configured');
    }

    let systemPrompt = '';
    
    switch (type) {
      case 'ioc-analysis':
        systemPrompt = `You are a threat intelligence analyst specializing in Indicators of Compromise (IOC) analysis. Analyze the provided IOC and provide:
- Threat classification
- Known attack campaigns
- Associated threat actors
- Recommended mitigations
- MITRE ATT&CK techniques`;
        break;
      case 'malware-analysis':
        systemPrompt = `You are a malware analyst. Analyze the provided sample characteristics and provide:
- Malware family identification
- Behavioral analysis
- C2 infrastructure
- Detection signatures
- Remediation steps`;
        break;
      case 'threat-hunting':
        systemPrompt = `You are a threat hunting expert. Based on the provided context, suggest:
- Hunting hypotheses
- Detection queries (SIEM/EDR)
- Key artifacts to investigate
- Behavioral patterns to monitor`;
        break;
      case 'vulnerability-intel':
        systemPrompt = `You are a vulnerability intelligence analyst. Provide detailed analysis including:
- Exploitability assessment
- Known exploits in the wild
- Patch prioritization
- Compensating controls
- Detection opportunities`;
        break;
      default:
        systemPrompt = 'You are a cybersecurity threat intelligence expert. Provide comprehensive analysis.';
    }

    const response = await fetch('https://ai.gateway.lovable.dev/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${LOVABLE_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: 'google/gemini-2.5-flash',
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: query }
        ],
      }),
    });

    if (!response.ok) {
      if (response.status === 429) {
        return new Response(JSON.stringify({ error: 'Rate limit exceeded' }), {
          status: 429,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }
      throw new Error(`AI API error: ${response.status}`);
    }

    const data = await response.json();
    const analysis = data.choices[0].message.content;

    return new Response(JSON.stringify({ analysis }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });

  } catch (error) {
    console.error('Threat intelligence error:', error);
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
});
