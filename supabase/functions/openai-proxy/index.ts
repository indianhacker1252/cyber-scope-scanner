import "https://deno.land/x/xhr@0.1.0/mod.ts";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';
import { z } from "https://deno.land/x/zod@v3.22.4/mod.ts";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    // Authentication
    const supabaseClient = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_ANON_KEY') ?? '',
      { global: { headers: { Authorization: req.headers.get('Authorization')! } } }
    );

    const { data: { user }, error: authError } = await supabaseClient.auth.getUser();
    if (authError || !user) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    const requestBody = await req.json();
    
    // Input validation
    const schema = z.object({
      action: z.enum(['analyze-vulnerabilities', 'generate-payloads', 'generate-report', 'custom-completion']),
      data: z.object({
        scanResults: z.array(z.any()).optional(),
        vulnerabilityType: z.string().max(200).optional(),
        target: z.string().max(500).optional(),
        context: z.string().max(2000).optional(),
        analysisData: z.any().optional(),
        prompt: z.string().max(10000).optional(),
        maxTokens: z.number().optional(),
        temperature: z.number().optional()
      })
    });

    const validation = schema.safeParse(requestBody);
    if (!validation.success) {
      return new Response(
        JSON.stringify({ error: 'Invalid input', details: validation.error.issues }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    const { action, data } = validation.data;
    const OPENAI_API_KEY = Deno.env.get('OPENAI_API_KEY');

    if (!OPENAI_API_KEY) {
      return new Response(
        JSON.stringify({ error: 'OpenAI API key not configured' }),
        { status: 503, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    let prompt = '';
    let maxTokens = 2000;
    let temperature = 0.5;

    switch (action) {
      case 'custom-completion':
        prompt = data.prompt || '';
        maxTokens = data.maxTokens || 3000;
        temperature = data.temperature || 0.3;
        break;

      case 'analyze-vulnerabilities':
        const vulnerabilityData = data.scanResults?.slice(0, 10).map(result => ({
          tool: result.tool,
          target: result.target,
          findings: result.findings,
          output: result.output?.substring(0, 1000)
        }));
        
        prompt = `You are a cybersecurity expert. Analyze the following vulnerability scan results and provide a comprehensive security assessment:

Scan Results:
${JSON.stringify(vulnerabilityData, null, 2)}

Please provide:
1. Executive Summary
2. Critical Vulnerabilities (if any)
3. Risk Assessment (High/Medium/Low)
4. Detailed Analysis of each finding
5. Remediation Recommendations
6. Attack Vectors that could exploit these vulnerabilities
7. Compliance Impact (OWASP, NIST, etc.)`;
        break;

      case 'generate-payloads':
        prompt = `You are a penetration testing expert. Generate modern, effective payloads for testing the following vulnerability:

Vulnerability Type: ${data.vulnerabilityType}
Target: ${data.target}
Context: ${data.context || 'General testing'}

Generate payloads for:
1. Initial Discovery/Detection
2. Exploitation Attempts
3. Privilege Escalation (if applicable)
4. Data Extraction (if applicable)

Important: 
- Provide payloads for educational/authorized testing only
- Include detection evasion techniques
- Explain the purpose of each payload
- Focus on latest techniques (2024)`;
        maxTokens = 1500;
        break;

      case 'generate-report':
        prompt = `Generate a professional penetration testing report based on the following data:

Analysis: ${JSON.stringify(data.analysisData)}
Scan Results: ${JSON.stringify(data.scanResults?.slice(0, 3), null, 2)}

Create a comprehensive report with:
1. Executive Summary
2. Methodology
3. Findings Summary Table
4. Detailed Technical Findings
5. Risk Matrix
6. Recommendations`;
        maxTokens = 2500;
        break;
    }

    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${OPENAI_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: 'gpt-3.5-turbo',
        messages: [{ role: 'user', content: prompt }],
        max_tokens: maxTokens,
        temperature: temperature
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('OpenAI API error:', response.status, errorText);
      return new Response(
        JSON.stringify({ error: 'AI service temporarily unavailable' }),
        { status: 503, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    const responseData = await response.json();
    const result = responseData.choices[0]?.message?.content || 'No response generated';

    return new Response(JSON.stringify({ result }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });

  } catch (error) {
    console.error('OpenAI proxy error:', error);
    return new Response(
      JSON.stringify({ error: 'Internal server error' }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  }
});
