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
      action: z.enum(['analyze-scan', 'get-exploits', 'get-strategy']),
      data: z.object({
        target: z.string().max(500).optional(),
        tool: z.string().max(100).optional(),
        findings: z.array(z.any()).optional(),
        output: z.string().max(5000).optional(),
        vulnerabilityType: z.string().max(200).optional(),
        scanType: z.string().max(100).optional(),
        scope: z.string().max(200).optional()
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
    const EXA_API_KEY = Deno.env.get('EXA_API_KEY');

    if (!EXA_API_KEY) {
      return new Response(
        JSON.stringify({ error: 'Exa API key not configured' }),
        { status: 503, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    let query = '';
    let numResults = 5;

    switch (action) {
      case 'analyze-scan':
        query = `vulnerability assessment ${data.tool} ${data.target} security best practices remediation`;
        break;
      case 'get-exploits':
        query = `${data.vulnerabilityType} exploitation techniques ${data.target} penetration testing methodology`;
        numResults = 3;
        break;
      case 'get-strategy':
        query = `${data.scanType} vulnerability assessment strategy ${data.target} ${data.scope} best practices`;
        break;
    }

    const exaResponse = await fetch('https://api.exa.ai/search', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${EXA_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        query,
        type: 'neural',
        useAutoprompt: true,
        numResults,
        contents: {
          text: true
        }
      }),
    });

    if (!exaResponse.ok) {
      console.error('Exa API error:', exaResponse.status);
      return new Response(
        JSON.stringify({ error: 'Search service temporarily unavailable' }),
        { status: 503, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    const exaData = await exaResponse.json();
    
    // Format response based on action
    let result;
    switch (action) {
      case 'analyze-scan':
        result = {
          recommendations: {
            immediate_actions: data.findings?.filter((f: any) => 
              f.severity === 'critical' || f.severity === 'high'
            ).map((f: any) => 
              `Address ${f.type || 'vulnerability'} on ${data.target} immediately`
            ) || [],
            references: exaData.results?.map((r: any) => ({
              title: r.title,
              url: r.url,
              snippet: r.text?.substring(0, 200) || ''
            })) || []
          }
        };
        break;
      case 'get-exploits':
        result = exaData.results?.map((r: any) => ({
          title: r.title,
          url: r.url,
          technique: r.text?.substring(0, 500) || '',
          score: r.score
        })) || [];
        break;
      case 'get-strategy':
        result = {
          recommended_tools: extractTools(exaData),
          scan_sequence: generateScanSequence(data.scanType || 'comprehensive'),
          expected_duration: estimateDuration(data.scanType || 'comprehensive'),
          references: exaData.results?.map((r: any) => ({
            title: r.title,
            url: r.url
          })) || []
        };
        break;
    }

    return new Response(JSON.stringify({ result }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });

  } catch (error) {
    console.error('Exa proxy error:', error);
    return new Response(
      JSON.stringify({ error: 'Internal server error' }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  }
});

function extractTools(searchResults: any): string[] {
  const commonTools = ['nmap', 'nikto', 'sqlmap', 'gobuster', 'nuclei', 'metasploit', 'burpsuite'];
  const tools: string[] = [];
  
  searchResults.results?.forEach((result: any) => {
    const text = result.text?.toLowerCase() || '';
    commonTools.forEach(tool => {
      if (text.includes(tool) && !tools.includes(tool)) {
        tools.push(tool);
      }
    });
  });
  
  return tools.slice(0, 5);
}

function generateScanSequence(scanType: string): string[] {
  const sequences: Record<string, string[]> = {
    'network': ['Port Scanning', 'Service Detection', 'Vulnerability Assessment', 'Exploit Testing'],
    'web': ['Technology Detection', 'Directory Enumeration', 'SQL Injection Testing', 'XSS Testing'],
    'database': ['Port Detection', 'Version Detection', 'Authentication Testing', 'SQL Injection'],
    'comprehensive': ['Reconnaissance', 'Network Scanning', 'Web Testing', 'Database Testing', 'Reporting']
  };
  
  return sequences[scanType] || sequences['comprehensive'];
}

function estimateDuration(scanType: string): string {
  const durations: Record<string, string> = {
    'network': '5-15 minutes',
    'web': '10-30 minutes',
    'database': '5-20 minutes',
    'comprehensive': '30-60 minutes'
  };
  
  return durations[scanType] || '15-45 minutes';
}
