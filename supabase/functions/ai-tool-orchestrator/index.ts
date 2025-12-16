import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

// Tool definitions for AI to choose from
const AVAILABLE_TOOLS = {
  network_scan: {
    name: "Network Scanning",
    description: "Scan network for hosts, ports, and services using nmap",
    keywords: ["network", "scan", "ports", "hosts", "nmap", "discover", "enumerate"],
    tool: "nmap",
    defaultParams: "-sV -sC"
  },
  subdomain_enum: {
    name: "Subdomain Enumeration",
    description: "Find subdomains of a target domain",
    keywords: ["subdomain", "dns", "enumerate", "domain", "recon"],
    tool: "subfinder",
    defaultParams: "-silent"
  },
  web_crawl: {
    name: "Web Crawling",
    description: "Crawl websites to discover endpoints and parameters",
    keywords: ["crawl", "spider", "endpoints", "urls", "web", "discover"],
    tool: "katana",
    defaultParams: "-d 3"
  },
  vulnerability_scan: {
    name: "Vulnerability Scanning",
    description: "Scan for known vulnerabilities using nuclei",
    keywords: ["vulnerability", "vuln", "cve", "exploit", "scan", "nuclei"],
    tool: "nuclei",
    defaultParams: "-severity medium,high,critical"
  },
  xss_scan: {
    name: "XSS Testing",
    description: "Test for Cross-Site Scripting vulnerabilities",
    keywords: ["xss", "cross-site", "scripting", "injection", "web"],
    tool: "dalfox",
    defaultParams: "url"
  },
  sql_injection: {
    name: "SQL Injection Testing",
    description: "Test for SQL injection vulnerabilities",
    keywords: ["sql", "injection", "sqli", "database", "query"],
    tool: "sqlmap",
    defaultParams: "--batch --random-agent"
  },
  directory_fuzzing: {
    name: "Directory Fuzzing",
    description: "Discover hidden directories and files",
    keywords: ["directory", "fuzz", "brute", "hidden", "files", "paths"],
    tool: "ffuf",
    defaultParams: "-w /usr/share/wordlists/dirb/common.txt"
  },
  port_scan_fast: {
    name: "Fast Port Scanning",
    description: "Quick port scanning with rustscan",
    keywords: ["port", "fast", "quick", "rustscan", "tcp"],
    tool: "rustscan",
    defaultParams: "-a"
  },
  secrets_scan: {
    name: "Secrets Detection",
    description: "Find exposed secrets, API keys, and credentials",
    keywords: ["secrets", "api", "keys", "credentials", "leak", "exposed"],
    tool: "gitleaks",
    defaultParams: "detect"
  },
  parameter_discovery: {
    name: "Parameter Discovery",
    description: "Discover hidden parameters in web applications",
    keywords: ["parameter", "param", "query", "input", "discover"],
    tool: "arjun",
    defaultParams: "-u"
  },
  http_probe: {
    name: "HTTP Probing",
    description: "Probe for live HTTP/HTTPS servers",
    keywords: ["http", "https", "probe", "alive", "live", "web"],
    tool: "httpx",
    defaultParams: "-silent -status-code"
  },
  wayback_urls: {
    name: "Wayback URL Mining",
    description: "Extract historical URLs from Wayback Machine",
    keywords: ["wayback", "archive", "historical", "urls", "old"],
    tool: "waybackurls",
    defaultParams: ""
  }
};

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
    const supabaseKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
    const lovableApiKey = Deno.env.get('LOVABLE_API_KEY');
    
    const supabase = createClient(supabaseUrl, supabaseKey);
    
    const authHeader = req.headers.get('Authorization');
    if (!authHeader) {
      return new Response(JSON.stringify({ error: 'No authorization header' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    const { data: { user }, error: authError } = await supabase.auth.getUser(
      authHeader.replace('Bearer ', '')
    );

    if (authError || !user) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    const { action, data } = await req.json();

    switch (action) {
      case 'analyze-intent': {
        // Use AI to understand user intent and select appropriate tools
        const { userInput, target } = data;
        
        // Fetch previous learnings to improve decision making
        const { data: learnings } = await supabase
          .from('ai_learnings')
          .select('*')
          .eq('user_id', user.id)
          .order('created_at', { ascending: false })
          .limit(20);

        const { data: successfulAttempts } = await supabase
          .from('attack_attempts')
          .select('*')
          .eq('user_id', user.id)
          .eq('success', true)
          .order('created_at', { ascending: false })
          .limit(10);

        const learningContext = learnings?.map(l => 
          `Tool: ${l.tool_used}, Success: ${l.success_rate}%, Strategy: ${l.improvement_strategy}`
        ).join('\n') || 'No previous learnings';

        const successContext = successfulAttempts?.map(a =>
          `Attack: ${a.attack_type} on ${a.target} - Technique: ${a.technique}`
        ).join('\n') || 'No successful attacks recorded';

        const toolDescriptions = Object.entries(AVAILABLE_TOOLS)
          .map(([key, tool]) => `${key}: ${tool.description}`)
          .join('\n');

        const aiPrompt = `You are an expert penetration tester AI. Analyze the user's request and determine the best tools and attack strategy.

AVAILABLE TOOLS:
${toolDescriptions}

PREVIOUS LEARNINGS (use to improve strategy):
${learningContext}

SUCCESSFUL ATTACK PATTERNS:
${successContext}

USER REQUEST: "${userInput}"
TARGET: ${target || 'Not specified'}

Respond with a JSON object containing:
{
  "understood_intent": "brief description of what user wants",
  "recommended_tools": ["tool_key1", "tool_key2"],
  "execution_order": ["first_tool", "second_tool"],
  "parameters": { "tool_key": "specific params" },
  "attack_strategy": "detailed multi-step strategy",
  "reasoning": "why these tools were chosen",
  "risk_level": "low/medium/high",
  "estimated_time": "time estimate",
  "learning_from_history": "how previous learnings influenced this decision"
}`;

        const aiResponse = await fetch('https://ai.gateway.lovable.dev/v1/chat/completions', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${lovableApiKey}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            model: 'google/gemini-2.5-flash',
            messages: [
              { role: 'system', content: 'You are an expert penetration testing AI that selects optimal tools and strategies. Always respond with valid JSON.' },
              { role: 'user', content: aiPrompt }
            ],
            temperature: 0.3,
          }),
        });

        const aiData = await aiResponse.json();
        let analysis;
        
        try {
          const content = aiData.choices[0].message.content;
          const jsonMatch = content.match(/\{[\s\S]*\}/);
          analysis = jsonMatch ? JSON.parse(jsonMatch[0]) : null;
        } catch {
          analysis = {
            understood_intent: "General security scan",
            recommended_tools: ["network_scan"],
            execution_order: ["network_scan"],
            parameters: {},
            attack_strategy: "Perform reconnaissance scan",
            reasoning: "Default fallback",
            risk_level: "low",
            estimated_time: "5-10 minutes"
          };
        }

        // Store the analysis decision for learning
        await supabase.from('ai_decisions').insert({
          user_id: user.id,
          user_input: userInput,
          target: target,
          analysis: analysis,
          tools_selected: analysis.recommended_tools,
          created_at: new Date().toISOString()
        });

        return new Response(JSON.stringify({ 
          success: true, 
          analysis,
          availableTools: AVAILABLE_TOOLS
        }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      case 'record-learning': {
        // Record what the AI learned from an operation
        const { tool_used, target, findings, success, execution_time, error_message } = data;

        // Generate improvement strategy using AI
        const learningPrompt = `Analyze this security tool execution and suggest improvements:

Tool Used: ${tool_used}
Target: ${target}
Success: ${success}
Findings: ${JSON.stringify(findings)}
Error: ${error_message || 'None'}
Execution Time: ${execution_time}ms

Provide:
1. What worked well
2. What could be improved
3. Better parameters for next time
4. Alternative tools to try
5. Success rate estimation for similar targets`;

        const aiResponse = await fetch('https://ai.gateway.lovable.dev/v1/chat/completions', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${lovableApiKey}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            model: 'google/gemini-2.5-flash',
            messages: [
              { role: 'system', content: 'You are a security analysis AI that learns from tool executions.' },
              { role: 'user', content: learningPrompt }
            ],
          }),
        });

        const aiData = await aiResponse.json();
        const aiAnalysis = aiData.choices[0]?.message?.content || '';

        // Store learning
        const { data: learning, error } = await supabase.from('ai_learnings').insert({
          user_id: user.id,
          tool_used,
          target,
          findings: findings,
          success,
          execution_time,
          ai_analysis: aiAnalysis,
          improvement_strategy: aiAnalysis,
          success_rate: success ? 100 : 0,
          created_at: new Date().toISOString()
        }).select().single();

        return new Response(JSON.stringify({ success: true, learning }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      case 'get-learnings': {
        // Retrieve AI learnings for display
        const { data: learnings } = await supabase
          .from('ai_learnings')
          .select('*')
          .eq('user_id', user.id)
          .order('created_at', { ascending: false })
          .limit(50);

        const { data: decisions } = await supabase
          .from('ai_decisions')
          .select('*')
          .eq('user_id', user.id)
          .order('created_at', { ascending: false })
          .limit(20);

        // Calculate stats
        const totalLearnings = learnings?.length || 0;
        const successfulOps = learnings?.filter(l => l.success).length || 0;
        const avgSuccessRate = totalLearnings > 0 ? (successfulOps / totalLearnings) * 100 : 0;
        
        const toolUsage: Record<string, number> = {};
        learnings?.forEach(l => {
          toolUsage[l.tool_used] = (toolUsage[l.tool_used] || 0) + 1;
        });

        return new Response(JSON.stringify({ 
          success: true, 
          learnings,
          decisions,
          stats: {
            totalLearnings,
            successfulOps,
            avgSuccessRate: Math.round(avgSuccessRate),
            toolUsage
          }
        }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      case 'generate-attack-plan': {
        // Generate comprehensive attack plan based on learnings
        const { target, objective } = data;

        const { data: learnings } = await supabase
          .from('ai_learnings')
          .select('*')
          .eq('user_id', user.id)
          .eq('success', true)
          .limit(30);

        const planPrompt = `Create a comprehensive penetration testing attack plan.

TARGET: ${target}
OBJECTIVE: ${objective}

HISTORICAL SUCCESS DATA:
${learnings?.map(l => `- ${l.tool_used}: ${l.success ? 'Success' : 'Failed'} on similar target`).join('\n') || 'No history'}

AVAILABLE TOOLS: ${Object.keys(AVAILABLE_TOOLS).join(', ')}

Generate a detailed attack plan with:
1. Reconnaissance phase (tools and parameters)
2. Scanning phase (tools and parameters)
3. Exploitation phase (tools and parameters)
4. Post-exploitation (if applicable)
5. Estimated success probability based on historical data
6. Risk assessment
7. Recommended order of operations
8. Fallback strategies if primary approach fails

Respond in JSON format with phases, tools, parameters, and reasoning.`;

        const aiResponse = await fetch('https://ai.gateway.lovable.dev/v1/chat/completions', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${lovableApiKey}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            model: 'google/gemini-2.5-flash',
            messages: [
              { role: 'system', content: 'You are an expert penetration tester creating attack plans. Respond with detailed JSON.' },
              { role: 'user', content: planPrompt }
            ],
          }),
        });

        const aiData = await aiResponse.json();
        let plan;
        
        try {
          const content = aiData.choices[0].message.content;
          const jsonMatch = content.match(/\{[\s\S]*\}/);
          plan = jsonMatch ? JSON.parse(jsonMatch[0]) : { raw: content };
        } catch {
          plan = { raw: aiData.choices[0]?.message?.content || 'Failed to generate plan' };
        }

        return new Response(JSON.stringify({ success: true, plan }), {
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
    console.error('AI Orchestrator error:', error);
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
});
