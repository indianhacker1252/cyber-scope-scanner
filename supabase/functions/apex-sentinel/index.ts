import "https://deno.land/x/xhr@0.1.0/mod.ts";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.78.0";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

// Kali Linux Tool Definitions with Categories
const KALI_TOOLS = {
  reconnaissance: {
    nmap: { command: 'nmap', description: 'Network scanner and port discovery', defaultArgs: ['-sV', '-sC'] },
    masscan: { command: 'masscan', description: 'Fast port scanner', defaultArgs: ['--rate=1000'] },
    amass: { command: 'amass', description: 'DNS enumeration', defaultArgs: ['enum', '-d'] },
    subfinder: { command: 'subfinder', description: 'Subdomain discovery', defaultArgs: ['-d'] },
    whatweb: { command: 'whatweb', description: 'Web technology fingerprinting', defaultArgs: ['-a', '3'] },
    wafw00f: { command: 'wafw00f', description: 'WAF detection', defaultArgs: [] },
  },
  vulnerability: {
    nikto: { command: 'nikto', description: 'Web server scanner', defaultArgs: ['-h'] },
    nuclei: { command: 'nuclei', description: 'Template-based vulnerability scanner', defaultArgs: ['-u'] },
    sqlmap: { command: 'sqlmap', description: 'SQL injection testing', defaultArgs: ['--batch'] },
    wpscan: { command: 'wpscan', description: 'WordPress scanner', defaultArgs: ['--url'] },
    sslyze: { command: 'sslyze', description: 'SSL/TLS configuration analyzer', defaultArgs: [] },
  },
  exploitation: {
    metasploit: { command: 'msfconsole', description: 'Exploitation framework', defaultArgs: ['-q', '-x'] },
    searchsploit: { command: 'searchsploit', description: 'Exploit database search', defaultArgs: [] },
    hydra: { command: 'hydra', description: 'Password cracking', defaultArgs: ['-V'] },
  },
  hardware: {
    binwalk: { command: 'binwalk', description: 'Firmware analysis', defaultArgs: ['-e'] },
    ghidra_headless: { command: 'analyzeHeadless', description: 'Binary analysis', defaultArgs: [] },
    flashrom: { command: 'flashrom', description: 'Flash chip programming', defaultArgs: ['-p'] },
  }
};

// CVE Database for vulnerability correlation
const CVE_DATABASES = [
  { name: 'NIST NVD', url: 'https://services.nvd.nist.gov/rest/json/cves/2.0' },
  { name: 'CIRCL CVE', url: 'https://cve.circl.lu/api/search' },
];

// MITRE ATT&CK Framework Mapping
const MITRE_ATTACK_TACTICS = {
  reconnaissance: 'TA0043',
  resource_development: 'TA0042',
  initial_access: 'TA0001',
  execution: 'TA0002',
  persistence: 'TA0003',
  privilege_escalation: 'TA0004',
  defense_evasion: 'TA0005',
  credential_access: 'TA0006',
  discovery: 'TA0007',
  lateral_movement: 'TA0008',
  collection: 'TA0009',
  command_and_control: 'TA0011',
  exfiltration: 'TA0010',
  impact: 'TA0040',
};

// Mutation Strategies for WAF/IPS Bypass
const MUTATION_STRATEGIES = {
  encoding: ['base64', 'url', 'double-url', 'unicode', 'hex', 'html-entity'],
  chunking: ['split-payload', 'null-byte-injection', 'comment-injection'],
  protocol_switch: ['http-smuggling', 'websocket', 'h2c-upgrade'],
  timing_variation: ['slow-rate', 'delayed-chunks', 'jitter'],
  obfuscation: ['case-variation', 'whitespace-padding', 'string-concat'],
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
    
    // Get user from auth header
    const authHeader = req.headers.get('Authorization');
    if (!authHeader) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    const token = authHeader.replace('Bearer ', '');
    const { data: { user }, error: authError } = await supabase.auth.getUser(token);
    
    if (authError || !user) {
      return new Response(JSON.stringify({ error: 'Invalid token' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    const { action, data } = await req.json();
    console.log(`[Apex Sentinel] Action: ${action}`, data);

    switch (action) {
      case 'create-session': {
        const { target, targetType, sessionName, authorizedTargets } = data;
        
        // Global Scoping Module - Check authorization
        const isAuthorized = authorizedTargets?.includes(target) || false;
        
        const { data: session, error } = await supabase
          .from('apex_sessions')
          .insert({
            user_id: user.id,
            session_name: sessionName || `Session-${Date.now()}`,
            target,
            target_type: targetType || 'ip',
            authorized: isAuthorized,
            status: 'planning',
            current_phase: 'discovery',
          })
          .select()
          .single();

        if (error) throw error;

        return new Response(JSON.stringify({ success: true, session }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      case 'plan-attack': {
        const { sessionId, targetInfo, previousResults } = data;
        
        // Get session
        const { data: session } = await supabase
          .from('apex_sessions')
          .select('*')
          .eq('id', sessionId)
          .single();

        if (!session) throw new Error('Session not found');
        if (!session.authorized) throw new Error('Target not in authorized list');

        // Get previous successful chains for this type of target
        const { data: successfulChains } = await supabase
          .from('apex_successful_chains')
          .select('*')
          .eq('user_id', user.id)
          .order('success_rate', { ascending: false })
          .limit(5);

        // Use AI to generate attack plan
        const planPrompt = `You are an AI Senior Pentester analyzing a target. Use Chain-of-Thought reasoning.

TARGET: ${session.target}
TARGET TYPE: ${session.target_type}
CURRENT PHASE: ${session.current_phase}
PREVIOUS RESULTS: ${JSON.stringify(previousResults || {})}
SUCCESSFUL CHAINS FROM HISTORY: ${JSON.stringify(successfulChains || [])}

Based on this information, create an attack plan with the following structure:
1. Break down the high-level goal into atomic tasks
2. For each task, specify:
   - task_type (recon, service_id, fuzzing, exploit, post_exploit, hardware)
   - task_name
   - description
   - recommended_tool (from: ${Object.keys(KALI_TOOLS).map(cat => Object.keys(KALI_TOOLS[cat as keyof typeof KALI_TOOLS]).join(', ')).join(', ')})
   - reasoning (Chain-of-Thought justification)
   - priority (1-5, 1 being highest)

Respond with a JSON object containing an array of tasks.`;

        const aiResponse = await fetch('https://ai.gateway.lovable.dev/v1/chat/completions', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${lovableApiKey}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            model: 'google/gemini-2.5-flash',
            messages: [
              { role: 'system', content: 'You are an AI pentesting assistant. Always respond with valid JSON.' },
              { role: 'user', content: planPrompt }
            ],
          }),
        });

        const aiData = await aiResponse.json();
        const planContent = aiData.choices?.[0]?.message?.content || '{"tasks":[]}';
        
        // Parse the plan
        let plan;
        try {
          const jsonMatch = planContent.match(/\{[\s\S]*\}/);
          plan = jsonMatch ? JSON.parse(jsonMatch[0]) : { tasks: [] };
        } catch {
          plan = { tasks: [] };
        }

        // Insert tasks into database
        const tasks = (plan.tasks || []).map((task: any, index: number) => ({
          session_id: sessionId,
          task_type: task.task_type || 'recon',
          task_name: task.task_name || `Task ${index + 1}`,
          description: task.description,
          tool_selected: task.recommended_tool,
          reasoning: task.reasoning,
          priority: task.priority || index + 1,
          status: 'pending',
        }));

        if (tasks.length > 0) {
          await supabase.from('apex_tasks').insert(tasks);
        }

        // Update session status
        await supabase
          .from('apex_sessions')
          .update({ status: 'executing', attack_chain: plan })
          .eq('id', sessionId);

        return new Response(JSON.stringify({ success: true, plan, tasksCreated: tasks.length }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      case 'execute-task': {
        const { taskId, sessionId } = data;

        // Get task details
        const { data: task } = await supabase
          .from('apex_tasks')
          .select('*')
          .eq('id', taskId)
          .single();

        if (!task) throw new Error('Task not found');

        // Get session for target info
        const { data: session } = await supabase
          .from('apex_sessions')
          .select('*')
          .eq('id', sessionId)
          .single();

        if (!session?.authorized) throw new Error('Unauthorized target');

        // Map tool to command
        const toolCategory = Object.entries(KALI_TOOLS).find(([_, tools]) => 
          Object.keys(tools).includes(task.tool_selected)
        );
        
        const toolInfo = toolCategory ? 
          KALI_TOOLS[toolCategory[0] as keyof typeof KALI_TOOLS][task.tool_selected as keyof typeof KALI_TOOLS['reconnaissance']] : 
          null;

        // Simulate command generation (in real implementation, this would execute via secure subprocess)
        const command = toolInfo ? 
          `${toolInfo.command} ${toolInfo.defaultArgs.join(' ')} ${session.target}` :
          `echo "Tool ${task.tool_selected} not found"`;

        // Update task as executing
        await supabase
          .from('apex_tasks')
          .update({ status: 'executing', command, executed_at: new Date().toISOString() })
          .eq('id', taskId);

        // Simulate execution (in production, this calls actual Kali tools)
        const executionResult = await simulateToolExecution(task.tool_selected, session.target, session.target_type);

        // Record execution
        const { data: execution } = await supabase
          .from('apex_tool_executions')
          .insert({
            task_id: taskId,
            session_id: sessionId,
            tool_name: task.tool_selected,
            command_executed: command,
            execution_time_ms: executionResult.executionTime,
            exit_code: executionResult.exitCode,
            stdout: executionResult.stdout,
            stderr: executionResult.stderr,
            parsed_results: executionResult.parsedResults,
            success: executionResult.success,
            blocked_by: executionResult.blockedBy,
          })
          .select()
          .single();

        // Update task with results
        const newStatus = executionResult.success ? 'success' : 
                          executionResult.blockedBy ? 'blocked' : 'failed';

        await supabase
          .from('apex_tasks')
          .update({ 
            status: newStatus,
            stdout: executionResult.stdout,
            stderr: executionResult.stderr,
            result_analysis: executionResult.analysis,
          })
          .eq('id', taskId);

        return new Response(JSON.stringify({ 
          success: true, 
          execution,
          taskStatus: newStatus,
          analysis: executionResult.analysis,
        }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      case 'critic-analyze': {
        const { sessionId, taskId, executionResults } = data;

        // AI Critic analyzes the results
        const criticPrompt = `You are the Critic in a Planner-Executor-Critic loop for penetration testing.

TASK RESULTS: ${JSON.stringify(executionResults)}

Analyze:
1. Was the objective met?
2. What vulnerabilities were discovered?
3. What should the next steps be?
4. If blocked, what mutation strategy should we use?

Available mutation strategies:
${JSON.stringify(MUTATION_STRATEGIES, null, 2)}

Respond with JSON containing:
- objective_met: boolean
- findings: array of discovered items
- next_steps: array of recommended actions
- mutation_needed: boolean
- mutation_strategy: if needed, which strategy to use`;

        const aiResponse = await fetch('https://ai.gateway.lovable.dev/v1/chat/completions', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${lovableApiKey}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            model: 'google/gemini-2.5-flash',
            messages: [
              { role: 'system', content: 'You are a security analysis AI. Respond with valid JSON only.' },
              { role: 'user', content: criticPrompt }
            ],
          }),
        });

        const aiData = await aiResponse.json();
        const analysisContent = aiData.choices?.[0]?.message?.content || '{}';
        
        let analysis;
        try {
          const jsonMatch = analysisContent.match(/\{[\s\S]*\}/);
          analysis = jsonMatch ? JSON.parse(jsonMatch[0]) : {};
        } catch {
          analysis = { objective_met: false, findings: [], next_steps: [] };
        }

        // Update session findings
        const { data: session } = await supabase
          .from('apex_sessions')
          .select('findings')
          .eq('id', sessionId)
          .single();

        const existingFindings = session?.findings || [];
        const updatedFindings = [...existingFindings, ...(analysis.findings || [])];

        await supabase
          .from('apex_sessions')
          .update({ findings: updatedFindings })
          .eq('id', sessionId);

        // If mutation needed, log it
        if (analysis.mutation_needed && analysis.mutation_strategy) {
          await supabase
            .from('apex_mutation_log')
            .insert({
              session_id: sessionId,
              mutation_type: analysis.mutation_strategy.type || 'encoding',
              reason: analysis.mutation_strategy.reason || 'Blocked by security control',
              original_payload: executionResults.command,
            });
        }

        return new Response(JSON.stringify({ success: true, analysis }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      case 're-enhance-attack': {
        const { sessionId, failedTaskId, failureReason } = data;

        // Get failed task and session context
        const { data: failedTask } = await supabase
          .from('apex_tasks')
          .select('*')
          .eq('id', failedTaskId)
          .single();

        const { data: session } = await supabase
          .from('apex_sessions')
          .select('*')
          .eq('id', sessionId)
          .single();

        const { data: previousMutations } = await supabase
          .from('apex_mutation_log')
          .select('*')
          .eq('session_id', sessionId)
          .order('created_at', { ascending: false })
          .limit(5);

        // AI generates re-enhanced attack strategy
        const reEnhancePrompt = `You are an AgentBrain handling re-enhancement after a failed attack attempt.

FAILED TASK: ${JSON.stringify(failedTask)}
FAILURE REASON: ${failureReason}
PREVIOUS MUTATIONS TRIED: ${JSON.stringify(previousMutations)}
SESSION CONSTRAINTS: ${JSON.stringify(session?.constraints || [])}

Generate a new attack approach that:
1. Avoids previously failed strategies
2. Uses a different mutation technique
3. Considers alternative tools if available

Available mutation strategies:
${JSON.stringify(MUTATION_STRATEGIES, null, 2)}

Available tools:
${JSON.stringify(Object.keys(KALI_TOOLS).map(cat => Object.keys(KALI_TOOLS[cat as keyof typeof KALI_TOOLS])).flat())}

Respond with JSON containing:
- new_approach: description of new strategy
- mutation_type: which mutation to apply
- alternative_tool: if switching tools
- modified_parameters: new parameters to use
- reasoning: Chain-of-Thought explanation`;

        const aiResponse = await fetch('https://ai.gateway.lovable.dev/v1/chat/completions', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${lovableApiKey}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            model: 'google/gemini-2.5-flash',
            messages: [
              { role: 'system', content: 'You are an adaptive penetration testing AI. Respond with valid JSON.' },
              { role: 'user', content: reEnhancePrompt }
            ],
          }),
        });

        const aiData = await aiResponse.json();
        const strategyContent = aiData.choices?.[0]?.message?.content || '{}';
        
        let strategy;
        try {
          const jsonMatch = strategyContent.match(/\{[\s\S]*\}/);
          strategy = jsonMatch ? JSON.parse(jsonMatch[0]) : {};
        } catch {
          strategy = { new_approach: 'Retry with default parameters' };
        }

        // Create new task with enhanced approach
        const { data: newTask } = await supabase
          .from('apex_tasks')
          .insert({
            session_id: sessionId,
            task_type: failedTask?.task_type || 'recon',
            task_name: `Re-enhanced: ${failedTask?.task_name}`,
            description: strategy.new_approach,
            tool_selected: strategy.alternative_tool || failedTask?.tool_selected,
            parameters: strategy.modified_parameters || {},
            reasoning: strategy.reasoning,
            mutation_strategy: { type: strategy.mutation_type, details: strategy },
            status: 'pending',
            priority: 1,
          })
          .select()
          .single();

        // Add constraint to session
        const constraints = session?.constraints || [];
        constraints.push({
          type: 'failed_approach',
          original_task: failedTaskId,
          reason: failureReason,
          timestamp: new Date().toISOString(),
        });

        await supabase
          .from('apex_sessions')
          .update({ constraints })
          .eq('id', sessionId);

        return new Response(JSON.stringify({ success: true, strategy, newTask }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      case 'save-successful-chain': {
        const { sessionId } = data;

        const { data: session } = await supabase
          .from('apex_sessions')
          .select('*')
          .eq('id', sessionId)
          .single();

        const { data: tasks } = await supabase
          .from('apex_tasks')
          .select('*')
          .eq('session_id', sessionId)
          .eq('status', 'success')
          .order('created_at');

        if (tasks && tasks.length > 0) {
          await supabase
            .from('apex_successful_chains')
            .insert({
              user_id: user.id,
              target_type: session?.target_type,
              service_signature: session?.target_map?.services?.join(' + ') || 'unknown',
              vulnerability_type: session?.findings?.[0]?.type || 'general',
              attack_chain: tasks.map(t => ({
                tool: t.tool_selected,
                task_type: t.task_type,
                parameters: t.parameters,
              })),
              success_rate: 100,
            });
        }

        return new Response(JSON.stringify({ success: true, chainSaved: tasks?.length || 0 }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      case 'get-session-status': {
        const { sessionId } = data;

        const { data: session } = await supabase
          .from('apex_sessions')
          .select('*')
          .eq('id', sessionId)
          .single();

        const { data: tasks } = await supabase
          .from('apex_tasks')
          .select('*')
          .eq('session_id', sessionId)
          .order('priority');

        const { data: executions } = await supabase
          .from('apex_tool_executions')
          .select('*')
          .eq('session_id', sessionId)
          .order('created_at', { ascending: false })
          .limit(10);

        return new Response(JSON.stringify({ session, tasks, executions }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      case 'get-user-sessions': {
        const { data: sessions } = await supabase
          .from('apex_sessions')
          .select('*')
          .eq('user_id', user.id)
          .order('created_at', { ascending: false });

        return new Response(JSON.stringify({ sessions }), {
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
    console.error('[Apex Sentinel] Error:', error);
    return new Response(JSON.stringify({ 
      error: error instanceof Error ? error.message : 'Unknown error' 
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
});

// Simulation function for tool execution (replace with actual subprocess wrapper in production)
async function simulateToolExecution(tool: string, target: string, targetType: string) {
  const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));
  await delay(500); // Simulate execution time

  const executionResults: Record<string, any> = {
    nmap: {
      success: true,
      exitCode: 0,
      executionTime: 2500,
      stdout: `Starting Nmap scan on ${target}
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.4
80/tcp   open  http    Apache/2.4.49
443/tcp  open  https   Apache/2.4.49
3306/tcp open  mysql   MySQL 8.0.26`,
      stderr: '',
      parsedResults: {
        ports: [
          { port: 22, service: 'ssh', version: 'OpenSSH 8.4' },
          { port: 80, service: 'http', version: 'Apache/2.4.49' },
          { port: 443, service: 'https', version: 'Apache/2.4.49' },
          { port: 3306, service: 'mysql', version: 'MySQL 8.0.26' },
        ],
        os_detection: 'Linux 5.x',
      },
      analysis: 'Port scan complete. Apache 2.4.49 detected - CVE-2021-41773 path traversal vulnerability may apply. MySQL exposed on default port.',
    },
    nikto: {
      success: true,
      exitCode: 0,
      executionTime: 15000,
      stdout: `- Nikto v2.1.6
+ Target IP: ${target}
+ Server: Apache/2.4.49
+ /: The anti-clickjacking X-Frame-Options header is not present.
+ /: The X-Content-Type-Options header is not set.
+ /icons/: Directory indexing found.
+ /cgi-bin/: CGI Directory found.
+ Apache/2.4.49 appears to be outdated`,
      parsedResults: {
        vulnerabilities: [
          { id: 'OSVDB-0', type: 'info', description: 'X-Frame-Options not set' },
          { id: 'OSVDB-0', type: 'info', description: 'X-Content-Type-Options not set' },
          { id: 'OSVDB-3268', type: 'medium', description: 'Directory indexing found' },
        ],
      },
      analysis: 'Web server scan reveals missing security headers and directory indexing. Apache version vulnerable to known exploits.',
    },
    sqlmap: {
      success: false,
      exitCode: 1,
      executionTime: 8000,
      stdout: `[*] testing connection to the target URL
[*] testing if the target URL is stable
[!] target URL is not stable`,
      stderr: 'WAF/IPS detected: Cloudflare',
      blockedBy: 'WAF',
      parsedResults: {},
      analysis: 'SQL injection testing blocked by WAF. Recommend mutation strategy: encoding or chunking.',
    },
    nuclei: {
      success: true,
      exitCode: 0,
      executionTime: 12000,
      stdout: `[apache-detect] [http] [info] ${target}:80
[CVE-2021-41773] [http] [critical] ${target}:80
[CVE-2021-42013] [http] [critical] ${target}:80
[mysql-detect] [tcp] [info] ${target}:3306`,
      parsedResults: {
        findings: [
          { template: 'CVE-2021-41773', severity: 'critical', matched: true },
          { template: 'CVE-2021-42013', severity: 'critical', matched: true },
        ],
      },
      analysis: 'Critical vulnerabilities found: Apache path traversal (CVE-2021-41773, CVE-2021-42013). Immediate exploitation recommended.',
    },
    binwalk: {
      success: true,
      exitCode: 0,
      executionTime: 5000,
      stdout: `DECIMAL       HEXADECIMAL     DESCRIPTION
0             0x0             uImage header
64            0x40            LZMA compressed data
1048576       0x100000        Squashfs filesystem`,
      parsedResults: {
        filesystems: ['squashfs'],
        compression: ['lzma'],
        headers: ['uImage'],
      },
      analysis: 'Firmware extracted. SquashFS filesystem detected. Proceeding with filesystem analysis for hardcoded credentials.',
    },
  };

  return executionResults[tool] || {
    success: true,
    exitCode: 0,
    executionTime: 1000,
    stdout: `Simulated execution of ${tool} against ${target}`,
    stderr: '',
    parsedResults: {},
    analysis: `Tool ${tool} executed successfully. Further analysis required.`,
  };
}