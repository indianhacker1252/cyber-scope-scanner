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

    const { chain_id } = await req.json();

    console.log(`Autonomous Executor - Starting chain: ${chain_id}`);

    // Fetch attack chain
    const { data: chain, error: chainError } = await supabaseClient
      .from('attack_chains')
      .select('*')
      .eq('id', chain_id)
      .single();

    if (chainError || !chain) {
      throw new Error('Attack chain not found');
    }

    // Update status to running
    await supabaseClient.from('attack_chains').update({
      status: 'running',
      updated_at: new Date().toISOString()
    }).eq('id', chain_id);

    const results: any[] = [];
    let currentStage = 0;
    const attackSequence = chain.attack_sequence as any[];

    // Execute attack chain with autonomous adaptation
    while (currentStage < attackSequence.length) {
      const stage = attackSequence[currentStage];
      
      console.log(`Executing stage ${stage.stage}: ${stage.name}`);

      try {
        // Execute attack via Kali backend
        const executionResult = await executeAttackStage(stage, chain.target);
        
        // Store attempt
        const { data: attemptData } = await supabaseClient.from('attack_attempts').insert({
          user_id: user.id,
          target: chain.target,
          attack_type: stage.technique,
          technique: stage.name,
          payload: stage.command,
          success: executionResult.success,
          output: executionResult.output,
          metadata: { stage: stage.stage }
        }).select().single();

        results.push({
          stage: stage.stage,
          name: stage.name,
          success: executionResult.success,
          output: executionResult.output,
          timestamp: new Date().toISOString()
        });

        if (executionResult.success) {
          // Move to next stage based on success path
          if (stage.on_success === 'complete') {
            break;
          }
          currentStage = typeof stage.on_success === 'number' ? stage.on_success - 1 : currentStage + 1;
        } else {
          // Attack failed - invoke AI learning
          console.log(`Stage ${stage.stage} failed - invoking AI learning`);
          
          const learningResponse = await supabaseClient.functions.invoke('ai-attack-orchestrator', {
            body: {
              action: 'learn-from-failure',
              data: {
                attack_attempt_id: attemptData.id,
                attack_output: executionResult.output,
                error: executionResult.error
              }
            }
          });

          if (learningResponse.data?.learning) {
            const learning = learningResponse.data.learning;
            
            // Try adapted strategies
            if (learning.adaptation_strategies && learning.adaptation_strategies.length > 0) {
              console.log('Attempting adaptive strategy...');
              
              const adaptedStage = {
                ...stage,
                command: learning.adaptation_strategies[0].modified_payload,
                technique: learning.adaptation_strategies[0].strategy
              };

              const adaptedResult = await executeAttackStage(adaptedStage, chain.target);
              
              await supabaseClient.from('attack_attempts').insert({
                user_id: user.id,
                target: chain.target,
                attack_type: adaptedStage.technique,
                technique: adaptedStage.name,
                payload: adaptedStage.command,
                success: adaptedResult.success,
                output: adaptedResult.output,
                metadata: { stage: stage.stage, adapted: true }
              });

              if (adaptedResult.success) {
                results.push({
                  stage: stage.stage,
                  name: `${stage.name} (Adapted)`,
                  success: true,
                  output: adaptedResult.output,
                  adaptation: learning.adaptation_strategies[0].strategy,
                  timestamp: new Date().toISOString()
                });
                currentStage = typeof stage.on_success === 'number' ? stage.on_success - 1 : currentStage + 1;
                continue;
              }
            }
          }

          // Still failed - try alternative path or stop
          if (stage.on_failure) {
            currentStage = typeof stage.on_failure === 'number' ? stage.on_failure - 1 : currentStage + 1;
          } else {
            console.log('No alternative path, stopping chain');
            break;
          }
        }

        // Update chain progress
        await supabaseClient.from('attack_chains').update({
          current_step: currentStage + 1,
          results,
          updated_at: new Date().toISOString()
        }).eq('id', chain_id);

      } catch (error) {
        console.error(`Error executing stage ${stage.stage}:`, error);
        results.push({
          stage: stage.stage,
          name: stage.name,
          success: false,
          error: error.message,
          timestamp: new Date().toISOString()
        });
        break;
      }
    }

    // Mark chain as complete
    await supabaseClient.from('attack_chains').update({
      status: 'completed',
      results,
      updated_at: new Date().toISOString()
    }).eq('id', chain_id);

    return new Response(JSON.stringify({ 
      success: true, 
      chain_id,
      results,
      total_stages: attackSequence.length,
      completed_stages: results.length
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });

  } catch (error) {
    console.error('Autonomous Executor error:', error);
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
});

async function executeAttackStage(stage: any, target: string): Promise<any> {
  // Map technique to Kali backend endpoint
  const toolMap: any = {
    'nmap': '/api/scan/nmap',
    'nikto': '/api/scan/nikto',
    'sqlmap': '/api/scan/sqlmap',
    'gobuster': '/api/scan/gobuster',
    'nuclei': '/api/scan/nuclei',
    'hydra': '/api/scan/hydra',
    'metasploit': '/api/scan/metasploit',
    'wpscan': '/api/scan/wpscan'
  };

  const endpoint = toolMap[stage.tool?.toLowerCase()] || '/api/scan/nmap';
  
  try {
    // This would call your Kali backend
    // For now, simulate execution
    const simulatedSuccess = Math.random() > 0.3; // 70% success rate for demo
    
    return {
      success: simulatedSuccess,
      output: simulatedSuccess ? 
        `Stage ${stage.stage} executed successfully\n${stage.command}\nTarget: ${target}` :
        `Stage ${stage.stage} failed\nError: Target may have defenses`,
      error: simulatedSuccess ? null : 'Execution failed'
    };
  } catch (error) {
    return {
      success: false,
      output: '',
      error: error.message
    };
  }
}