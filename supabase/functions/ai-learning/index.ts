import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

const LOVABLE_API_KEY = Deno.env.get('LOVABLE_API_KEY');
const AI_GATEWAY_URL = 'https://ai.gateway.lovable.dev/v1/chat/completions';

interface LearningEntry {
  tool_used: string;
  target: string;
  findings: any;
  success: boolean;
  execution_time: number;
  context?: any;
}

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

    const authHeader = req.headers.get('Authorization');
    let user = null;
    
    if (authHeader) {
      const { data: { user: authUser } } = await supabase.auth.getUser(
        authHeader.replace('Bearer ', '')
      );
      user = authUser;
    }

    // For unauthenticated users, provide responses but don't persist to DB
    const userId = user?.id || null;
    const isAuthenticated = !!userId;
    console.log(`[AI Learning] User: ${userId || 'anonymous'} - Action: ${action} - Authenticated: ${isAuthenticated}`);

    // Handle actions based on authentication status

    switch (action) {
      case 'record-learning': {
        const entry: LearningEntry = data;
        
        // Analyze the results with AI
        const aiAnalysis = await analyzeWithAI({
          tool: entry.tool_used,
          target: entry.target,
          findings: entry.findings,
          success: entry.success,
          context: entry.context
        });

        // Only store in database if authenticated
        if (isAuthenticated) {
          const { error: insertError } = await supabase.from('ai_learnings').insert({
            user_id: userId,
            tool_used: entry.tool_used,
            target: entry.target,
            findings: entry.findings,
            success: entry.success,
            execution_time: entry.execution_time,
            ai_analysis: aiAnalysis.analysis,
            improvement_strategy: aiAnalysis.improvement_strategy,
            success_rate: aiAnalysis.success_rate
          });

          if (insertError) {
            console.error('Error inserting learning:', insertError);
            // Don't throw - still return the analysis
          }
        }

        return new Response(JSON.stringify({
          success: true,
          analysis: aiAnalysis,
          message: isAuthenticated ? 'Learning recorded and analyzed' : 'Analysis complete (login to persist learnings)',
          persisted: isAuthenticated
        }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      case 'get-recommendations': {
        const { tool, target, context } = data;

        // Get past learnings for similar scenarios (only if authenticated)
        let pastLearnings: any[] = [];
        if (isAuthenticated) {
          const { data: learningsData } = await supabase
            .from('ai_learnings')
            .select('*')
            .eq('user_id', userId)
            .eq('tool_used', tool)
            .order('created_at', { ascending: false })
            .limit(10);
          pastLearnings = learningsData || [];
        }

        // Generate recommendations based on past learnings
        const recommendations = await generateRecommendations({
          tool,
          target,
          context,
          pastLearnings
        });

        return new Response(JSON.stringify({
          success: true,
          recommendations,
          past_learnings_count: pastLearnings.length
        }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      case 'analyze-improvement': {
        const { tool, target } = data;

        // Get all learnings for this tool (only if authenticated)
        let allLearnings: any[] = [];
        if (isAuthenticated) {
          const { data: learningsData } = await supabase
            .from('ai_learnings')
            .select('*')
            .eq('user_id', userId)
            .eq('tool_used', tool)
            .order('created_at', { ascending: false })
            .limit(50);
          allLearnings = learningsData || [];
        }

        // Calculate improvement metrics
        const metrics = calculateImprovementMetrics(allLearnings);
        
        // Get AI insights
        const insights = await getImprovementInsights({
          tool,
          metrics,
          recentLearnings: allLearnings.slice(0, 10)
        });

        return new Response(JSON.stringify({
          success: true,
          metrics,
          insights,
          total_learnings: allLearnings.length
        }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      case 'get-learning-summary': {
        // Get overall learning summary (only if authenticated)
        let allLearnings: any[] = [];
        if (isAuthenticated) {
          const { data: learningsData } = await supabase
            .from('ai_learnings')
            .select('*')
            .eq('user_id', userId)
            .order('created_at', { ascending: false })
            .limit(100);
          allLearnings = learningsData || [];
        }

        const summary = generateLearningSummary(allLearnings);

        return new Response(JSON.stringify({
          success: true,
          summary
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
    console.error('[AI Learning Error]', error);
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
});

async function analyzeWithAI(data: any): Promise<any> {
  if (!LOVABLE_API_KEY) {
    return {
      analysis: 'AI analysis not available - API key not configured',
      improvement_strategy: 'Configure LOVABLE_API_KEY for detailed analysis',
      success_rate: data.success ? 1.0 : 0.0
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
            content: `You are a security analysis AI. Analyze scan results and provide actionable insights. Be concise and technical.`
          },
          {
            role: 'user',
            content: `Analyze this security scan result and provide improvement strategies:
Tool: ${data.tool}
Target: ${data.target}
Success: ${data.success}
Findings: ${JSON.stringify(data.findings, null, 2)}
Context: ${JSON.stringify(data.context || {}, null, 2)}

Provide:
1. Brief analysis (2-3 sentences)
2. Improvement strategy for next time
3. Success rate estimate (0.0 to 1.0)`
          }
        ],
        max_tokens: 500
      })
    });

    if (!response.ok) {
      throw new Error(`AI API error: ${response.status}`);
    }

    const result = await response.json();
    const content = result.choices?.[0]?.message?.content || '';
    
    // Parse the AI response
    const analysis = content.split('1.')[1]?.split('2.')[0]?.trim() || 'Analysis complete';
    const strategy = content.split('2.')[1]?.split('3.')[0]?.trim() || 'Continue monitoring';
    const rateMatch = content.match(/(\d+\.?\d*)/);
    const rate = rateMatch ? Math.min(1.0, Math.max(0.0, parseFloat(rateMatch[1]) / 100 || parseFloat(rateMatch[1]))) : (data.success ? 0.8 : 0.2);

    return {
      analysis,
      improvement_strategy: strategy,
      success_rate: rate
    };
  } catch (error) {
    console.error('AI analysis error:', error);
    return {
      analysis: `Scan ${data.success ? 'completed successfully' : 'encountered issues'}`,
      improvement_strategy: data.success ? 'Maintain current approach' : 'Review scan parameters',
      success_rate: data.success ? 0.75 : 0.25
    };
  }
}

async function generateRecommendations(data: any): Promise<any> {
  const { pastLearnings } = data;
  
  // Calculate success patterns
  const successfulScans = pastLearnings.filter((l: any) => l.success);
  const failedScans = pastLearnings.filter((l: any) => !l.success);
  
  const recommendations = {
    confidence_level: successfulScans.length / Math.max(pastLearnings.length, 1),
    suggested_approach: successfulScans.length > failedScans.length ? 'aggressive' : 'conservative',
    common_findings: extractCommonFindings(successfulScans),
    avoid_patterns: extractFailurePatterns(failedScans),
    estimated_duration: calculateAverageDuration(pastLearnings),
    tips: generateTips(pastLearnings)
  };

  return recommendations;
}

function extractCommonFindings(learnings: any[]): string[] {
  const findingsMap = new Map<string, number>();
  
  learnings.forEach(l => {
    if (l.findings && Array.isArray(l.findings)) {
      l.findings.forEach((f: any) => {
        const key = f.name || f.type || 'unknown';
        findingsMap.set(key, (findingsMap.get(key) || 0) + 1);
      });
    }
  });

  return Array.from(findingsMap.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([name]) => name);
}

function extractFailurePatterns(learnings: any[]): string[] {
  return learnings.slice(0, 3).map(l => l.ai_analysis || 'Unknown failure pattern');
}

function calculateAverageDuration(learnings: any[]): number {
  if (learnings.length === 0) return 0;
  const total = learnings.reduce((sum, l) => sum + (l.execution_time || 0), 0);
  return Math.round(total / learnings.length);
}

function generateTips(learnings: any[]): string[] {
  const tips = [];
  
  if (learnings.length >= 5) {
    const recentSuccess = learnings.slice(0, 5).filter(l => l.success).length;
    if (recentSuccess >= 4) {
      tips.push('Recent scans have been very successful - consider more aggressive testing');
    } else if (recentSuccess <= 1) {
      tips.push('Recent scans have had issues - review target configurations');
    }
  }

  if (learnings.length > 0 && learnings[0].improvement_strategy) {
    tips.push(`Latest recommendation: ${learnings[0].improvement_strategy}`);
  }

  return tips;
}

function calculateImprovementMetrics(learnings: any[]): any {
  if (learnings.length === 0) {
    return {
      overall_success_rate: 0,
      trend: 'insufficient_data',
      avg_findings_per_scan: 0,
      total_vulnerabilities_found: 0
    };
  }

  const successRate = learnings.filter(l => l.success).length / learnings.length;
  
  // Calculate trend (compare first half to second half)
  const midpoint = Math.floor(learnings.length / 2);
  const firstHalf = learnings.slice(midpoint);
  const secondHalf = learnings.slice(0, midpoint);
  
  const firstHalfRate = firstHalf.filter(l => l.success).length / Math.max(firstHalf.length, 1);
  const secondHalfRate = secondHalf.filter(l => l.success).length / Math.max(secondHalf.length, 1);
  
  let trend = 'stable';
  if (secondHalfRate > firstHalfRate + 0.1) trend = 'improving';
  else if (secondHalfRate < firstHalfRate - 0.1) trend = 'declining';

  const totalFindings = learnings.reduce((sum, l) => {
    const findings = l.findings?.length || (Array.isArray(l.findings) ? l.findings : []).length;
    return sum + findings;
  }, 0);

  return {
    overall_success_rate: Math.round(successRate * 100),
    trend,
    avg_findings_per_scan: Math.round(totalFindings / learnings.length * 10) / 10,
    total_vulnerabilities_found: totalFindings,
    total_scans: learnings.length
  };
}

async function getImprovementInsights(data: any): Promise<any> {
  const { tool, metrics, recentLearnings } = data;
  
  return {
    summary: `Tool "${tool}" has a ${metrics.overall_success_rate}% success rate with a ${metrics.trend} trend`,
    key_insights: [
      `Average of ${metrics.avg_findings_per_scan} findings per scan`,
      `Total ${metrics.total_vulnerabilities_found} vulnerabilities discovered`,
      recentLearnings[0]?.improvement_strategy || 'No recent recommendations'
    ],
    next_steps: [
      metrics.trend === 'improving' ? 'Continue current approach' : 'Review scan methodology',
      'Consider expanding target scope',
      'Update tool configurations based on recent findings'
    ]
  };
}

function generateLearningSummary(learnings: any[]): any {
  const toolStats = new Map<string, { success: number; total: number; findings: number }>();
  
  learnings.forEach(l => {
    const tool = l.tool_used;
    const stats = toolStats.get(tool) || { success: 0, total: 0, findings: 0 };
    stats.total++;
    if (l.success) stats.success++;
    stats.findings += l.findings?.length || 0;
    toolStats.set(tool, stats);
  });

  const toolSummaries = Array.from(toolStats.entries()).map(([tool, stats]) => ({
    tool,
    success_rate: Math.round((stats.success / stats.total) * 100),
    total_scans: stats.total,
    total_findings: stats.findings
  }));

  return {
    total_learnings: learnings.length,
    tools_used: toolSummaries.length,
    overall_success_rate: Math.round(
      (learnings.filter(l => l.success).length / Math.max(learnings.length, 1)) * 100
    ),
    by_tool: toolSummaries,
    recent_improvements: learnings.slice(0, 3).map(l => l.improvement_strategy).filter(Boolean),
    last_scan: learnings[0]?.created_at || null
  };
}
