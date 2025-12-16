import { useState, useEffect, useRef } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { useToast } from "@/hooks/use-toast";
import { supabase } from "@/integrations/supabase/client";
import { useKaliTools } from "@/hooks/useKaliTools";
import { 
  Brain, Send, Loader2, Terminal, Target, Zap, 
  BookOpen, TrendingUp, CheckCircle, XCircle, 
  Sparkles, Play, Pause, RotateCcw, Lightbulb,
  Shield, Activity, Clock, AlertTriangle
} from 'lucide-react';

interface Message {
  id: string;
  role: 'user' | 'assistant' | 'system';
  content: string;
  timestamp: Date;
  toolsUsed?: string[];
  executionStatus?: 'pending' | 'running' | 'complete' | 'error';
}

interface AIAnalysis {
  understood_intent: string;
  recommended_tools: string[];
  execution_order: string[];
  parameters: Record<string, string>;
  attack_strategy: string;
  reasoning: string;
  risk_level: string;
  estimated_time: string;
  learning_from_history?: string;
}

interface Learning {
  id: string;
  tool_used: string;
  target: string;
  success: boolean;
  ai_analysis: string;
  improvement_strategy: string;
  success_rate: number;
  created_at: string;
}

interface Stats {
  totalLearnings: number;
  successfulOps: number;
  avgSuccessRate: number;
  toolUsage: Record<string, number>;
}

const AIAssistant = () => {
  const { toast } = useToast();
  const { runNetworkScan, runWebScan, runSQLInjectionTest, activeSessions } = useKaliTools();
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [target, setTarget] = useState('');
  const [isProcessing, setIsProcessing] = useState(false);
  const [currentAnalysis, setCurrentAnalysis] = useState<AIAnalysis | null>(null);
  const [isExecuting, setIsExecuting] = useState(false);
  const [executionProgress, setExecutionProgress] = useState(0);
  const [learnings, setLearnings] = useState<Learning[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [liveOutput, setLiveOutput] = useState<string[]>([]);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    loadLearnings();
    
    // Subscribe to real-time learning updates
    const channel = supabase
      .channel('ai-learnings')
      .on('postgres_changes', {
        event: 'INSERT',
        schema: 'public',
        table: 'ai_learnings'
      }, (payload) => {
        setLearnings(prev => [payload.new as Learning, ...prev]);
        toast({
          title: "🧠 AI Learning Updated",
          description: "New learning recorded from recent operation"
        });
      })
      .subscribe();

    return () => {
      supabase.removeChannel(channel);
    };
  }, []);

  useEffect(() => {
    scrollRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, liveOutput]);

  const loadLearnings = async () => {
    try {
      const { data: { session } } = await supabase.auth.getSession();
      if (!session) return;

      const { data, error } = await supabase.functions.invoke('ai-tool-orchestrator', {
        body: { action: 'get-learnings', data: {} }
      });

      if (data?.learnings) {
        setLearnings(data.learnings);
        setStats(data.stats);
      }
    } catch (error) {
      console.error('Error loading learnings:', error);
    }
  };

  const analyzeIntent = async () => {
    if (!input.trim()) {
      toast({ title: "Please enter a command", variant: "destructive" });
      return;
    }

    setIsProcessing(true);
    const userMessage: Message = {
      id: crypto.randomUUID(),
      role: 'user',
      content: input,
      timestamp: new Date()
    };
    setMessages(prev => [...prev, userMessage]);

    try {
      const { data: { session } } = await supabase.auth.getSession();
      if (!session) {
        toast({ title: "Please login first", variant: "destructive" });
        return;
      }

      const { data, error } = await supabase.functions.invoke('ai-tool-orchestrator', {
        body: { 
          action: 'analyze-intent', 
          data: { userInput: input, target } 
        }
      });

      if (error) throw error;

      const analysis = data.analysis as AIAnalysis;
      setCurrentAnalysis(analysis);

      const assistantMessage: Message = {
        id: crypto.randomUUID(),
        role: 'assistant',
        content: `**Understanding:** ${analysis.understood_intent}\n\n**Strategy:** ${analysis.attack_strategy}\n\n**Tools Selected:** ${analysis.recommended_tools.join(', ')}\n\n**Risk Level:** ${analysis.risk_level}\n\n**Estimated Time:** ${analysis.estimated_time}\n\n${analysis.learning_from_history ? `**Learning Applied:** ${analysis.learning_from_history}` : ''}`,
        timestamp: new Date(),
        toolsUsed: analysis.recommended_tools,
        executionStatus: 'pending'
      };
      setMessages(prev => [...prev, assistantMessage]);
      setInput('');

    } catch (error: any) {
      toast({ 
        title: "Analysis failed", 
        description: error.message, 
        variant: "destructive" 
      });
    } finally {
      setIsProcessing(false);
    }
  };

  const executeTools = async () => {
    if (!currentAnalysis || !target) {
      toast({ title: "Please analyze a command and specify target first", variant: "destructive" });
      return;
    }

    setIsExecuting(true);
    setExecutionProgress(0);
    setLiveOutput([]);

    const systemMessage: Message = {
      id: crypto.randomUUID(),
      role: 'system',
      content: `🚀 Starting autonomous execution of ${currentAnalysis.recommended_tools.length} tools...`,
      timestamp: new Date(),
      executionStatus: 'running'
    };
    setMessages(prev => [...prev, systemMessage]);

    const totalTools = currentAnalysis.execution_order.length;
    const results: any[] = [];

    for (let i = 0; i < currentAnalysis.execution_order.length; i++) {
      const toolKey = currentAnalysis.execution_order[i];
      const progress = ((i + 1) / totalTools) * 100;
      setExecutionProgress(progress);
      
      setLiveOutput(prev => [...prev, `\n[${new Date().toLocaleTimeString()}] Executing: ${toolKey}...`]);

      try {
        const startTime = Date.now();
        let result: any = null;
        let success = false;

        // Execute the actual tool based on toolKey
        switch (toolKey) {
          case 'network_scan':
          case 'port_scan_fast':
            result = await runNetworkScan(target, 'comprehensive');
            success = true;
            break;
          case 'vulnerability_scan':
            result = await runWebScan(target);
            success = true;
            break;
          case 'xss_scan':
            result = await runWebScan(target);
            success = true;
            break;
          case 'sql_injection':
            result = await runSQLInjectionTest(target);
            success = true;
            break;
          case 'subdomain_enum':
          case 'web_crawl':
          case 'directory_fuzzing':
          case 'http_probe':
          case 'wayback_urls':
          case 'parameter_discovery':
          case 'secrets_scan':
            result = await runWebScan(target);
            success = true;
            break;
          default:
            result = await runNetworkScan(target, 'basic');
            success = true;
        }

        const executionTime = Date.now() - startTime;
        results.push({ tool: toolKey, result, success, executionTime });

        setLiveOutput(prev => [...prev, `✅ ${toolKey} completed in ${executionTime}ms`]);
        
        if (result?.output) {
          setLiveOutput(prev => [...prev, result.output.substring(0, 500)]);
        }

        // Record learning for this tool execution
        await supabase.functions.invoke('ai-tool-orchestrator', {
          body: {
            action: 'record-learning',
            data: {
              tool_used: toolKey,
              target,
              findings: result?.findings || [],
              success,
              execution_time: executionTime
            }
          }
        });

      } catch (error: any) {
        setLiveOutput(prev => [...prev, `❌ ${toolKey} failed: ${error.message}`]);
        results.push({ tool: toolKey, error: error.message, success: false });

        // Record failed learning
        await supabase.functions.invoke('ai-tool-orchestrator', {
          body: {
            action: 'record-learning',
            data: {
              tool_used: toolKey,
              target,
              findings: [],
              success: false,
              execution_time: 0,
              error_message: error.message
            }
          }
        });
      }

      // Small delay between tools
      await new Promise(resolve => setTimeout(resolve, 1000));
    }

    const successCount = results.filter(r => r.success).length;
    const completionMessage: Message = {
      id: crypto.randomUUID(),
      role: 'assistant',
      content: `**Execution Complete!**\n\n✅ Successful: ${successCount}/${totalTools} tools\n\n**Results Summary:**\n${results.map(r => `- ${r.tool}: ${r.success ? '✅ Success' : '❌ Failed'}`).join('\n')}\n\n🧠 AI has learned from this execution and will improve future operations.`,
      timestamp: new Date(),
      executionStatus: 'complete'
    };
    setMessages(prev => [...prev, completionMessage]);

    setIsExecuting(false);
    setExecutionProgress(100);
    loadLearnings(); // Refresh learnings
    
    toast({
      title: "🎯 Execution Complete",
      description: `${successCount}/${totalTools} tools executed successfully. AI learnings updated.`
    });
  };

  const generateAttackPlan = async () => {
    if (!target) {
      toast({ title: "Please specify a target", variant: "destructive" });
      return;
    }

    setIsProcessing(true);
    try {
      const { data, error } = await supabase.functions.invoke('ai-tool-orchestrator', {
        body: {
          action: 'generate-attack-plan',
          data: { target, objective: input || 'Full penetration test' }
        }
      });

      if (error) throw error;

      const planMessage: Message = {
        id: crypto.randomUUID(),
        role: 'assistant',
        content: `**🎯 AI-Generated Attack Plan for ${target}**\n\n\`\`\`json\n${JSON.stringify(data.plan, null, 2)}\n\`\`\``,
        timestamp: new Date()
      };
      setMessages(prev => [...prev, planMessage]);

    } catch (error: any) {
      toast({ title: "Failed to generate plan", description: error.message, variant: "destructive" });
    } finally {
      setIsProcessing(false);
    }
  };

  const clearChat = () => {
    setMessages([]);
    setCurrentAnalysis(null);
    setLiveOutput([]);
    setExecutionProgress(0);
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="bg-gradient-to-br from-purple-500/10 to-pink-500/10 border-purple-500/20">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-purple-500/20 rounded-lg">
                <Brain className="h-5 w-5 text-purple-400" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Total Learnings</p>
                <p className="text-2xl font-bold">{stats?.totalLearnings || 0}</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-green-500/10 to-emerald-500/10 border-green-500/20">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-green-500/20 rounded-lg">
                <CheckCircle className="h-5 w-5 text-green-400" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Success Rate</p>
                <p className="text-2xl font-bold">{stats?.avgSuccessRate || 0}%</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-blue-500/10 to-cyan-500/10 border-blue-500/20">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-blue-500/20 rounded-lg">
                <Zap className="h-5 w-5 text-blue-400" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Tools Mastered</p>
                <p className="text-2xl font-bold">{Object.keys(stats?.toolUsage || {}).length}</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-orange-500/10 to-red-500/10 border-orange-500/20">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-orange-500/20 rounded-lg">
                <Activity className="h-5 w-5 text-orange-400" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Active Sessions</p>
                <p className="text-2xl font-bold">{activeSessions.length}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main Chat Interface */}
        <div className="lg:col-span-2">
          <Card className="h-[700px] flex flex-col">
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Brain className="h-6 w-6 text-primary animate-pulse" />
                  <CardTitle>AI Security Assistant</CardTitle>
                </div>
                <div className="flex gap-2">
                  <Button variant="outline" size="sm" onClick={clearChat}>
                    <RotateCcw className="h-4 w-4 mr-1" />
                    Clear
                  </Button>
                </div>
              </div>
              <CardDescription>
                Natural language commands → Automatic tool selection → Self-learning execution
              </CardDescription>
            </CardHeader>

            <CardContent className="flex-1 flex flex-col overflow-hidden">
              {/* Messages Area */}
              <ScrollArea className="flex-1 pr-4 mb-4">
                <div className="space-y-4">
                  {messages.length === 0 && (
                    <div className="text-center py-12 text-muted-foreground">
                      <Sparkles className="h-12 w-12 mx-auto mb-4 opacity-50" />
                      <p className="text-lg font-medium">AI Security Assistant Ready</p>
                      <p className="text-sm mt-2">Try commands like:</p>
                      <div className="mt-4 space-y-2">
                        <Badge variant="outline" className="mx-1">"Scan the network for vulnerabilities"</Badge>
                        <Badge variant="outline" className="mx-1">"Find SQL injection points"</Badge>
                        <Badge variant="outline" className="mx-1">"Enumerate subdomains"</Badge>
                        <Badge variant="outline" className="mx-1">"Run a full penetration test"</Badge>
                      </div>
                    </div>
                  )}

                  {messages.map((message) => (
                    <div
                      key={message.id}
                      className={`flex ${message.role === 'user' ? 'justify-end' : 'justify-start'}`}
                    >
                      <div
                        className={`max-w-[80%] rounded-lg p-4 ${
                          message.role === 'user'
                            ? 'bg-primary text-primary-foreground'
                            : message.role === 'system'
                            ? 'bg-yellow-500/10 border border-yellow-500/20'
                            : 'bg-muted'
                        }`}
                      >
                        {message.role === 'assistant' && (
                          <div className="flex items-center gap-2 mb-2">
                            <Brain className="h-4 w-4" />
                            <span className="text-xs font-medium">AI Assistant</span>
                            {message.executionStatus && (
                              <Badge variant={
                                message.executionStatus === 'complete' ? 'default' :
                                message.executionStatus === 'error' ? 'destructive' :
                                'secondary'
                              } className="text-xs">
                                {message.executionStatus}
                              </Badge>
                            )}
                          </div>
                        )}
                        <div className="whitespace-pre-wrap text-sm">
                          {message.content}
                        </div>
                        {message.toolsUsed && message.toolsUsed.length > 0 && (
                          <div className="mt-2 flex flex-wrap gap-1">
                            {message.toolsUsed.map(tool => (
                              <Badge key={tool} variant="outline" className="text-xs">
                                {tool}
                              </Badge>
                            ))}
                          </div>
                        )}
                        <p className="text-xs opacity-50 mt-2">
                          {message.timestamp.toLocaleTimeString()}
                        </p>
                      </div>
                    </div>
                  ))}

                  {/* Live Output */}
                  {liveOutput.length > 0 && (
                    <Card className="bg-black/50 border-green-500/20">
                      <CardContent className="p-4">
                        <div className="flex items-center gap-2 mb-2">
                          <Terminal className="h-4 w-4 text-green-400" />
                          <span className="text-sm font-medium text-green-400">Live Output</span>
                        </div>
                        <ScrollArea className="h-48">
                          <pre className="text-xs text-green-400 font-mono whitespace-pre-wrap">
                            {liveOutput.join('\n')}
                          </pre>
                        </ScrollArea>
                      </CardContent>
                    </Card>
                  )}

                  <div ref={scrollRef} />
                </div>
              </ScrollArea>

              {/* Execution Progress */}
              {isExecuting && (
                <div className="mb-4">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm text-muted-foreground">Execution Progress</span>
                    <span className="text-sm font-medium">{Math.round(executionProgress)}%</span>
                  </div>
                  <Progress value={executionProgress} className="h-2" />
                </div>
              )}

              {/* Input Area */}
              <div className="space-y-3">
                <div className="flex gap-2">
                  <Input
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    placeholder="Target (IP/domain/URL)"
                    className="w-1/3"
                  />
                  <Input
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    placeholder="Tell AI what to do... (e.g., 'scan for vulnerabilities')"
                    className="flex-1"
                    onKeyPress={(e) => e.key === 'Enter' && analyzeIntent()}
                    disabled={isProcessing || isExecuting}
                  />
                </div>
                <div className="flex gap-2">
                  <Button 
                    onClick={analyzeIntent} 
                    disabled={isProcessing || isExecuting}
                    className="flex-1"
                  >
                    {isProcessing ? (
                      <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    ) : (
                      <Lightbulb className="h-4 w-4 mr-2" />
                    )}
                    Analyze & Plan
                  </Button>
                  <Button 
                    onClick={executeTools} 
                    disabled={!currentAnalysis || isExecuting || isProcessing}
                    variant="default"
                    className="flex-1 bg-green-600 hover:bg-green-700"
                  >
                    {isExecuting ? (
                      <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    ) : (
                      <Play className="h-4 w-4 mr-2" />
                    )}
                    Execute
                  </Button>
                  <Button 
                    onClick={generateAttackPlan}
                    disabled={isProcessing || isExecuting}
                    variant="outline"
                  >
                    <Target className="h-4 w-4 mr-2" />
                    Full Plan
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Learnings Panel */}
        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <BookOpen className="h-5 w-5" />
                AI Learning History
              </CardTitle>
              <CardDescription>Self-improving from every operation</CardDescription>
            </CardHeader>
            <CardContent>
              <Tabs defaultValue="learnings">
                <TabsList className="grid w-full grid-cols-2">
                  <TabsTrigger value="learnings">Learnings</TabsTrigger>
                  <TabsTrigger value="stats">Statistics</TabsTrigger>
                </TabsList>

                <TabsContent value="learnings">
                  <ScrollArea className="h-[450px]">
                    <div className="space-y-3">
                      {learnings.length === 0 ? (
                        <div className="text-center py-8 text-muted-foreground">
                          <Brain className="h-8 w-8 mx-auto mb-2 opacity-50" />
                          <p className="text-sm">No learnings yet</p>
                          <p className="text-xs">Execute tools to start learning</p>
                        </div>
                      ) : (
                        learnings.map((learning) => (
                          <Card key={learning.id} className={`p-3 ${learning.success ? 'border-green-500/20' : 'border-red-500/20'}`}>
                            <div className="flex items-start justify-between mb-2">
                              <Badge variant={learning.success ? "default" : "destructive"}>
                                {learning.tool_used}
                              </Badge>
                              {learning.success ? (
                                <CheckCircle className="h-4 w-4 text-green-400" />
                              ) : (
                                <XCircle className="h-4 w-4 text-red-400" />
                              )}
                            </div>
                            <p className="text-xs text-muted-foreground mb-1">
                              Target: {learning.target || 'N/A'}
                            </p>
                            {learning.improvement_strategy && (
                              <p className="text-xs mt-2 p-2 bg-muted rounded">
                                💡 {learning.improvement_strategy.substring(0, 150)}...
                              </p>
                            )}
                            <p className="text-xs text-muted-foreground mt-2">
                              {new Date(learning.created_at).toLocaleString()}
                            </p>
                          </Card>
                        ))
                      )}
                    </div>
                  </ScrollArea>
                </TabsContent>

                <TabsContent value="stats">
                  <div className="space-y-4">
                    <div className="grid grid-cols-2 gap-3">
                      <Card className="p-3">
                        <p className="text-xs text-muted-foreground">Total Ops</p>
                        <p className="text-xl font-bold">{stats?.totalLearnings || 0}</p>
                      </Card>
                      <Card className="p-3">
                        <p className="text-xs text-muted-foreground">Successful</p>
                        <p className="text-xl font-bold text-green-400">{stats?.successfulOps || 0}</p>
                      </Card>
                    </div>

                    <Card className="p-3">
                      <p className="text-xs text-muted-foreground mb-2">Tool Usage</p>
                      <div className="space-y-2">
                        {Object.entries(stats?.toolUsage || {}).map(([tool, count]) => (
                          <div key={tool} className="flex items-center justify-between">
                            <span className="text-xs">{tool}</span>
                            <Badge variant="outline">{count}</Badge>
                          </div>
                        ))}
                      </div>
                    </Card>

                    <Card className="p-3 bg-gradient-to-br from-purple-500/10 to-pink-500/10">
                      <div className="flex items-center gap-2 mb-2">
                        <TrendingUp className="h-4 w-4 text-purple-400" />
                        <p className="text-xs font-medium">AI Improvement</p>
                      </div>
                      <p className="text-xs text-muted-foreground">
                        The AI learns from each operation and improves tool selection, 
                        parameter optimization, and attack strategies over time.
                      </p>
                    </Card>
                  </div>
                </TabsContent>
              </Tabs>
            </CardContent>
          </Card>

          {/* Current Analysis Preview */}
          {currentAnalysis && (
            <Card className="border-primary/20">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Zap className="h-4 w-4 text-yellow-400" />
                  Ready to Execute
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2 text-xs">
                  <div className="flex items-center gap-2">
                    <AlertTriangle className={`h-3 w-3 ${
                      currentAnalysis.risk_level === 'high' ? 'text-red-400' :
                      currentAnalysis.risk_level === 'medium' ? 'text-yellow-400' :
                      'text-green-400'
                    }`} />
                    <span>Risk: {currentAnalysis.risk_level}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Clock className="h-3 w-3 text-muted-foreground" />
                    <span>{currentAnalysis.estimated_time}</span>
                  </div>
                  <div className="flex flex-wrap gap-1 mt-2">
                    {currentAnalysis.recommended_tools.map(tool => (
                      <Badge key={tool} variant="secondary" className="text-xs">
                        {tool}
                      </Badge>
                    ))}
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
};

export default AIAssistant;
