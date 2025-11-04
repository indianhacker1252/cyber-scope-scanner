import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';
import { Brain, Zap, Shield, Target, Activity, AlertTriangle, CheckCircle, XCircle, Play, Pause, RotateCcw } from 'lucide-react';

export default function AutonomousHacking() {
  const { toast } = useToast();
  const [target, setTarget] = useState('');
  const [objective, setObjective] = useState('full-pentest');
  const [loading, setLoading] = useState(false);
  const [targetIntelligence, setTargetIntelligence] = useState<any>(null);
  const [attackChain, setAttackChain] = useState<any>(null);
  const [executionResults, setExecutionResults] = useState<any[]>([]);
  const [isExecuting, setIsExecuting] = useState(false);
  const [attackAttempts, setAttackAttempts] = useState<any[]>([]);
  const [learnings, setLearnings] = useState<any[]>([]);

  // Real-time updates for attack chain execution
  useEffect(() => {
    if (!attackChain?.chain_id) return;

    const channel = supabase
      .channel('attack_chain_updates')
      .on(
        'postgres_changes',
        {
          event: 'UPDATE',
          schema: 'public',
          table: 'attack_chains',
          filter: `id=eq.${attackChain.chain_id}`
        },
        (payload) => {
          console.log('Chain update:', payload);
          if (payload.new.results) {
            setExecutionResults(payload.new.results);
          }
          if (payload.new.status === 'completed') {
            setIsExecuting(false);
            toast({
              title: "Attack Chain Completed",
              description: "Autonomous attack chain has finished execution",
            });
          }
        }
      )
      .subscribe();

    return () => {
      supabase.removeChannel(channel);
    };
  }, [attackChain?.chain_id]);

  const analyzeTarget = async () => {
    if (!target) {
      toast({
        title: "Error",
        description: "Please enter a target",
        variant: "destructive",
      });
      return;
    }

    setLoading(true);
    try {
      // First, run basic reconnaissance
      toast({
        title: "Starting Reconnaissance",
        description: "Gathering intelligence on target...",
      });

      // Simulate reconnaissance data (in production, this would come from actual scans)
      const reconData = {
        nmap: `Scanning ${target}...\nPorts: 80, 443, 22 open`,
        dns: `DNS records found for ${target}`,
        ssl: `SSL certificate detected`,
      };

      // Send to AI for deep analysis
      const { data, error } = await supabase.functions.invoke('ai-attack-orchestrator', {
        body: {
          action: 'analyze-target',
          data: {
            target,
            reconnaissance_data: reconData
          }
        }
      });

      if (error) throw error;

      setTargetIntelligence(data.analysis);
      toast({
        title: "Target Analysis Complete",
        description: `AI identified ${data.analysis.vulnerabilities?.length || 0} potential vulnerabilities`,
      });
    } catch (error) {
      console.error('Analysis error:', error);
      toast({
        title: "Analysis Failed",
        description: error.message,
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const createAttackChain = async () => {
    if (!targetIntelligence) {
      toast({
        title: "Error",
        description: "Please analyze target first",
        variant: "destructive",
      });
      return;
    }

    setLoading(true);
    try {
      const { data, error } = await supabase.functions.invoke('ai-attack-orchestrator', {
        body: {
          action: 'create-attack-chain',
          data: {
            target,
            objective,
            intelligence: targetIntelligence
          }
        }
      });

      if (error) throw error;

      setAttackChain(data);
      toast({
        title: "Attack Chain Created",
        description: `${data.chain.total_stages} stages planned with AI intelligence`,
      });
    } catch (error) {
      console.error('Chain creation error:', error);
      toast({
        title: "Failed to Create Chain",
        description: error.message,
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const executeAutonomously = async () => {
    if (!attackChain?.chain_id) {
      toast({
        title: "Error",
        description: "Please create attack chain first",
        variant: "destructive",
      });
      return;
    }

    setIsExecuting(true);
    setExecutionResults([]);

    try {
      toast({
        title: "Autonomous Execution Started",
        description: "AI is executing attack chain with adaptive learning...",
      });

      const { data, error } = await supabase.functions.invoke('autonomous-attack-executor', {
        body: {
          chain_id: attackChain.chain_id
        }
      });

      if (error) throw error;

      toast({
        title: "Execution Complete",
        description: `${data.completed_stages}/${data.total_stages} stages executed`,
      });
    } catch (error) {
      console.error('Execution error:', error);
      toast({
        title: "Execution Failed",
        description: error.message,
        variant: "destructive",
      });
    } finally {
      setIsExecuting(false);
    }
  };

  const loadAttackHistory = async () => {
    try {
      // @ts-ignore - Types will be regenerated after migration
      const { data: attempts } = await supabase
        .from('attack_attempts')
        .select('*')
        .order('created_at', { ascending: false })
        .limit(10);

      setAttackAttempts(attempts || []);

      // @ts-ignore - Types will be regenerated after migration
      const { data: learningsData } = await supabase
        .from('attack_learnings')
        .select('*')
        .order('created_at', { ascending: false })
        .limit(5);

      setLearnings(learningsData || []);
    } catch (error) {
      console.error('Failed to load history:', error);
    }
  };

  useEffect(() => {
    loadAttackHistory();
  }, []);

  return (
    <div className="space-y-6">
      <Card className="border-primary/20 bg-gradient-to-br from-background to-primary/5">
        <CardHeader>
          <div className="flex items-center gap-2">
            <Brain className="h-6 w-6 text-primary" />
            <CardTitle>Autonomous AI-Powered Hacking</CardTitle>
          </div>
          <CardDescription>
            Let AI automatically analyze, learn, adapt, and execute sophisticated attack chains
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="target">Target</Label>
              <Input
                id="target"
                placeholder="example.com or 192.168.1.1"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="objective">Attack Objective</Label>
              <select
                id="objective"
                className="w-full px-3 py-2 border rounded-md"
                value={objective}
                onChange={(e) => setObjective(e.target.value)}
              >
                <option value="full-pentest">Full Penetration Test</option>
                <option value="vulnerability-scan">Vulnerability Assessment Only</option>
                <option value="exploitation">Exploitation & Post-Exploitation</option>
                <option value="credential-access">Credential Access</option>
                <option value="data-exfiltration">Data Discovery & Exfiltration</option>
              </select>
            </div>
            <div className="flex gap-2">
              <Button
                onClick={analyzeTarget}
                disabled={loading || !target}
                className="flex-1"
              >
                <Target className="mr-2 h-4 w-4" />
                {loading ? 'Analyzing...' : '1. AI Target Analysis'}
              </Button>
              <Button
                onClick={createAttackChain}
                disabled={loading || !targetIntelligence}
                variant="secondary"
                className="flex-1"
              >
                <Brain className="mr-2 h-4 w-4" />
                2. Generate Attack Chain
              </Button>
              <Button
                onClick={executeAutonomously}
                disabled={isExecuting || !attackChain}
                variant="default"
                className="flex-1"
              >
                {isExecuting ? (
                  <>
                    <Activity className="mr-2 h-4 w-4 animate-spin" />
                    Executing...
                  </>
                ) : (
                  <>
                    <Zap className="mr-2 h-4 w-4" />
                    3. Execute Autonomously
                  </>
                )}
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      <Tabs defaultValue="intelligence" className="w-full">
        <TabsList className="grid w-full grid-cols-5">
          <TabsTrigger value="intelligence">Intelligence</TabsTrigger>
          <TabsTrigger value="chain">Attack Chain</TabsTrigger>
          <TabsTrigger value="execution">Live Execution</TabsTrigger>
          <TabsTrigger value="learnings">AI Learnings</TabsTrigger>
          <TabsTrigger value="history">History</TabsTrigger>
        </TabsList>

        <TabsContent value="intelligence">
          <Card>
            <CardHeader>
              <CardTitle>Target Intelligence</CardTitle>
              <CardDescription>AI-powered deep analysis of target</CardDescription>
            </CardHeader>
            <CardContent>
              {targetIntelligence ? (
                <ScrollArea className="h-[500px]">
                  <div className="space-y-6">
                    <div>
                      <h3 className="font-semibold mb-2 flex items-center gap-2">
                        <Shield className="h-4 w-4" />
                        Technology Stack
                      </h3>
                      <div className="flex flex-wrap gap-2">
                        {targetIntelligence.tech_stack?.map((tech: string, i: number) => (
                          <Badge key={i} variant="secondary">{tech}</Badge>
                        ))}
                      </div>
                    </div>

                    <div>
                      <h3 className="font-semibold mb-2 flex items-center gap-2">
                        <AlertTriangle className="h-4 w-4 text-destructive" />
                        Vulnerabilities Detected
                      </h3>
                      <ul className="list-disc list-inside space-y-1">
                        {targetIntelligence.vulnerabilities?.map((vuln: string, i: number) => (
                          <li key={i} className="text-sm">{vuln}</li>
                        ))}
                      </ul>
                    </div>

                    <div>
                      <h3 className="font-semibold mb-2">Attack Surface</h3>
                      <ul className="list-disc list-inside space-y-1">
                        {targetIntelligence.attack_surface?.map((surface: string, i: number) => (
                          <li key={i} className="text-sm">{surface}</li>
                        ))}
                      </ul>
                    </div>

                    <div>
                      <h3 className="font-semibold mb-2 flex items-center gap-2">
                        <Target className="h-4 w-4 text-primary" />
                        Prioritized Weak Points
                      </h3>
                      <ol className="list-decimal list-inside space-y-1">
                        {targetIntelligence.weak_points?.map((point: string, i: number) => (
                          <li key={i} className="text-sm font-medium">{point}</li>
                        ))}
                      </ol>
                    </div>

                    <div className="flex gap-4">
                      <Badge variant="outline">
                        Confidence: {targetIntelligence.ai_confidence}
                      </Badge>
                      <Badge variant="outline">
                        Difficulty: {targetIntelligence.estimated_difficulty}
                      </Badge>
                    </div>
                  </div>
                </ScrollArea>
              ) : (
                <p className="text-muted-foreground text-center py-12">
                  No intelligence data yet. Start by analyzing a target.
                </p>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="chain">
          <Card>
            <CardHeader>
              <CardTitle>AI-Generated Attack Chain</CardTitle>
              <CardDescription>Autonomous multi-stage attack sequence</CardDescription>
            </CardHeader>
            <CardContent>
              {attackChain?.chain ? (
                <ScrollArea className="h-[500px]">
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <h3 className="font-bold text-lg">{attackChain.chain.chain_name}</h3>
                      <div className="flex gap-2">
                        <Badge>{attackChain.chain.total_stages} stages</Badge>
                        <Badge variant="secondary">{attackChain.chain.estimated_time}</Badge>
                        <Badge variant={attackChain.chain.risk_level === 'high' ? 'destructive' : 'default'}>
                          {attackChain.chain.risk_level} risk
                        </Badge>
                      </div>
                    </div>

                    {attackChain.chain.attack_sequence?.map((stage: any, i: number) => (
                      <Card key={i} className="p-4">
                        <div className="space-y-2">
                          <div className="flex items-center justify-between">
                            <h4 className="font-semibold">Stage {stage.stage}: {stage.name}</h4>
                            <Badge variant="outline">{stage.tool}</Badge>
                          </div>
                          <p className="text-sm text-muted-foreground">{stage.technique}</p>
                          <div className="bg-muted p-2 rounded text-xs font-mono">
                            {stage.command}
                          </div>
                          <p className="text-xs italic">Reason: {stage.reason}</p>
                          <div className="flex gap-2 text-xs">
                            <span>✅ On success → {stage.on_success}</span>
                            <span>❌ On failure → {stage.on_failure || 'stop'}</span>
                          </div>
                        </div>
                      </Card>
                    ))}
                  </div>
                </ScrollArea>
              ) : (
                <p className="text-muted-foreground text-center py-12">
                  No attack chain generated yet. Analyze target first.
                </p>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="execution">
          <Card>
            <CardHeader>
              <CardTitle>Live Execution Monitor</CardTitle>
              <CardDescription>Real-time autonomous attack execution with AI adaptation</CardDescription>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[500px]">
                {executionResults.length > 0 ? (
                  <div className="space-y-3">
                    {executionResults.map((result: any, i: number) => (
                      <Card key={i} className={`p-4 ${result.success ? 'border-green-500' : 'border-red-500'}`}>
                        <div className="space-y-2">
                          <div className="flex items-center justify-between">
                            <h4 className="font-semibold flex items-center gap-2">
                              {result.success ? (
                                <CheckCircle className="h-4 w-4 text-green-500" />
                              ) : (
                                <XCircle className="h-4 w-4 text-red-500" />
                              )}
                              Stage {result.stage}: {result.name}
                            </h4>
                            <span className="text-xs text-muted-foreground">
                              {new Date(result.timestamp).toLocaleTimeString()}
                            </span>
                          </div>
                          {result.adaptation && (
                            <Badge variant="default" className="mb-2">
                              <RotateCcw className="h-3 w-3 mr-1" />
                              AI Adapted: {result.adaptation}
                            </Badge>
                          )}
                          <pre className="text-xs bg-muted p-2 rounded overflow-x-auto">
                            {result.output || result.error}
                          </pre>
                        </div>
                      </Card>
                    ))}
                  </div>
                ) : (
                  <p className="text-muted-foreground text-center py-12">
                    {isExecuting ? 'Execution starting...' : 'No execution results yet'}
                  </p>
                )}
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="learnings">
          <Card>
            <CardHeader>
              <CardTitle>AI Learnings from Failures</CardTitle>
              <CardDescription>How AI adapts and improves from failed attacks</CardDescription>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[500px]">
                {learnings.length > 0 ? (
                  <div className="space-y-4">
                    {learnings.map((learning: any, i: number) => (
                      <Card key={i} className="p-4 bg-primary/5">
                        <div className="space-y-2">
                          <h4 className="font-semibold">Learning #{i + 1}</h4>
                          <p className="text-sm"><strong>Failure Reason:</strong> {learning.failure_reason}</p>
                          <div className="text-sm">
                            <strong>Adaptation Strategy:</strong>
                            <pre className="mt-1 bg-muted p-2 rounded text-xs">
                              {learning.adaptation_strategy}
                            </pre>
                          </div>
                          <p className="text-xs italic text-muted-foreground">{learning.ai_analysis}</p>
                          <span className="text-xs text-muted-foreground">
                            {new Date(learning.created_at).toLocaleString()}
                          </span>
                        </div>
                      </Card>
                    ))}
                  </div>
                ) : (
                  <p className="text-muted-foreground text-center py-12">
                    No learnings yet. AI will learn from failed attacks automatically.
                  </p>
                )}
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="history">
          <Card>
            <CardHeader>
              <CardTitle>Attack Attempt History</CardTitle>
              <CardDescription>All recorded attack attempts and outcomes</CardDescription>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[500px]">
                {attackAttempts.length > 0 ? (
                  <div className="space-y-2">
                    {attackAttempts.map((attempt: any, i: number) => (
                      <div key={i} className="flex items-center justify-between p-3 border rounded">
                        <div className="flex-1">
                          <p className="font-medium">{attempt.technique}</p>
                          <p className="text-sm text-muted-foreground">Target: {attempt.target}</p>
                        </div>
                        <div className="flex items-center gap-2">
                          {attempt.success ? (
                            <Badge variant="default">Success</Badge>
                          ) : (
                            <Badge variant="destructive">Failed</Badge>
                          )}
                          <span className="text-xs text-muted-foreground">
                            {new Date(attempt.created_at).toLocaleDateString()}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-muted-foreground text-center py-12">
                    No attack history yet
                  </p>
                )}
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}