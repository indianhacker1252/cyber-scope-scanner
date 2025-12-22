import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Progress } from "@/components/ui/progress";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { 
  Brain, 
  Target, 
  Play, 
  Pause, 
  RotateCcw, 
  Shield, 
  Cpu, 
  Database,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Clock,
  Zap,
  GitBranch,
  Eye,
  Lock,
  Unlock,
  ChevronRight,
  Activity,
  Terminal,
  FileJson
} from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { toast } from "sonner";

interface ApexSession {
  id: string;
  session_name: string;
  target: string;
  target_type: string;
  status: string;
  current_phase: string;
  authorized: boolean;
  target_map: any;
  findings: any[];
  attack_chain: any;
  constraints: any[];
  created_at: string;
}

interface ApexTask {
  id: string;
  task_type: string;
  task_name: string;
  description: string;
  tool_selected: string;
  reasoning: string;
  status: string;
  priority: number;
  stdout: string;
  stderr: string;
  result_analysis: string;
}

const ApexSentinel = () => {
  const [activeTab, setActiveTab] = useState("control");
  const [sessions, setSessions] = useState<ApexSession[]>([]);
  const [currentSession, setCurrentSession] = useState<ApexSession | null>(null);
  const [tasks, setTasks] = useState<ApexTask[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [output, setOutput] = useState<string[]>([]);
  
  // Session creation
  const [newTarget, setNewTarget] = useState("");
  const [targetType, setTargetType] = useState("ip");
  const [sessionName, setSessionName] = useState("");
  const [authorizedTargets, setAuthorizedTargets] = useState("");

  // Real-time findings report
  const [findingsReport, setFindingsReport] = useState<any>({
    session_id: null,
    phase: "idle",
    discovered_services: [],
    vulnerabilities: [],
    exploitation_attempts: [],
    recommendations: [],
    risk_score: 0,
  });

  const addOutput = (message: string) => {
    const timestamp = new Date().toLocaleTimeString();
    setOutput(prev => [...prev, `[${timestamp}] ${message}`]);
  };

  const invokeApexSentinel = async (action: string, data: any) => {
    const { data: { session } } = await supabase.auth.getSession();
    if (!session) {
      toast.error("Please log in to use Apex Sentinel");
      return null;
    }

    const response = await supabase.functions.invoke('apex-sentinel', {
      body: { action, data },
    });

    if (response.error) {
      throw new Error(response.error.message);
    }

    return response.data;
  };

  const loadSessions = async () => {
    try {
      const result = await invokeApexSentinel('get-user-sessions', {});
      if (result?.sessions) {
        setSessions(result.sessions);
      }
    } catch (error) {
      console.error('Error loading sessions:', error);
    }
  };

  useEffect(() => {
    loadSessions();
  }, []);

  const createSession = async () => {
    if (!newTarget) {
      toast.error("Please enter a target");
      return;
    }

    setIsLoading(true);
    addOutput(`🎯 Creating new session for target: ${newTarget}`);

    try {
      const authorizedList = authorizedTargets.split('\n').filter(t => t.trim());
      
      const result = await invokeApexSentinel('create-session', {
        target: newTarget,
        targetType,
        sessionName: sessionName || `Session-${Date.now()}`,
        authorizedTargets: authorizedList,
      });

      if (result?.session) {
        setCurrentSession(result.session);
        setSessions(prev => [result.session, ...prev]);
        addOutput(`✅ Session created: ${result.session.id}`);
        
        if (!result.session.authorized) {
          addOutput(`⚠️ WARNING: Target not in authorized list. Operations will be restricted.`);
          toast.warning("Target not authorized. Add to authorized_targets.txt");
        }

        setFindingsReport(prev => ({
          ...prev,
          session_id: result.session.id,
          phase: "initialized",
        }));

        toast.success("Session created successfully");
      }
    } catch (error: any) {
      addOutput(`❌ Error: ${error.message}`);
      toast.error(error.message);
    } finally {
      setIsLoading(false);
    }
  };

  const planAttack = async () => {
    if (!currentSession) {
      toast.error("No active session");
      return;
    }

    setIsLoading(true);
    addOutput(`🧠 AI Planner analyzing target: ${currentSession.target}`);
    addOutput(`📊 Using Chain-of-Thought reasoning to generate attack plan...`);

    try {
      const result = await invokeApexSentinel('plan-attack', {
        sessionId: currentSession.id,
        targetInfo: currentSession.target_map,
        previousResults: currentSession.findings,
      });

      if (result?.plan) {
        addOutput(`✅ Attack plan generated with ${result.tasksCreated} tasks`);
        addOutput(`📋 Plan overview:`);
        
        result.plan.tasks?.forEach((task: any, i: number) => {
          addOutput(`   ${i + 1}. [${task.task_type}] ${task.task_name} → ${task.recommended_tool}`);
        });

        // Refresh tasks
        const statusResult = await invokeApexSentinel('get-session-status', {
          sessionId: currentSession.id,
        });
        
        if (statusResult?.tasks) {
          setTasks(statusResult.tasks);
        }

        setFindingsReport(prev => ({
          ...prev,
          phase: "planning_complete",
        }));

        toast.success(`Attack plan created: ${result.tasksCreated} tasks`);
      }
    } catch (error: any) {
      addOutput(`❌ Planning error: ${error.message}`);
      toast.error(error.message);
    } finally {
      setIsLoading(false);
    }
  };

  const executeTask = async (taskId: string) => {
    if (!currentSession) return;

    setIsLoading(true);
    const task = tasks.find(t => t.id === taskId);
    addOutput(`⚡ Executing task: ${task?.task_name}`);
    addOutput(`🔧 Tool: ${task?.tool_selected}`);

    try {
      const result = await invokeApexSentinel('execute-task', {
        taskId,
        sessionId: currentSession.id,
      });

      if (result?.execution) {
        addOutput(`📤 Execution result: ${result.taskStatus}`);
        
        if (result.execution.stdout) {
          addOutput(`📝 Output:\n${result.execution.stdout}`);
        }
        
        if (result.execution.stderr) {
          addOutput(`⚠️ Stderr: ${result.execution.stderr}`);
        }

        if (result.execution.blocked_by) {
          addOutput(`🛡️ Blocked by: ${result.execution.blocked_by}`);
          addOutput(`🔄 Initiating re-enhancement strategy...`);
          
          // Trigger re-enhance
          await reEnhanceAttack(taskId, `Blocked by ${result.execution.blocked_by}`);
        }

        // Run critic analysis
        await criticAnalyze(taskId, result.execution);

        // Refresh tasks
        const statusResult = await invokeApexSentinel('get-session-status', {
          sessionId: currentSession.id,
        });
        
        if (statusResult?.tasks) {
          setTasks(statusResult.tasks);
        }

        // Update findings report
        if (result.execution.parsed_results) {
          setFindingsReport(prev => ({
            ...prev,
            phase: "executing",
            discovered_services: [
              ...prev.discovered_services,
              ...(result.execution.parsed_results.ports || []),
            ],
            vulnerabilities: [
              ...prev.vulnerabilities,
              ...(result.execution.parsed_results.findings || []),
              ...(result.execution.parsed_results.vulnerabilities || []),
            ],
          }));
        }
      }
    } catch (error: any) {
      addOutput(`❌ Execution error: ${error.message}`);
      toast.error(error.message);
    } finally {
      setIsLoading(false);
    }
  };

  const criticAnalyze = async (taskId: string, executionResults: any) => {
    if (!currentSession) return;

    addOutput(`🔍 Critic analyzing results...`);

    try {
      const result = await invokeApexSentinel('critic-analyze', {
        sessionId: currentSession.id,
        taskId,
        executionResults,
      });

      if (result?.analysis) {
        addOutput(`📊 Critic Analysis:`);
        addOutput(`   Objective met: ${result.analysis.objective_met ? '✅' : '❌'}`);
        
        if (result.analysis.findings?.length > 0) {
          addOutput(`   Findings: ${result.analysis.findings.length} items discovered`);
        }
        
        if (result.analysis.next_steps?.length > 0) {
          addOutput(`   Recommended next steps:`);
          result.analysis.next_steps.forEach((step: string, i: number) => {
            addOutput(`      ${i + 1}. ${step}`);
          });
        }

        if (result.analysis.mutation_needed) {
          addOutput(`   ⚠️ Mutation required: ${result.analysis.mutation_strategy?.type}`);
        }

        setFindingsReport(prev => ({
          ...prev,
          recommendations: [
            ...prev.recommendations,
            ...(result.analysis.next_steps || []),
          ],
        }));
      }
    } catch (error: any) {
      addOutput(`❌ Critic error: ${error.message}`);
    }
  };

  const reEnhanceAttack = async (taskId: string, failureReason: string) => {
    if (!currentSession) return;

    addOutput(`🔄 Re-enhancing attack method...`);
    addOutput(`📝 Failure reason: ${failureReason}`);

    try {
      const result = await invokeApexSentinel('re-enhance-attack', {
        sessionId: currentSession.id,
        failedTaskId: taskId,
        failureReason,
      });

      if (result?.strategy) {
        addOutput(`✅ New strategy generated:`);
        addOutput(`   Approach: ${result.strategy.new_approach}`);
        addOutput(`   Mutation: ${result.strategy.mutation_type}`);
        addOutput(`   Reasoning: ${result.strategy.reasoning}`);

        if (result.newTask) {
          addOutput(`📋 New task created: ${result.newTask.task_name}`);
          setTasks(prev => [result.newTask, ...prev]);
        }
      }
    } catch (error: any) {
      addOutput(`❌ Re-enhancement error: ${error.message}`);
    }
  };

  const executeAllTasks = async () => {
    const pendingTasks = tasks.filter(t => t.status === 'pending');
    
    for (const task of pendingTasks) {
      await executeTask(task.id);
      // Small delay between tasks
      await new Promise(resolve => setTimeout(resolve, 1000));
    }

    addOutput(`✅ All tasks executed. Saving successful chain...`);
    
    // Save successful chain
    try {
      await invokeApexSentinel('save-successful-chain', {
        sessionId: currentSession?.id,
      });
      addOutput(`💾 Successful attack chain saved to knowledge base`);
    } catch (error) {
      console.error('Error saving chain:', error);
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'success': return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'failed': return <XCircle className="h-4 w-4 text-red-500" />;
      case 'blocked': return <Shield className="h-4 w-4 text-yellow-500" />;
      case 'executing': return <Activity className="h-4 w-4 text-blue-500 animate-pulse" />;
      default: return <Clock className="h-4 w-4 text-muted-foreground" />;
    }
  };

  const getPhaseProgress = () => {
    const phases = ['discovery', 'vulnerability_correlation', 'exploitation', 'post_exploitation', 'hardware_check'];
    const currentIndex = phases.indexOf(currentSession?.current_phase || 'discovery');
    return ((currentIndex + 1) / phases.length) * 100;
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <Brain className="h-8 w-8 text-primary" />
            Apex Sentinel
          </h1>
          <p className="text-muted-foreground mt-1">
            Autonomous AI-Driven Offensive Security System
          </p>
        </div>
        
        {currentSession && (
          <div className="flex items-center gap-4">
            <Badge variant={currentSession.authorized ? "default" : "destructive"}>
              {currentSession.authorized ? (
                <><Unlock className="h-3 w-3 mr-1" /> Authorized</>
              ) : (
                <><Lock className="h-3 w-3 mr-1" /> Unauthorized</>
              )}
            </Badge>
            <Badge variant="outline">{currentSession.current_phase}</Badge>
          </div>
        )}
      </div>

      {/* Global Scoping Warning */}
      {currentSession && !currentSession.authorized && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>
            Target is not in the authorized_targets list. Add the target to authorized_targets.txt before running offensive operations.
          </AlertDescription>
        </Alert>
      )}

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="grid grid-cols-5 w-full">
          <TabsTrigger value="control" className="flex items-center gap-2">
            <Target className="h-4 w-4" />
            Control Center
          </TabsTrigger>
          <TabsTrigger value="planner" className="flex items-center gap-2">
            <Brain className="h-4 w-4" />
            Planner
          </TabsTrigger>
          <TabsTrigger value="executor" className="flex items-center gap-2">
            <Zap className="h-4 w-4" />
            Executor
          </TabsTrigger>
          <TabsTrigger value="memory" className="flex items-center gap-2">
            <Database className="h-4 w-4" />
            Memory
          </TabsTrigger>
          <TabsTrigger value="report" className="flex items-center gap-2">
            <FileJson className="h-4 w-4" />
            Live Report
          </TabsTrigger>
        </TabsList>

        {/* Control Center Tab */}
        <TabsContent value="control" className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            {/* Session Creation */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Target className="h-5 w-5" />
                  New Session
                </CardTitle>
                <CardDescription>
                  Create a new autonomous attack session
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <label className="text-sm font-medium">Target (IP/Domain/Hardware ID)</label>
                  <Input
                    value={newTarget}
                    onChange={(e) => setNewTarget(e.target.value)}
                    placeholder="192.168.1.100 or target.com"
                  />
                </div>
                
                <div className="space-y-2">
                  <label className="text-sm font-medium">Target Type</label>
                  <select
                    value={targetType}
                    onChange={(e) => setTargetType(e.target.value)}
                    className="w-full p-2 rounded-md border bg-background"
                  >
                    <option value="ip">IP Address</option>
                    <option value="domain">Domain</option>
                    <option value="hardware">Hardware/Firmware</option>
                  </select>
                </div>

                <div className="space-y-2">
                  <label className="text-sm font-medium">Session Name</label>
                  <Input
                    value={sessionName}
                    onChange={(e) => setSessionName(e.target.value)}
                    placeholder="Optional session name"
                  />
                </div>

                <div className="space-y-2">
                  <label className="text-sm font-medium">Authorized Targets (one per line)</label>
                  <Textarea
                    value={authorizedTargets}
                    onChange={(e) => setAuthorizedTargets(e.target.value)}
                    placeholder="192.168.1.100&#10;target.com&#10;10.0.0.0/24"
                    rows={4}
                  />
                  <p className="text-xs text-muted-foreground">
                    Global Scoping Module: Only targets listed here will be allowed
                  </p>
                </div>

                <Button 
                  onClick={createSession} 
                  disabled={isLoading || !newTarget}
                  className="w-full"
                >
                  <Play className="h-4 w-4 mr-2" />
                  Create Session
                </Button>
              </CardContent>
            </Card>

            {/* Previous Sessions */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <GitBranch className="h-5 w-5" />
                  Previous Sessions
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-[300px]">
                  <div className="space-y-2">
                    {sessions.map((session) => (
                      <div
                        key={session.id}
                        className={`p-3 rounded-lg border cursor-pointer transition-colors ${
                          currentSession?.id === session.id 
                            ? 'bg-primary/10 border-primary' 
                            : 'hover:bg-muted'
                        }`}
                        onClick={() => setCurrentSession(session)}
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-medium">{session.session_name}</span>
                          <Badge variant={session.status === 'completed' ? 'default' : 'secondary'}>
                            {session.status}
                          </Badge>
                        </div>
                        <p className="text-sm text-muted-foreground">{session.target}</p>
                        <p className="text-xs text-muted-foreground">
                          {new Date(session.created_at).toLocaleString()}
                        </p>
                      </div>
                    ))}
                    {sessions.length === 0 && (
                      <p className="text-muted-foreground text-center py-8">
                        No sessions yet
                      </p>
                    )}
                  </div>
                </ScrollArea>
              </CardContent>
            </Card>
          </div>

          {/* Terminal Output */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Terminal className="h-5 w-5" />
                Live Output
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[300px] bg-black/90 rounded-lg p-4 font-mono text-sm">
                {output.map((line, i) => (
                  <div key={i} className="text-green-400">{line}</div>
                ))}
                {output.length === 0 && (
                  <div className="text-muted-foreground">
                    Awaiting commands...
                  </div>
                )}
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Planner Tab */}
        <TabsContent value="planner" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Brain className="h-5 w-5" />
                AI Planner - Chain of Thought
              </CardTitle>
              <CardDescription>
                The Planner breaks down high-level goals into atomic tasks using reasoning
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {currentSession ? (
                <>
                  <div className="grid gap-4 md:grid-cols-3">
                    <div className="p-4 rounded-lg bg-muted">
                      <p className="text-sm text-muted-foreground">Target</p>
                      <p className="font-mono font-bold">{currentSession.target}</p>
                    </div>
                    <div className="p-4 rounded-lg bg-muted">
                      <p className="text-sm text-muted-foreground">Phase</p>
                      <p className="font-bold capitalize">{currentSession.current_phase.replace('_', ' ')}</p>
                    </div>
                    <div className="p-4 rounded-lg bg-muted">
                      <p className="text-sm text-muted-foreground">Progress</p>
                      <Progress value={getPhaseProgress()} className="mt-2" />
                    </div>
                  </div>

                  <Button 
                    onClick={planAttack} 
                    disabled={isLoading || !currentSession.authorized}
                    className="w-full"
                  >
                    <Brain className="h-4 w-4 mr-2" />
                    Generate Attack Plan
                  </Button>

                  {tasks.length > 0 && (
                    <div className="space-y-2">
                      <h3 className="font-semibold">Generated Tasks:</h3>
                      {tasks.map((task, i) => (
                        <div key={task.id} className="p-3 rounded-lg border">
                          <div className="flex items-center gap-2">
                            <Badge variant="outline">{task.priority}</Badge>
                            <span className="font-medium">{task.task_name}</span>
                            {getStatusIcon(task.status)}
                          </div>
                          <p className="text-sm text-muted-foreground mt-1">
                            {task.description}
                          </p>
                          <div className="flex items-center gap-2 mt-2">
                            <Badge>{task.tool_selected}</Badge>
                            <Badge variant="secondary">{task.task_type}</Badge>
                          </div>
                          {task.reasoning && (
                            <div className="mt-2 p-2 bg-muted rounded text-xs">
                              <strong>Reasoning:</strong> {task.reasoning}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </>
              ) : (
                <p className="text-muted-foreground text-center py-8">
                  Create a session first to start planning
                </p>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Executor Tab */}
        <TabsContent value="executor" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Zap className="h-5 w-5" />
                Task Executor
              </CardTitle>
              <CardDescription>
                Execute planned tasks with real-time feedback
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {tasks.length > 0 ? (
                <>
                  <Button 
                    onClick={executeAllTasks} 
                    disabled={isLoading || !currentSession?.authorized}
                    className="w-full"
                  >
                    <Play className="h-4 w-4 mr-2" />
                    Execute All Pending Tasks
                  </Button>

                  <div className="space-y-2">
                    {tasks.map((task) => (
                      <div key={task.id} className="p-4 rounded-lg border">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            {getStatusIcon(task.status)}
                            <span className="font-medium">{task.task_name}</span>
                          </div>
                          <div className="flex items-center gap-2">
                            <Badge>{task.tool_selected}</Badge>
                            {task.status === 'pending' && (
                              <Button
                                size="sm"
                                onClick={() => executeTask(task.id)}
                                disabled={isLoading}
                              >
                                <Play className="h-3 w-3" />
                              </Button>
                            )}
                          </div>
                        </div>
                        
                        {task.stdout && (
                          <div className="mt-2 p-2 bg-black/90 rounded font-mono text-xs text-green-400 whitespace-pre-wrap">
                            {task.stdout}
                          </div>
                        )}
                        
                        {task.stderr && (
                          <div className="mt-2 p-2 bg-red-950/50 rounded font-mono text-xs text-red-400">
                            {task.stderr}
                          </div>
                        )}
                        
                        {task.result_analysis && (
                          <div className="mt-2 p-2 bg-muted rounded text-sm">
                            <strong>Analysis:</strong> {task.result_analysis}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </>
              ) : (
                <p className="text-muted-foreground text-center py-8">
                  Generate an attack plan first
                </p>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Memory Tab */}
        <TabsContent value="memory" className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Database className="h-5 w-5" />
                  Short-term Context
                </CardTitle>
                <CardDescription>
                  Session log to prevent infinite loops
                </CardDescription>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-[300px]">
                  <pre className="text-xs font-mono">
                    {JSON.stringify({
                      session_id: currentSession?.id,
                      target: currentSession?.target,
                      phase: currentSession?.current_phase,
                      constraints: currentSession?.constraints,
                      attempted_tasks: tasks.map(t => ({
                        name: t.task_name,
                        tool: t.tool_selected,
                        status: t.status,
                      })),
                    }, null, 2)}
                  </pre>
                </ScrollArea>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Cpu className="h-5 w-5" />
                  Long-term Knowledge Base
                </CardTitle>
                <CardDescription>
                  Successful attack chains stored for future use
                </CardDescription>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-[300px]">
                  <div className="space-y-2">
                    {currentSession?.findings?.map((finding: any, i: number) => (
                      <div key={i} className="p-2 rounded bg-muted text-sm">
                        <pre className="text-xs">{JSON.stringify(finding, null, 2)}</pre>
                      </div>
                    ))}
                    {(!currentSession?.findings || currentSession.findings.length === 0) && (
                      <p className="text-muted-foreground text-center py-4">
                        No findings recorded yet
                      </p>
                    )}
                  </div>
                </ScrollArea>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <RotateCcw className="h-5 w-5" />
                Mutation Log
              </CardTitle>
              <CardDescription>
                Adaptation strategies after blocked attempts
              </CardDescription>
            </CardHeader>
            <CardContent>
              <p className="text-muted-foreground text-center py-4">
                Mutations will appear here when attacks are blocked by WAF/IPS
              </p>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Live Report Tab */}
        <TabsContent value="report" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <FileJson className="h-5 w-5" />
                Real-time Findings Report (JSON Schema)
              </CardTitle>
              <CardDescription>
                Live structured output following the defined schema
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[500px]">
                <pre className="text-sm font-mono bg-muted p-4 rounded-lg">
                  {JSON.stringify({
                    schema_version: "1.0.0",
                    report_type: "apex_sentinel_findings",
                    session: {
                      id: currentSession?.id || null,
                      target: currentSession?.target || null,
                      target_type: currentSession?.target_type || null,
                      status: currentSession?.status || "idle",
                      phase: currentSession?.current_phase || "idle",
                      authorized: currentSession?.authorized || false,
                    },
                    timestamp: new Date().toISOString(),
                    discovery: {
                      services: findingsReport.discovered_services,
                      technologies: currentSession?.target_map?.technologies || [],
                      os_detection: currentSession?.target_map?.os || null,
                    },
                    vulnerabilities: {
                      critical: findingsReport.vulnerabilities.filter((v: any) => v.severity === 'critical'),
                      high: findingsReport.vulnerabilities.filter((v: any) => v.severity === 'high'),
                      medium: findingsReport.vulnerabilities.filter((v: any) => v.severity === 'medium'),
                      low: findingsReport.vulnerabilities.filter((v: any) => v.severity === 'low'),
                      info: findingsReport.vulnerabilities.filter((v: any) => v.severity === 'info' || !v.severity),
                    },
                    exploitation: {
                      attempts: findingsReport.exploitation_attempts,
                      successful: findingsReport.exploitation_attempts.filter((e: any) => e.success),
                      blocked: findingsReport.exploitation_attempts.filter((e: any) => e.blocked),
                    },
                    recommendations: findingsReport.recommendations,
                    risk_assessment: {
                      score: findingsReport.risk_score,
                      level: findingsReport.risk_score > 7 ? "CRITICAL" : 
                             findingsReport.risk_score > 5 ? "HIGH" :
                             findingsReport.risk_score > 3 ? "MEDIUM" : "LOW",
                    },
                    mitre_attack_mapping: {
                      tactics_used: ["TA0043", "TA0007", "TA0001"],
                      techniques_identified: [],
                    },
                    constraints_applied: currentSession?.constraints || [],
                    execution_summary: {
                      total_tasks: tasks.length,
                      completed: tasks.filter(t => t.status === 'success').length,
                      failed: tasks.filter(t => t.status === 'failed').length,
                      blocked: tasks.filter(t => t.status === 'blocked').length,
                      pending: tasks.filter(t => t.status === 'pending').length,
                    },
                  }, null, 2)}
                </pre>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default ApexSentinel;