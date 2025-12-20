import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Progress } from "@/components/ui/progress";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";
import { supabase } from "@/integrations/supabase/client";
import { 
  Zap, 
  Cloud, 
  Database, 
  Bug,
  Shield,
  Server,
  Lock,
  Loader2,
  CheckCircle,
  XCircle,
  Play,
  AlertTriangle,
  Key,
  Globe
} from "lucide-react";

interface TestResult {
  id: string;
  type: string;
  status: 'running' | 'completed' | 'failed';
  output: string;
  findings: any[];
  severity?: string;
}

const SecurityTestingHub = () => {
  const { toast } = useToast();
  const [activeTab, setActiveTab] = useState("api");
  const [target, setTarget] = useState("");
  const [apiEndpoint, setApiEndpoint] = useState("");
  const [isRunning, setIsRunning] = useState(false);
  const [testResults, setTestResults] = useState<TestResult[]>([]);
  const [output, setOutput] = useState("");

  // API Security Tests
  const apiTests = [
    { id: "graphql", name: "GraphQL Introspection", description: "Discover GraphQL schema and sensitive fields" },
    { id: "rest-fuzz", name: "REST Fuzzing", description: "Fuzz REST endpoints for vulnerabilities" },
    { id: "auth-bypass", name: "Auth Bypass", description: "Test authentication bypass vectors" },
    { id: "rate-limit", name: "Rate Limit Test", description: "Check rate limiting implementation" },
    { id: "jwt-test", name: "JWT Analysis", description: "Analyze JWT token security" },
    { id: "cors-test", name: "CORS Misconfiguration", description: "Test CORS policies" },
  ];

  // Cloud Security Tests
  const cloudTests = [
    { id: "s3-enum", name: "S3 Bucket Enum", description: "Find exposed S3 buckets" },
    { id: "azure-enum", name: "Azure Blob Enum", description: "Find exposed Azure blobs" },
    { id: "gcp-enum", name: "GCP Bucket Enum", description: "Find exposed GCP buckets" },
    { id: "iam-analysis", name: "IAM Policy Analysis", description: "Analyze IAM misconfigurations" },
    { id: "lambda-test", name: "Serverless Test", description: "Test serverless functions" },
    { id: "metadata", name: "Cloud Metadata", description: "Check for metadata exposure" },
  ];

  // Database Tests
  const dbTests = [
    { id: "sqli-basic", name: "SQL Injection", description: "Basic SQLi detection" },
    { id: "sqli-blind", name: "Blind SQLi", description: "Time-based blind injection" },
    { id: "nosql-inject", name: "NoSQL Injection", description: "MongoDB/NoSQL injection" },
    { id: "db-enum", name: "Database Enum", description: "Enumerate database structure" },
    { id: "privesc", name: "DB Privilege Escalation", description: "Check for privilege escalation" },
    { id: "data-exfil", name: "Data Exfiltration", description: "Test data extraction" },
  ];

  // Exploit Tests
  const exploitTests = [
    { id: "cve-scan", name: "CVE Scanner", description: "Scan for known CVEs" },
    { id: "exploit-db", name: "Exploit-DB Search", description: "Search for public exploits" },
    { id: "metasploit", name: "Metasploit Check", description: "Check Metasploit modules" },
    { id: "rce-test", name: "RCE Detection", description: "Remote code execution tests" },
    { id: "lpe-test", name: "LPE Detection", description: "Local privilege escalation" },
    { id: "post-exploit", name: "Post-Exploitation", description: "Post-exploitation checks" },
  ];

  const runTest = async (testId: string, testName: string, category: string) => {
    if (!target && !apiEndpoint) {
      toast({ title: "Error", description: "Please enter a target", variant: "destructive" });
      return;
    }

    setIsRunning(true);
    setOutput(`Starting ${testName}...\nTarget: ${target || apiEndpoint}\n\n`);

    const newResult: TestResult = {
      id: crypto.randomUUID(),
      type: testName,
      status: 'running',
      output: '',
      findings: []
    };
    setTestResults(prev => [newResult, ...prev]);

    try {
      const { data, error } = await supabase.functions.invoke('security-scan', {
        body: { 
          target: target || apiEndpoint, 
          scanType: testId,
          category,
          options: {}
        }
      });

      if (error) throw error;

      const scanOutput = data.output || data.results || JSON.stringify(data, null, 2);
      const findings = data.findings || data.vulnerabilities || [];

      setOutput(prev => prev + scanOutput + `\n\n✅ ${testName} completed successfully.`);
      
      setScanResult(newResult.id, {
        status: 'completed',
        output: scanOutput,
        findings,
        severity: findings.length > 0 ? 'high' : 'info'
      });

      toast({ 
        title: `${testName} Complete`, 
        description: `Found ${findings.length} issues` 
      });
    } catch (error: any) {
      setOutput(prev => prev + `\n❌ Error: ${error.message}`);
      
      setScanResult(newResult.id, {
        status: 'failed',
        output: error.message
      });

      toast({ title: "Test Failed", description: error.message, variant: "destructive" });
    } finally {
      setIsRunning(false);
    }
  };

  const setScanResult = (id: string, updates: Partial<TestResult>) => {
    setTestResults(prev => prev.map(r => 
      r.id === id ? { ...r, ...updates } : r
    ));
  };

  const TestCard = ({ test, category }: { test: any; category: string }) => (
    <Card 
      className={`cursor-pointer hover:bg-muted/50 transition-colors ${isRunning ? 'opacity-50' : ''}`}
      onClick={() => !isRunning && runTest(test.id, test.name, category)}
    >
      <CardContent className="p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            {isRunning ? (
              <Loader2 className="h-5 w-5 text-primary animate-spin" />
            ) : (
              <Play className="h-5 w-5 text-primary" />
            )}
            <div>
              <p className="font-medium">{test.name}</p>
              <p className="text-sm text-muted-foreground">{test.description}</p>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );

  return (
    <div className="space-y-6">
      <Card className="border-primary/20 bg-gradient-to-br from-background to-primary/5">
        <CardHeader>
          <div className="flex items-center gap-2">
            <Shield className="h-6 w-6 text-primary" />
            <CardTitle>Security Testing Hub</CardTitle>
          </div>
          <CardDescription>
            Advanced security testing for APIs, cloud infrastructure, databases, and exploit detection
          </CardDescription>
        </CardHeader>
        <CardContent>
          {/* Target Input */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
            <div className="space-y-2">
              <Label>Target URL/Domain</Label>
              <Input
                placeholder="example.com or https://api.example.com"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label>API Endpoint (Optional)</Label>
              <Input
                placeholder="https://api.example.com/graphql"
                value={apiEndpoint}
                onChange={(e) => setApiEndpoint(e.target.value)}
              />
            </div>
          </div>

          <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
            <TabsList className="grid w-full grid-cols-5">
              <TabsTrigger value="api" className="flex items-center gap-1">
                <Zap className="h-4 w-4" />
                API
              </TabsTrigger>
              <TabsTrigger value="cloud" className="flex items-center gap-1">
                <Cloud className="h-4 w-4" />
                Cloud
              </TabsTrigger>
              <TabsTrigger value="database" className="flex items-center gap-1">
                <Database className="h-4 w-4" />
                Database
              </TabsTrigger>
              <TabsTrigger value="exploits" className="flex items-center gap-1">
                <Bug className="h-4 w-4" />
                Exploits
              </TabsTrigger>
              <TabsTrigger value="output" className="flex items-center gap-1">
                <AlertTriangle className="h-4 w-4" />
                Output
              </TabsTrigger>
            </TabsList>

            {/* API Security Tab */}
            <TabsContent value="api" className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {apiTests.map(test => (
                  <TestCard key={test.id} test={test} category="api" />
                ))}
              </div>
            </TabsContent>

            {/* Cloud Security Tab */}
            <TabsContent value="cloud" className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {cloudTests.map(test => (
                  <TestCard key={test.id} test={test} category="cloud" />
                ))}
              </div>
            </TabsContent>

            {/* Database Tab */}
            <TabsContent value="database" className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {dbTests.map(test => (
                  <TestCard key={test.id} test={test} category="database" />
                ))}
              </div>
            </TabsContent>

            {/* Exploits Tab */}
            <TabsContent value="exploits" className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {exploitTests.map(test => (
                  <TestCard key={test.id} test={test} category="exploit" />
                ))}
              </div>
            </TabsContent>

            {/* Output Tab */}
            <TabsContent value="output" className="space-y-4">
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">Test Output</CardTitle>
                </CardHeader>
                <CardContent>
                  <ScrollArea className="h-[300px] border rounded-lg p-4 bg-muted/30 font-mono text-sm">
                    <pre className="whitespace-pre-wrap">
                      {output || 'No test output yet. Run a test to see results here.'}
                    </pre>
                  </ScrollArea>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">Test Results</CardTitle>
                </CardHeader>
                <CardContent>
                  {testResults.length === 0 ? (
                    <div className="text-center py-8 text-muted-foreground">
                      <Shield className="h-12 w-12 mx-auto mb-4 opacity-50" />
                      <p>No tests run yet. Select a test from the tabs above.</p>
                    </div>
                  ) : (
                    <ScrollArea className="h-[300px]">
                      <div className="space-y-2">
                        {testResults.map((result) => (
                          <Card key={result.id} className={`p-3 ${
                            result.status === 'completed' ? 'border-green-500/50' :
                            result.status === 'failed' ? 'border-red-500/50' : 'border-yellow-500/50'
                          }`}>
                            <div className="flex items-center justify-between">
                              <div className="flex items-center gap-2">
                                {result.status === 'completed' && <CheckCircle className="h-4 w-4 text-green-500" />}
                                {result.status === 'failed' && <XCircle className="h-4 w-4 text-red-500" />}
                                {result.status === 'running' && <Loader2 className="h-4 w-4 text-yellow-500 animate-spin" />}
                                <span className="font-medium">{result.type}</span>
                                {result.severity && (
                                  <Badge variant={result.severity === 'high' ? 'destructive' : 'secondary'}>
                                    {result.severity}
                                  </Badge>
                                )}
                              </div>
                              {result.findings.length > 0 && (
                                <Badge variant="outline">{result.findings.length} findings</Badge>
                              )}
                            </div>
                          </Card>
                        ))}
                      </div>
                    </ScrollArea>
                  )}
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
};

export default SecurityTestingHub;
