import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { ScrollArea } from "@/components/ui/scroll-area";
import { 
  GitBranch, 
  Github,
  GitCommit,
  Code,
  Shield,
  AlertTriangle,
  CheckCircle,
  Play,
  Download,
  Eye,
  Bug,
  Lock,
  Key,
  Loader2,
  Trash2
} from "lucide-react";
import { useState, useEffect } from "react";
import { useToast } from "@/hooks/use-toast";
import { RealKaliToolsManager } from "@/utils/realKaliTools";
import { supabase } from "@/integrations/supabase/client";

interface Repository {
  id: string;
  name: string;
  url: string;
  description: string;
  language: string;
  lastScan: string;
  vulnerabilities: number;
  severity: string;
  scanOutput?: string;
  findings?: any[];
}

const GitRepository = () => {
  const { toast } = useToast();
  const toolsManager = RealKaliToolsManager.getInstance();
  const [repoUrl, setRepoUrl] = useState("");
  const [accessToken, setAccessToken] = useState("");
  const [scanProgress, setScanProgress] = useState(0);
  const [isScanning, setIsScanning] = useState(false);
  const [repositories, setRepositories] = useState<Repository[]>([]);
  const [scanOutput, setScanOutput] = useState("");
  const [selectedRepo, setSelectedRepo] = useState<Repository | null>(null);

  // Load repositories from localStorage
  useEffect(() => {
    const stored = localStorage.getItem('git_repositories');
    if (stored) {
      try {
        setRepositories(JSON.parse(stored));
      } catch (e) {
        setRepositories([]);
      }
    }
  }, []);

  // Save repositories to localStorage
  useEffect(() => {
    if (repositories.length > 0) {
      localStorage.setItem('git_repositories', JSON.stringify(repositories));
    }
  }, [repositories]);

  const cloneRepository = async () => {
    if (!repoUrl) {
      toast({
        title: "Repository URL Required",
        description: "Please enter a valid Git repository URL",
        variant: "destructive"
      });
      return;
    }

    setIsScanning(true);
    setScanProgress(0);
    setScanOutput("");

    toast({
      title: "Repository Clone Started",
      description: `Cloning and scanning: ${repoUrl}`,
    });

    try {
      // Extract repo name from URL
      const repoName = repoUrl.split('/').pop()?.replace('.git', '') || 'unknown';
      
      setScanProgress(10);
      setScanOutput(prev => prev + `[INFO] Cloning repository: ${repoUrl}\n`);

      // Run gitleaks for secret detection
      setScanProgress(30);
      setScanOutput(prev => prev + `[INFO] Running Gitleaks secret detection...\n`);
      
      const gitleaksResult = await toolsManager.runGitleaks(repoUrl, {
        onOutput: (data) => {
          setScanOutput(prev => prev + data);
        },
        onProgress: (progress) => {
          setScanProgress(30 + progress * 0.4);
        }
      });

      setScanProgress(70);
      setScanOutput(prev => prev + `[INFO] Running static code analysis...\n`);

      // Parse findings
      const findings = gitleaksResult?.findings || [];
      const vulnCount = findings.length;
      const severity = vulnCount > 10 ? 'critical' : vulnCount > 5 ? 'high' : vulnCount > 0 ? 'medium' : 'low';

      setScanProgress(100);

      // Add to repositories list
      const newRepo: Repository = {
        id: `repo_${Date.now()}`,
        name: repoName,
        url: repoUrl,
        description: `Scanned repository`,
        language: 'Unknown',
        lastScan: new Date().toISOString().split('T')[0],
        vulnerabilities: vulnCount,
        severity,
        scanOutput: gitleaksResult?.output || '',
        findings
      };

      setRepositories(prev => [newRepo, ...prev]);
      setRepoUrl("");

      toast({
        title: "Repository Scan Complete",
        description: `Found ${vulnCount} potential security issues`,
      });

    } catch (error: any) {
      setScanOutput(prev => prev + `[ERROR] ${error.message}\n`);
      toast({
        title: "Scan Failed",
        description: error.message,
        variant: "destructive"
      });
    } finally {
      setIsScanning(false);
    }
  };

  const scanRepository = async (repo: Repository) => {
    setSelectedRepo(repo);
    setIsScanning(true);
    setScanOutput("");

    try {
      toast({
        title: "Rescanning Repository",
        description: `Starting security scan for ${repo.name}`,
      });

      const result = await toolsManager.runGitleaks(repo.url, {
        onOutput: (data) => {
          setScanOutput(prev => prev + data);
        }
      });

      const findings = result?.findings || [];
      const updatedRepo = {
        ...repo,
        lastScan: new Date().toISOString().split('T')[0],
        vulnerabilities: findings.length,
        severity: findings.length > 10 ? 'critical' : findings.length > 5 ? 'high' : findings.length > 0 ? 'medium' : 'low',
        scanOutput: result?.output || '',
        findings
      };

      setRepositories(prev => prev.map(r => r.id === repo.id ? updatedRepo : r));
      setSelectedRepo(updatedRepo);

      toast({
        title: "Rescan Complete",
        description: `Found ${findings.length} potential issues`,
      });

    } catch (error: any) {
      toast({
        title: "Rescan Failed",
        description: error.message,
        variant: "destructive"
      });
    } finally {
      setIsScanning(false);
    }
  };

  const removeRepository = (repoId: string) => {
    setRepositories(prev => prev.filter(r => r.id !== repoId));
    toast({
      title: "Repository Removed",
      description: "Repository has been removed from the list"
    });
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical": return "bg-destructive/20 text-destructive";
      case "high": return "bg-destructive/10 text-destructive"; 
      case "medium": return "bg-warning/20 text-warning";
      case "low": return "bg-success/20 text-success";
      default: return "bg-muted text-muted-foreground";
    }
  };

  const getLanguageColor = (language: string) => {
    switch (language) {
      case "JavaScript": return "bg-yellow-500/20 text-yellow-700";
      case "Python": return "bg-blue-500/20 text-blue-700";
      case "Java": return "bg-orange-500/20 text-orange-700";
      case "PHP": return "bg-purple-500/20 text-purple-700";
      default: return "bg-muted text-muted-foreground";
    }
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <GitBranch className="h-5 w-5 mr-2 text-primary" />
            Git Repository Security Testing
          </CardTitle>
          <CardDescription>
            Clone and analyze Git repositories for security vulnerabilities in source code
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="clone" className="w-full">
            <TabsList className="grid w-full grid-cols-4">
              <TabsTrigger value="clone">Clone Repository</TabsTrigger>
              <TabsTrigger value="repositories">Repositories</TabsTrigger>
              <TabsTrigger value="vulnerabilities">Vulnerabilities</TabsTrigger>
              <TabsTrigger value="reports">Reports</TabsTrigger>
            </TabsList>

            <TabsContent value="clone" className="space-y-4">
              <Card className="bg-muted/30">
                <CardHeader>
                  <CardTitle className="text-lg flex items-center">
                    <Github className="h-5 w-5 mr-2" />
                    Clone New Repository
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="repo-url">Repository URL</Label>
                    <Input
                      id="repo-url"
                      placeholder="https://github.com/username/repository.git"
                      value={repoUrl}
                      onChange={(e) => setRepoUrl(e.target.value)}
                    />
                  </div>
                  
                  <div className="space-y-2">
                    <Label htmlFor="access-token">Access Token (Optional)</Label>
                    <Input
                      id="access-token"
                      type="password"
                      placeholder="ghp_xxxxxxxxxxxxxxxxxxxx"
                      value={accessToken}
                      onChange={(e) => setAccessToken(e.target.value)}
                    />
                    <p className="text-xs text-muted-foreground">
                      Required for private repositories or to avoid rate limits
                    </p>
                  </div>

                  {isScanning && (
                    <div className="space-y-2">
                      <div className="flex justify-between text-sm">
                        <span>Cloning and analyzing...</span>
                        <span>{Math.round(scanProgress)}%</span>
                      </div>
                      <Progress value={scanProgress} className="h-2" />
                    </div>
                  )}

                  <Button onClick={cloneRepository} disabled={isScanning}>
                    <Download className="h-4 w-4 mr-2" />
                    {isScanning ? "Scanning..." : "Clone & Scan"}
                  </Button>
                </CardContent>
              </Card>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                <Card>
                  <CardContent className="p-4">
                    <div className="flex items-center space-x-2">
                      <Code className="h-5 w-5 text-primary" />
                      <div>
                        <p className="font-medium">Static Analysis</p>
                        <p className="text-sm text-muted-foreground">Source code vulnerability scanning</p>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                <Card>
                  <CardContent className="p-4">
                    <div className="flex items-center space-x-2">
                      <Key className="h-5 w-5 text-primary" />
                      <div>
                        <p className="font-medium">Secret Detection</p>
                        <p className="text-sm text-muted-foreground">API keys, passwords, tokens</p>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                <Card>
                  <CardContent className="p-4">
                    <div className="flex items-center space-x-2">
                      <Shield className="h-5 w-5 text-primary" />
                      <div>
                        <p className="font-medium">Dependency Check</p>
                        <p className="text-sm text-muted-foreground">Known vulnerable libraries</p>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>

            <TabsContent value="repositories" className="space-y-4">
              <div className="space-y-4">
                {repositories.map((repo) => (
                  <Card key={repo.id}>
                    <CardContent className="p-6">
                      <div className="flex items-center justify-between mb-4">
                        <div className="flex items-center space-x-3">
                          <GitBranch className="h-6 w-6 text-primary" />
                          <div>
                            <h3 className="font-semibold">{repo.name}</h3>
                            <p className="text-sm text-muted-foreground">{repo.description}</p>
                            <p className="text-xs text-muted-foreground mt-1">{repo.url}</p>
                          </div>
                        </div>
                        <div className="flex items-center space-x-2">
                          <Badge className={getLanguageColor(repo.language)} variant="secondary">
                            {repo.language}
                          </Badge>
                          <Badge className={getSeverityColor(repo.severity)}>
                            {repo.vulnerabilities} issues
                          </Badge>
                        </div>
                      </div>
                      
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-muted-foreground">
                          Last scan: {repo.lastScan}
                        </span>
                        <div className="space-x-2">
                          <Button size="sm" variant="outline" onClick={() => setSelectedRepo(repo)}>
                            <Eye className="h-4 w-4 mr-1" />
                            View Results
                          </Button>
                          <Button size="sm" onClick={() => scanRepository(repo)} disabled={isScanning}>
                            {isScanning && selectedRepo?.id === repo.id ? (
                              <Loader2 className="h-4 w-4 mr-1 animate-spin" />
                            ) : (
                              <Play className="h-4 w-4 mr-1" />
                            )}
                            Rescan
                          </Button>
                          <Button size="sm" variant="outline" onClick={() => removeRepository(repo.id)}>
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </TabsContent>

            <TabsContent value="vulnerabilities" className="space-y-4">
              {repositories.length === 0 ? (
                <Card>
                  <CardContent className="p-8 text-center">
                    <Bug className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                    <p className="text-lg font-medium mb-2">No Vulnerabilities</p>
                    <p className="text-muted-foreground">Clone and scan repositories to find vulnerabilities</p>
                  </CardContent>
                </Card>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {repositories.flatMap(repo => 
                    (repo.findings || []).map((finding: any, idx: number) => (
                      <Card key={`${repo.id}-${idx}`}>
                        <CardContent className="p-4">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center space-x-3">
                              <Bug className="h-5 w-5 text-primary" />
                              <div>
                                <p className="font-medium">{finding.type || finding.rule || 'Secret Found'}</p>
                                <p className="text-sm text-muted-foreground">{repo.name}</p>
                              </div>
                            </div>
                            <Badge className={getSeverityColor(finding.severity || 'high')}>
                              {finding.severity || 'high'}
                            </Badge>
                          </div>
                        </CardContent>
                      </Card>
                    ))
                  )}
                  {repositories.every(r => !r.findings?.length) && (
                    <Card className="col-span-2">
                      <CardContent className="p-8 text-center">
                        <CheckCircle className="h-12 w-12 mx-auto mb-4 text-green-500" />
                        <p className="text-lg font-medium mb-2">No Secrets Found</p>
                        <p className="text-muted-foreground">All scanned repositories appear clean</p>
                      </CardContent>
                    </Card>
                  )}
                </div>
              )}
            </TabsContent>

            <TabsContent value="reports" className="space-y-4">
              <div className="text-center p-8">
                <GitCommit className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                <p className="text-lg font-medium mb-2">Security Reports</p>
                <p className="text-muted-foreground mb-4">
                  Generate comprehensive security reports for your repositories
                </p>
                <Button>
                  <Download className="h-4 w-4 mr-2" />
                  Generate Report
                </Button>
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
};

export default GitRepository;