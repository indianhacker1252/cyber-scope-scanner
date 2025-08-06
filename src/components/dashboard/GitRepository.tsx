import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
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
  Key
} from "lucide-react";
import { useState } from "react";
import { useToast } from "@/hooks/use-toast";

const GitRepository = () => {
  const { toast } = useToast();
  const [repoUrl, setRepoUrl] = useState("");
  const [accessToken, setAccessToken] = useState("");
  const [scanProgress, setScanProgress] = useState(0);
  const [isScanning, setIsScanning] = useState(false);

  const [repositories] = useState([
    {
      id: 1,
      name: "vulnerable-web-app",
      url: "https://github.com/OWASP/WebGoat.git",
      description: "OWASP WebGoat - A deliberately insecure application",
      language: "Java",
      lastScan: "2024-01-15",
      vulnerabilities: 23,
      severity: "high"
    },
    {
      id: 2,
      name: "damn-vulnerable-node",
      url: "https://github.com/appsecco/dvna.git", 
      description: "Damn Vulnerable Node Application",
      language: "JavaScript",
      lastScan: "2024-01-10",
      vulnerabilities: 18,
      severity: "critical"
    },
    {
      id: 3,
      name: "python-security-test",
      url: "https://github.com/we45/DVPython.git",
      description: "Damn Vulnerable Python Web Application",
      language: "Python",
      lastScan: "2024-01-08",
      vulnerabilities: 15,
      severity: "medium"
    }
  ]);

  const vulnerabilityTypes = [
    { type: "SQL Injection", count: 8, severity: "critical" },
    { type: "XSS", count: 12, severity: "high" },
    { type: "CSRF", count: 5, severity: "medium" },
    { type: "Hardcoded Secrets", count: 7, severity: "high" },
    { type: "Weak Cryptography", count: 4, severity: "medium" },
    { type: "Path Traversal", count: 3, severity: "high" }
  ];

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

    toast({
      title: "Repository Clone Started",
      description: `Cloning repository: ${repoUrl}`,
    });

    // Simulate cloning and scanning process
    const interval = setInterval(() => {
      setScanProgress(prev => {
        const newProgress = Math.min(prev + Math.random() * 15, 100);
        if (newProgress >= 100) {
          clearInterval(interval);
          setIsScanning(false);
          toast({
            title: "Repository Scan Complete",
            description: "Security analysis completed successfully",
          });
        }
        return newProgress;
      });
    }, 500);
  };

  const scanRepository = (repoId: number) => {
    const repo = repositories.find(r => r.id === repoId);
    if (repo) {
      toast({
        title: "Repository Scan Started",
        description: `Starting security scan for ${repo.name}`,
      });
    }
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
                          <Button size="sm" variant="outline">
                            <Eye className="h-4 w-4 mr-1" />
                            View Results
                          </Button>
                          <Button size="sm" onClick={() => scanRepository(repo.id)}>
                            <Play className="h-4 w-4 mr-1" />
                            Rescan
                          </Button>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </TabsContent>

            <TabsContent value="vulnerabilities" className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {vulnerabilityTypes.map((vuln, index) => (
                  <Card key={index}>
                    <CardContent className="p-4">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-3">
                          <Bug className="h-5 w-5 text-primary" />
                          <div>
                            <p className="font-medium">{vuln.type}</p>
                            <p className="text-sm text-muted-foreground">{vuln.count} instances found</p>
                          </div>
                        </div>
                        <Badge className={getSeverityColor(vuln.severity)}>
                          {vuln.severity}
                        </Badge>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
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