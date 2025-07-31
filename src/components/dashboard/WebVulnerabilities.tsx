import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { 
  Database, 
  Code, 
  Shield, 
  AlertTriangle, 
  CheckCircle,
  Play,
  Pause,
  RotateCcw,
  FileText,
  Globe,
  Lock,
  Upload,
  Eye,
  Zap
} from "lucide-react";

const WebVulnerabilities = () => {
  const vulnerabilityTests = [
    {
      id: "sql-injection",
      name: "SQL Injection",
      description: "Test for SQL injection vulnerabilities in input fields and parameters",
      icon: Database,
      status: "pending",
      progress: 0,
      findings: 0,
      severity: "high",
      tools: ["SQLMap", "NoSQLMap", "Custom Payloads"]
    },
    {
      id: "xss",
      name: "Cross-Site Scripting (XSS)",
      description: "Detect reflected, stored, and DOM-based XSS vulnerabilities",
      icon: Code,
      status: "pending",
      progress: 0,
      findings: 0,
      severity: "medium",
      tools: ["XSSHunter", "DOMPurify", "Custom Payloads"]
    },
    {
      id: "csrf",
      name: "Cross-Site Request Forgery",
      description: "Test for CSRF protection mechanisms and token validation",
      icon: Shield,
      status: "pending",
      progress: 0,
      findings: 0,
      severity: "medium",
      tools: ["Burp Suite", "OWASP ZAP", "Custom Scripts"]
    },
    {
      id: "directory-traversal",
      name: "Directory Traversal",
      description: "Check for path traversal vulnerabilities in file operations",
      icon: FileText,
      status: "pending",
      progress: 0,
      findings: 0,
      severity: "high",
      tools: ["DirBuster", "Gobuster", "Custom Wordlists"]
    },
    {
      id: "file-upload",
      name: "File Upload Vulnerabilities",
      description: "Test file upload functionality for security bypass",
      icon: Upload,
      status: "pending",
      progress: 0,
      findings: 0,
      severity: "critical",
      tools: ["Upload Scanner", "File Type Bypass", "WebShell Detection"]
    },
    {
      id: "broken-auth",
      name: "Broken Authentication",
      description: "Test authentication mechanisms and session management",
      icon: Lock,
      status: "pending",
      progress: 0,
      findings: 0,
      severity: "high",
      tools: ["Hydra", "John the Ripper", "Custom Brute Force"]
    },
    {
      id: "ssrf",
      name: "Server-Side Request Forgery",
      description: "Test for SSRF vulnerabilities in server-side requests",
      icon: Globe,
      status: "pending",
      progress: 0,
      findings: 0,
      severity: "high",
      tools: ["SSRFmap", "Gopher Protocol", "Custom Payloads"]
    },
    {
      id: "clickjacking",
      name: "Clickjacking",
      description: "Test for clickjacking protection using X-Frame-Options",
      icon: Eye,
      status: "pending",
      progress: 0,
      findings: 0,
      severity: "low",
      tools: ["Frame Buster", "CSP Analysis", "Manual Testing"]
    }
  ];

  const getStatusColor = (status: string) => {
    switch (status) {
      case "completed": return "text-success";
      case "running": return "text-warning";
      case "pending": return "text-muted-foreground";
      case "failed": return "text-destructive";
      default: return "text-muted-foreground";
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

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "completed": return CheckCircle;
      case "running": return Play;
      case "pending": return Pause;
      case "failed": return AlertTriangle;
      default: return Pause;
    }
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <Globe className="h-5 w-5 mr-2 text-primary" />
            Web Application Security Testing
          </CardTitle>
          <CardDescription>
            Comprehensive vulnerability assessment for web applications
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="overview" className="w-full">
            <TabsList className="grid w-full grid-cols-4">
              <TabsTrigger value="overview">Overview</TabsTrigger>
              <TabsTrigger value="injection">Injection</TabsTrigger>
              <TabsTrigger value="auth">Authentication</TabsTrigger>
              <TabsTrigger value="misc">Miscellaneous</TabsTrigger>
            </TabsList>

            <TabsContent value="overview" className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                {[
                  { label: "Tests Running", value: "0", color: "text-warning" },
                  { label: "Critical Findings", value: "0", color: "text-destructive" },
                  { label: "Completed Tests", value: "0", color: "text-success" },
                  { label: "Total Findings", value: "0", color: "text-primary" }
                ].map((stat, index) => (
                  <Card key={index}>
                    <CardContent className="p-4">
                      <div className="text-center">
                        <p className="text-2xl font-bold">{stat.value}</p>
                        <p className={`text-sm ${stat.color}`}>{stat.label}</p>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {vulnerabilityTests.slice(0, 4).map((test) => {
                  const StatusIcon = getStatusIcon(test.status);
                  return (
                    <Card key={test.id} className="bg-gradient-to-r from-card to-muted/30">
                      <CardContent className="p-4">
                        <div className="flex items-start justify-between mb-3">
                          <div className="flex items-center">
                            <test.icon className="h-5 w-5 mr-2 text-primary" />
                            <h4 className="font-medium">{test.name}</h4>
                          </div>
                          <StatusIcon className={`h-4 w-4 ${getStatusColor(test.status)}`} />
                        </div>
                        <p className="text-sm text-muted-foreground mb-3">{test.description}</p>
                        <div className="space-y-2">
                          <div className="flex justify-between text-sm">
                            <span>Progress</span>
                            <span>{test.progress}%</span>
                          </div>
                          <Progress value={test.progress} className="h-2" />
                        </div>
                        <div className="flex items-center justify-between mt-3">
                          <Badge className={getSeverityColor(test.severity)}>
                            {test.severity.toUpperCase()}
                          </Badge>
                          <span className="text-sm text-muted-foreground">
                            {test.findings} findings
                          </span>
                        </div>
                      </CardContent>
                    </Card>
                  );
                })}
              </div>
            </TabsContent>

            <TabsContent value="injection" className="space-y-4">
              <div className="grid grid-cols-1 gap-4">
                {vulnerabilityTests
                  .filter(test => ["sql-injection", "xss", "ssrf"].includes(test.id))
                  .map((test) => {
                    const StatusIcon = getStatusIcon(test.status);
                    return (
                      <Card key={test.id}>
                        <CardContent className="p-6">
                          <div className="flex items-center justify-between mb-4">
                            <div className="flex items-center">
                              <test.icon className="h-6 w-6 mr-3 text-primary" />
                              <div>
                                <h3 className="font-semibold">{test.name}</h3>
                                <p className="text-sm text-muted-foreground">{test.description}</p>
                              </div>
                            </div>
                            <div className="flex items-center space-x-2">
                              <Badge className={getSeverityColor(test.severity)}>
                                {test.severity}
                              </Badge>
                              <StatusIcon className={`h-5 w-5 ${getStatusColor(test.status)}`} />
                            </div>
                          </div>
                          
                          <div className="space-y-3">
                            <div>
                              <div className="flex justify-between text-sm mb-1">
                                <span>Progress</span>
                                <span>{test.progress}%</span>
                              </div>
                              <Progress value={test.progress} className="h-2" />
                            </div>
                            
                            <div className="flex flex-wrap gap-2">
                              {test.tools.map((tool, index) => (
                                <Badge key={index} variant="outline" className="text-xs">
                                  {tool}
                                </Badge>
                              ))}
                            </div>
                            
                            <div className="flex justify-between items-center">
                              <span className="text-sm text-muted-foreground">
                                {test.findings} vulnerabilities found
                              </span>
                              <div className="space-x-2">
                                <Button size="sm" variant="outline">
                                  <Eye className="h-4 w-4 mr-1" />
                                  View Details
                                </Button>
                                {test.status === "running" ? (
                                  <Button size="sm" variant="outline">
                                    <Pause className="h-4 w-4 mr-1" />
                                    Pause
                                  </Button>
                                ) : test.status === "pending" ? (
                                  <Button size="sm">
                                    <Play className="h-4 w-4 mr-1" />
                                    Start
                                  </Button>
                                ) : (
                                  <Button size="sm" variant="outline">
                                    <RotateCcw className="h-4 w-4 mr-1" />
                                    Rerun
                                  </Button>
                                )}
                              </div>
                            </div>
                          </div>
                        </CardContent>
                      </Card>
                    );
                  })}
              </div>
            </TabsContent>

            <TabsContent value="auth" className="space-y-4">
              <div className="grid grid-cols-1 gap-4">
                {vulnerabilityTests
                  .filter(test => ["broken-auth", "csrf"].includes(test.id))
                  .map((test) => {
                    const StatusIcon = getStatusIcon(test.status);
                    return (
                      <Card key={test.id}>
                        <CardContent className="p-6">
                          <div className="flex items-center justify-between mb-4">
                            <div className="flex items-center">
                              <test.icon className="h-6 w-6 mr-3 text-primary" />
                              <div>
                                <h3 className="font-semibold">{test.name}</h3>
                                <p className="text-sm text-muted-foreground">{test.description}</p>
                              </div>
                            </div>
                            <div className="flex items-center space-x-2">
                              <Badge className={getSeverityColor(test.severity)}>
                                {test.severity}
                              </Badge>
                              <StatusIcon className={`h-5 w-5 ${getStatusColor(test.status)}`} />
                            </div>
                          </div>
                          
                          <div className="space-y-3">
                            <div>
                              <div className="flex justify-between text-sm mb-1">
                                <span>Progress</span>
                                <span>{test.progress}%</span>
                              </div>
                              <Progress value={test.progress} className="h-2" />
                            </div>
                            
                            <div className="flex flex-wrap gap-2">
                              {test.tools.map((tool, index) => (
                                <Badge key={index} variant="outline" className="text-xs">
                                  {tool}
                                </Badge>
                              ))}
                            </div>
                            
                            <div className="flex justify-between items-center">
                              <span className="text-sm text-muted-foreground">
                                {test.findings} vulnerabilities found
                              </span>
                              <div className="space-x-2">
                                <Button size="sm" variant="outline">
                                  <Eye className="h-4 w-4 mr-1" />
                                  View Details
                                </Button>
                                {test.status === "running" ? (
                                  <Button size="sm" variant="outline">
                                    <Pause className="h-4 w-4 mr-1" />
                                    Pause
                                  </Button>
                                ) : test.status === "pending" ? (
                                  <Button size="sm">
                                    <Play className="h-4 w-4 mr-1" />
                                    Start
                                  </Button>
                                ) : (
                                  <Button size="sm" variant="outline">
                                    <RotateCcw className="h-4 w-4 mr-1" />
                                    Rerun
                                  </Button>
                                )}
                              </div>
                            </div>
                          </div>
                        </CardContent>
                      </Card>
                    );
                  })}
              </div>
            </TabsContent>

            <TabsContent value="misc" className="space-y-4">
              <div className="grid grid-cols-1 gap-4">
                {vulnerabilityTests
                  .filter(test => ["directory-traversal", "file-upload", "clickjacking"].includes(test.id))
                  .map((test) => {
                    const StatusIcon = getStatusIcon(test.status);
                    return (
                      <Card key={test.id}>
                        <CardContent className="p-6">
                          <div className="flex items-center justify-between mb-4">
                            <div className="flex items-center">
                              <test.icon className="h-6 w-6 mr-3 text-primary" />
                              <div>
                                <h3 className="font-semibold">{test.name}</h3>
                                <p className="text-sm text-muted-foreground">{test.description}</p>
                              </div>
                            </div>
                            <div className="flex items-center space-x-2">
                              <Badge className={getSeverityColor(test.severity)}>
                                {test.severity}
                              </Badge>
                              <StatusIcon className={`h-5 w-5 ${getStatusColor(test.status)}`} />
                            </div>
                          </div>
                          
                          <div className="space-y-3">
                            <div>
                              <div className="flex justify-between text-sm mb-1">
                                <span>Progress</span>
                                <span>{test.progress}%</span>
                              </div>
                              <Progress value={test.progress} className="h-2" />
                            </div>
                            
                            <div className="flex flex-wrap gap-2">
                              {test.tools.map((tool, index) => (
                                <Badge key={index} variant="outline" className="text-xs">
                                  {tool}
                                </Badge>
                              ))}
                            </div>
                            
                            <div className="flex justify-between items-center">
                              <span className="text-sm text-muted-foreground">
                                {test.findings} vulnerabilities found
                              </span>
                              <div className="space-x-2">
                                <Button size="sm" variant="outline">
                                  <Eye className="h-4 w-4 mr-1" />
                                  View Details
                                </Button>
                                {test.status === "running" ? (
                                  <Button size="sm" variant="outline">
                                    <Pause className="h-4 w-4 mr-1" />
                                    Pause
                                  </Button>
                                ) : test.status === "pending" ? (
                                  <Button size="sm">
                                    <Play className="h-4 w-4 mr-1" />
                                    Start
                                  </Button>
                                ) : (
                                  <Button size="sm" variant="outline">
                                    <RotateCcw className="h-4 w-4 mr-1" />
                                    Rerun
                                  </Button>
                                )}
                              </div>
                            </div>
                          </div>
                        </CardContent>
                      </Card>
                    );
                  })}
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
};

export default WebVulnerabilities;