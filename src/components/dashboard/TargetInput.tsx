import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { 
  Globe, 
  Network, 
  Smartphone, 
  Database, 
  Target,
  Play,
  Upload,
  Download,
  Zap
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { useKaliTools } from "@/hooks/useKaliTools";

const TargetInput = () => {
  const [targetUrl, setTargetUrl] = useState("");
  const [targetNetwork, setTargetNetwork] = useState("");
  const [selectedTests, setSelectedTests] = useState<string[]>([]);
  const [multipleTargets, setMultipleTargets] = useState("");
  const [scanIntensity, setScanIntensity] = useState("normal");
  const [threads, setThreads] = useState("5");
  const [timeout, setTimeout] = useState("10");
  const [isScanning, setIsScanning] = useState(false);
  const { toast } = useToast();
  const { 
    isKaliEnvironment, 
    runNetworkScan, 
    runWebScan, 
    runSQLInjectionTest,
    runDirectoryEnum,
    runSubdomainEnum,
    runVulnerabilityScan,
    runAutomatedScan
  } = useKaliTools();

  const vulnerabilityTests = [
    { id: "subdomain-enum", label: "Subdomain Enumeration", category: "reconnaissance" },
    { id: "sql-injection", label: "SQL Injection", category: "web" },
    { id: "xss-testing", label: "XSS Testing", category: "web" },
    { id: "csrf", label: "Cross-Site Request Forgery", category: "web" },
    { id: "directory-traversal", label: "Directory Traversal", category: "web" },
    { id: "file-upload", label: "File Upload Vulnerabilities", category: "web" },
    { id: "broken-auth", label: "Broken Authentication", category: "web" },
    { id: "open-redirect", label: "Open Redirect", category: "web" },
    { id: "ssrf", label: "Server-Side Request Forgery", category: "web" },
    { id: "xxe", label: "XML External Entity", category: "web" },
    { id: "command-injection", label: "Command Injection", category: "web" },
    { id: "host-header", label: "Host Header Poisoning", category: "web" },
    { id: "clickjacking", label: "Clickjacking", category: "web" },
    { id: "prototype-pollution", label: "Prototype Pollution", category: "web" },
    { id: "regex-injection", label: "Regex Injection", category: "web" },
    { id: "port-scan", label: "Port Scanning", category: "network" },
    { id: "service-enum", label: "Service Enumeration", category: "network" },
    { id: "privilege-escalation", label: "Privilege Escalation", category: "network" },
    { id: "dns-poisoning", label: "DNS Poisoning", category: "network" },
    { id: "dos-ddos", label: "DoS/DDoS Testing", category: "network" },
    { id: "weak-encryption", label: "Weak Encryption", category: "network" },
    { id: "mobile-owasp", label: "OWASP Mobile Top 10", category: "mobile" },
    { id: "api-testing", label: "API Security Testing", category: "api" },
    { id: "code-review", label: "Static Code Analysis", category: "code" },
  ];

  const handleTestToggle = (testId: string) => {
    setSelectedTests(prev => 
      prev.includes(testId) 
        ? prev.filter(id => id !== testId)
        : [...prev, testId]
    );
  };

  const handleStartScan = async () => {
    if (!targetUrl && !targetNetwork && !multipleTargets) {
      toast({
        title: "Error",
        description: "Please provide at least one target",
        variant: "destructive"
      });
      return;
    }

    if (selectedTests.length === 0) {
      toast({
        title: "Error", 
        description: "Please select at least one vulnerability test",
        variant: "destructive"
      });
      return;
    }

    setIsScanning(true);
    
    try {
      const targets = getTargetList();
      
      for (const target of targets) {
        for (const testId of selectedTests) {
          await executeTest(testId, target);
        }
      }
      
      toast({
        title: "Scan Completed",
        description: `All ${selectedTests.length} tests completed successfully`,
      });
    } catch (error: any) {
      toast({
        title: "Scan Error",
        description: error.message,
        variant: "destructive"
      });
    } finally {
      setIsScanning(false);
    }
  };

  const getTargetList = (): string[] => {
    const targets = [];
    if (targetUrl) targets.push(targetUrl);
    if (targetNetwork) targets.push(targetNetwork);
    if (multipleTargets) {
      targets.push(...multipleTargets.split('\n').filter(t => t.trim()));
    }
    return targets;
  };

  const executeTest = async (testId: string, target: string) => {
    switch (testId) {
      case 'port-scan':
      case 'service-enum':
        await runNetworkScan(target, scanIntensity);
        break;
      case 'subdomain-enum':
        await runSubdomainEnum(target.replace(/^https?:\/\//, ''));
        break;
      case 'sql-injection':
        await runSQLInjectionTest(target);
        break;
      case 'directory-traversal':
        await runDirectoryEnum(target);
        break;
      case 'xss-testing':
      case 'csrf':
      case 'file-upload':
        await runWebScan(target);
        break;
      case 'code-review':
        await runVulnerabilityScan(target);
        break;
      default:
        console.log(`Test ${testId} not implemented yet`);
    }
  };

  const selectAllByCategory = (category: string) => {
    const categoryTests = vulnerabilityTests
      .filter(test => test.category === category)
      .map(test => test.id);
    
    setSelectedTests(prev => [
      ...prev.filter(id => !categoryTests.includes(id)),
      ...categoryTests
    ]);
  };

  const handleAutomatedScan = async () => {
    if (!targetUrl && !targetNetwork && !multipleTargets) {
      toast({
        title: "Error",
        description: "Please provide at least one target",
        variant: "destructive"
      });
      return;
    }

    setIsScanning(true);
    
    try {
      const targets = getTargetList();
      
      for (const target of targets) {
        // Run comprehensive automated scan using all available tools
        await runAutomatedScan(target);
      }
      
      toast({
        title: "Automated Scan Completed",
        description: `Comprehensive security assessment completed for all targets`,
      });
    } catch (error: any) {
      toast({
        title: "Automated Scan Error",
        description: error.message,
        variant: "destructive"
      });
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <Target className="h-5 w-5 mr-2 text-primary" />
            Target Configuration
          </CardTitle>
          <CardDescription>
            Configure your targets and select vulnerability tests to perform
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="single" className="w-full">
            <TabsList className="grid w-full grid-cols-3">
              <TabsTrigger value="single">Single Target</TabsTrigger>
              <TabsTrigger value="multiple">Multiple Targets</TabsTrigger>
              <TabsTrigger value="file">Upload File</TabsTrigger>
            </TabsList>
            
            <TabsContent value="single" className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="url">Target URL/Domain</Label>
                  <Input
                    id="url"
                    placeholder="https://example.com or example.com"
                    value={targetUrl}
                    onChange={(e) => setTargetUrl(e.target.value)}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="network">Network Range (Optional)</Label>
                  <Input
                    id="network"
                    placeholder="192.168.1.0/24"
                    value={targetNetwork}
                    onChange={(e) => setTargetNetwork(e.target.value)}
                  />
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="multiple" className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="targets">Target List</Label>
                <Textarea
                  id="targets"
                  placeholder="Enter multiple targets, one per line&#10;example.com&#10;test.example.com&#10;192.168.1.1"
                  className="min-h-32"
                  value={multipleTargets}
                  onChange={(e) => setMultipleTargets(e.target.value)}
                />
              </div>
            </TabsContent>
            
            <TabsContent value="file" className="space-y-4">
              <div className="border-2 border-dashed border-border rounded-lg p-8 text-center">
                <Upload className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                <p className="text-lg font-medium mb-2">Upload Target File</p>
                <p className="text-muted-foreground mb-4">
                  Upload a text file containing target URLs, domains, or IP ranges
                </p>
                <Button variant="outline">
                  <Upload className="h-4 w-4 mr-2" />
                  Choose File
                </Button>
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Vulnerability Tests Selection</CardTitle>
          <CardDescription>
            Select the vulnerability tests to perform on your targets
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-6">
            {/* Quick Selection Buttons */}
            <div className="flex flex-wrap gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => selectAllByCategory("web")}
              >
                <Globe className="h-4 w-4 mr-1" />
                All Web Tests
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => selectAllByCategory("network")}
              >
                <Network className="h-4 w-4 mr-1" />
                All Network Tests
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => selectAllByCategory("mobile")}
              >
                <Smartphone className="h-4 w-4 mr-1" />
                Mobile Tests
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setSelectedTests(vulnerabilityTests.map(t => t.id))}
              >
                Select All
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setSelectedTests([])}
              >
                Clear All
              </Button>
            </div>

            {/* Test Categories */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {["web", "network", "mobile", "api", "code"].map(category => (
                <div key={category} className="space-y-3">
                  <h4 className="font-medium text-sm uppercase tracking-wide text-muted-foreground">
                    {category === "web" && "Web Application"}
                    {category === "network" && "Network Security"}
                    {category === "mobile" && "Mobile Security"}
                    {category === "api" && "API Security"}
                    {category === "code" && "Code Analysis"}
                    {category === "reconnaissance" && "Reconnaissance"}
                  </h4>
                  <div className="space-y-2">
                    {vulnerabilityTests
                      .filter(test => test.category === category)
                      .map(test => (
                        <div key={test.id} className="flex items-center space-x-2">
                          <Checkbox
                            id={test.id}
                            checked={selectedTests.includes(test.id)}
                            onCheckedChange={() => handleTestToggle(test.id)}
                          />
                          <Label 
                            htmlFor={test.id}
                            className="text-sm font-normal cursor-pointer"
                          >
                            {test.label}
                          </Label>
                        </div>
                      ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Scan Configuration</CardTitle>
          <CardDescription>Configure scan parameters and output options</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="space-y-2">
              <Label htmlFor="scan-type">Scan Intensity</Label>
              <Select value={scanIntensity} onValueChange={setScanIntensity}>
                <SelectTrigger>
                  <SelectValue placeholder="Select intensity" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="basic">Light (Passive)</SelectItem>
                  <SelectItem value="normal">Normal</SelectItem>
                  <SelectItem value="aggressive">Aggressive</SelectItem>
                  <SelectItem value="stealth">Stealth</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="threads">Concurrent Threads</Label>
              <Select value={threads} onValueChange={setThreads}>
                <SelectTrigger>
                  <SelectValue placeholder="Threads" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="1">1 (Slow)</SelectItem>
                  <SelectItem value="5">5 (Normal)</SelectItem>
                  <SelectItem value="10">10 (Fast)</SelectItem>
                  <SelectItem value="20">20 (Aggressive)</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="timeout">Request Timeout</Label>
              <Select value={timeout} onValueChange={setTimeout}>
                <SelectTrigger>
                  <SelectValue placeholder="Timeout" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="5">5 seconds</SelectItem>
                  <SelectItem value="10">10 seconds</SelectItem>
                  <SelectItem value="30">30 seconds</SelectItem>
                  <SelectItem value="60">60 seconds</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="flex justify-between items-center pt-4">
            <div className="text-sm text-muted-foreground">
              {selectedTests.length} tests selected • Automated scan uses all tools
            </div>
            <div className="space-x-2">
              <Button 
                variant="outline"
                onClick={() => window.location.hash = '#/results'}
              >
                <Database className="h-4 w-4 mr-2" />
                View Results
              </Button>
              <Button variant="outline">
                <Download className="h-4 w-4 mr-2" />
                Save Config
              </Button>
              <Button onClick={handleAutomatedScan} disabled={isScanning} variant="secondary">
                <Zap className="h-4 w-4 mr-2" />
                {isScanning ? 'Running Auto Scan...' : 'Auto Scan'}
              </Button>
              <Button onClick={handleStartScan} disabled={isScanning}>
                <Play className="h-4 w-4 mr-2" />
                {isScanning ? 'Scanning...' : 'Manual Scan'}
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default TargetInput;