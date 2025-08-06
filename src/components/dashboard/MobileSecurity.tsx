import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { 
  Smartphone, 
  Shield, 
  Lock, 
  Upload,
  FileCode,
  Wifi,
  Database,
  Play,
  Eye,
  AlertTriangle,
  CheckCircle
} from "lucide-react";
import { useState } from "react";
import { useToast } from "@/hooks/use-toast";

const MobileSecurity = () => {
  const { toast } = useToast();
  const [uploadedApp, setUploadedApp] = useState<string | null>(null);
  const [analysisResults, setAnalysisResults] = useState<any[]>([]);

  const owaspMobileTop10 = [
    {
      id: "M1",
      name: "Improper Platform Usage",
      description: "Misuse of platform features or failure to use platform security controls",
      severity: "medium",
      status: "pending"
    },
    {
      id: "M2", 
      name: "Insecure Data Storage",
      description: "Insecure data storage on device file systems, SQL databases, or log files",
      severity: "high",
      status: "pending"
    },
    {
      id: "M3",
      name: "Insecure Communication", 
      description: "Poor handshaking, incorrect SSL versions, weak negotiation, cleartext transmission",
      severity: "high",
      status: "pending"
    },
    {
      id: "M4",
      name: "Insecure Authentication",
      description: "Failing to identify the user at all, or identify the user in a weak manner",
      severity: "critical",
      status: "pending"
    },
    {
      id: "M5",
      name: "Insufficient Cryptography",
      description: "Code applies cryptography to sensitive information, but the cryptography is insufficient",
      severity: "high",
      status: "pending"
    },
    {
      id: "M6",
      name: "Insecure Authorization",
      description: "Authorization failures within the mobile application",
      severity: "high", 
      status: "pending"
    },
    {
      id: "M7",
      name: "Client Code Quality",
      description: "Code-level implementation issues within the mobile app",
      severity: "medium",
      status: "pending"
    },
    {
      id: "M8",
      name: "Code Tampering",
      description: "Modification of code through malicious forms of apps",
      severity: "medium",
      status: "pending"
    },
    {
      id: "M9",
      name: "Reverse Engineering",
      description: "Analysis of the final code to extract source code",
      severity: "medium",
      status: "pending"
    },
    {
      id: "M10",
      name: "Extraneous Functionality",
      description: "Hidden backdoor functionality or internal development security controls",
      severity: "low",
      status: "pending"
    }
  ];

  const handleFileUpload = () => {
    setUploadedApp("sample_app.apk");
    toast({
      title: "App Uploaded Successfully",
      description: "Mobile application is ready for security analysis",
    });
  };

  const startMobileTest = (testId: string) => {
    toast({
      title: "Mobile Test Started",
      description: `OWASP Mobile ${testId} security test initiated`,
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
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <Smartphone className="h-5 w-5 mr-2 text-primary" />
            Mobile Application Security
          </CardTitle>
          <CardDescription>
            Comprehensive security testing for mobile applications (iOS & Android)
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="static" className="w-full">
            <TabsList className="grid w-full grid-cols-4">
              <TabsTrigger value="static">Static Analysis</TabsTrigger>
              <TabsTrigger value="dynamic">Dynamic Analysis</TabsTrigger>
              <TabsTrigger value="network">Network Testing</TabsTrigger>
              <TabsTrigger value="owasp">OWASP Mobile</TabsTrigger>
            </TabsList>

            <TabsContent value="static" className="space-y-4">
              <div className="border-2 border-dashed border-border rounded-lg p-8 text-center">
                <Upload className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                <p className="text-lg font-medium mb-2">Upload Mobile Application</p>
                <p className="text-muted-foreground mb-4">
                  Upload APK (Android) or IPA (iOS) files for static analysis
                </p>
                <Button variant="outline" onClick={handleFileUpload}>
                  <Upload className="h-4 w-4 mr-2" />
                  Choose Application File
                </Button>
                {uploadedApp && (
                  <div className="mt-4 p-3 bg-success/10 text-success rounded-lg">
                    <p className="text-sm font-medium">✅ {uploadedApp} uploaded successfully</p>
                  </div>
                )}
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                <Card>
                  <CardContent className="p-4">
                    <div className="flex items-center space-x-2">
                      <FileCode className="h-5 w-5 text-primary" />
                      <div>
                        <p className="font-medium">Code Analysis</p>
                        <p className="text-sm text-muted-foreground">Scan source code for vulnerabilities</p>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                <Card>
                  <CardContent className="p-4">
                    <div className="flex items-center space-x-2">
                      <Shield className="h-5 w-5 text-primary" />
                      <div>
                        <p className="font-medium">Permission Analysis</p>
                        <p className="text-sm text-muted-foreground">Review app permissions</p>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                <Card>
                  <CardContent className="p-4">
                    <div className="flex items-center space-x-2">
                      <Lock className="h-5 w-5 text-primary" />
                      <div>
                        <p className="font-medium">Crypto Analysis</p>
                        <p className="text-sm text-muted-foreground">Encryption implementation review</p>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>

            <TabsContent value="dynamic" className="space-y-4">
              <div className="text-center p-8">
                <Smartphone className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                <p className="text-lg font-medium mb-2">Dynamic Analysis</p>
                <p className="text-muted-foreground">
                  Runtime analysis and behavioral testing of mobile applications
                </p>
              </div>
            </TabsContent>

            <TabsContent value="network" className="space-y-4">
              <div className="text-center p-8">
                <Wifi className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                <p className="text-lg font-medium mb-2">Network Testing</p>
                <p className="text-muted-foreground">
                  API security testing and network communication analysis
                </p>
              </div>
            </TabsContent>

            <TabsContent value="owasp" className="space-y-4">
              <div className="space-y-4">
                {owaspMobileTop10.map((risk) => (
                  <Card key={risk.id}>
                    <CardContent className="p-6">
                      <div className="flex items-center justify-between mb-4">
                        <div className="flex items-center">
                          <Shield className="h-6 w-6 mr-3 text-primary" />
                          <div>
                            <h3 className="font-semibold">{risk.id}: {risk.name}</h3>
                            <p className="text-sm text-muted-foreground">{risk.description}</p>
                          </div>
                        </div>
                        <div className="flex items-center space-x-2">
                          <Badge className={getSeverityColor(risk.severity)}>
                            {risk.severity}
                          </Badge>
                          <Badge variant="outline">{risk.status}</Badge>
                        </div>
                      </div>
                      
                      <div className="flex justify-end space-x-2">
                        <Button size="sm" variant="outline" onClick={() => {
                          toast({
                            title: "Test Details",
                            description: `Viewing details for ${risk.name}`,
                          });
                        }}>
                          <Eye className="h-4 w-4 mr-1" />
                          View Details
                        </Button>
                        <Button size="sm" onClick={() => startMobileTest(risk.id)}>
                          <Play className="h-4 w-4 mr-1" />
                          Start Test
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
};

export default MobileSecurity;