import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { 
  Smartphone, 
  Shield, 
  Lock, 
  Upload,
  FileCode,
  Wifi,
  Play,
  Eye,
  AlertTriangle,
} from "lucide-react";
import { useState } from "react";
import { useToast } from "@/hooks/use-toast";
import { useKaliTools } from "@/hooks/useKaliTools";

const MobileSecurity = () => {
  const { toast } = useToast();
  const { runNetworkScan } = useKaliTools();
  const [mobileTarget, setMobileTarget] = useState("");

  const owaspMobileTop10 = [
    { id: "M1", name: "Improper Platform Usage", severity: "medium" },
    { id: "M2", name: "Insecure Data Storage", severity: "high" },
    { id: "M3", name: "Insecure Communication", severity: "high" },
    { id: "M4", name: "Insecure Authentication", severity: "critical" },
    { id: "M5", name: "Insufficient Cryptography", severity: "high" },
    { id: "M6", name: "Insecure Authorization", severity: "high" },
    { id: "M7", name: "Client Code Quality", severity: "medium" },
    { id: "M8", name: "Code Tampering", severity: "medium" },
    { id: "M9", name: "Reverse Engineering", severity: "medium" },
    { id: "M10", name: "Extraneous Functionality", severity: "low" }
  ];

  const handleMobileTest = async (testId: string) => {
    if (!mobileTarget) {
      toast({ title: "Error", description: "Enter mobile device IP or package name", variant: "destructive" });
      return;
    }

    await runNetworkScan(mobileTarget, 'comprehensive');
    toast({ title: `OWASP ${testId} Test Started`, description: `Analyzing ${mobileTarget}` });
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
            Real security testing for mobile applications using network analysis
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4 mb-4">
            <div>
              <Label htmlFor="mobile-target">Mobile Device IP / Package Name</Label>
              <Input
                id="mobile-target"
                placeholder="192.168.1.20 or com.example.app"
                value={mobileTarget}
                onChange={(e) => setMobileTarget(e.target.value)}
              />
            </div>
          </div>

          <Tabs defaultValue="static" className="w-full">
            <TabsList className="grid w-full grid-cols-3">
              <TabsTrigger value="static">Static Analysis</TabsTrigger>
              <TabsTrigger value="network">Network Testing</TabsTrigger>
              <TabsTrigger value="owasp">OWASP Mobile</TabsTrigger>
            </TabsList>

            <TabsContent value="static" className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                <Card>
                  <CardContent className="p-4">
                    <div className="flex items-center space-x-2">
                      <FileCode className="h-5 w-5 text-primary" />
                      <div>
                        <p className="font-medium">Code Analysis</p>
                        <p className="text-sm text-muted-foreground">APK/IPA decompilation</p>
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
                        <p className="text-sm text-muted-foreground">AndroidManifest review</p>
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
                        <p className="text-sm text-muted-foreground">Encryption review</p>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>

            <TabsContent value="network" className="space-y-4">
              <Button onClick={() => handleMobileTest("Network")} disabled={!mobileTarget}>
                <Wifi className="h-4 w-4 mr-2" />
                Start Network Analysis
              </Button>
              <div className="text-center p-8">
                <Wifi className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                <p className="text-lg font-medium mb-2">Network Testing</p>
                <p className="text-muted-foreground">
                  API security testing and network communication analysis using real Kali tools
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
                          </div>
                        </div>
                        <Badge className={getSeverityColor(risk.severity)}>
                          {risk.severity}
                        </Badge>
                      </div>
                      
                      <div className="flex justify-end space-x-2">
                        <Button size="sm" onClick={() => handleMobileTest(risk.id)} disabled={!mobileTarget}>
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
