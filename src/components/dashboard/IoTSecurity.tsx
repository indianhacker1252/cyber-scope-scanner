import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { 
  Wifi, 
  Router, 
  Camera, 
  Smartphone,
  Bluetooth,
  Radio,
  Shield,
  AlertTriangle,
  Network,
  Lock,
  Unlock,
  Zap
} from "lucide-react";
import { useState } from "react";
import { useToast } from "@/hooks/use-toast";
import { useKaliTools } from "@/hooks/useKaliTools";

const IoTSecurity = () => {
  const { toast } = useToast();
  const { runNetworkScan, activeSessions } = useKaliTools();
  const [targetIP, setTargetIP] = useState("");

  const iotDeviceTypes = [
    { id: "router", name: "Router/Gateway", icon: Router, vulnerabilities: ["Default credentials", "Firmware vulnerabilities", "Weak encryption"] },
    { id: "camera", name: "IP Cameras", icon: Camera, vulnerabilities: ["Insecure streaming", "Authentication bypass", "Privacy issues"] },
    { id: "smart-home", name: "Smart Home Devices", icon: Smartphone, vulnerabilities: ["Weak pairing", "Command injection", "Privacy leaks"] },
    { id: "industrial", name: "Industrial IoT", icon: Zap, vulnerabilities: ["Unencrypted protocols", "Remote access", "System disruption"] }
  ];

  const communicationProtocols = [
    { name: "WiFi (802.11)", icon: Wifi, secure: false },
    { name: "Bluetooth", icon: Bluetooth, secure: false },
    { name: "Zigbee", icon: Radio, secure: true },
    { name: "Z-Wave", icon: Radio, secure: true },
    { name: "LoRaWAN", icon: Radio, secure: true },
    { name: "Cellular", icon: Smartphone, secure: true }
  ];

  const startIoTScan = async (deviceType: string) => {
    if (!targetIP) {
      toast({ title: "Target Required", description: "Enter IP address or range", variant: "destructive" });
      return;
    }

    await runNetworkScan(targetIP, 'service-detection');
    toast({ title: "IoT Scan Started", description: `Scanning ${deviceType} at ${targetIP}` });
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <Router className="h-5 w-5 mr-2 text-primary" />
            IoT Security Assessment
          </CardTitle>
          <CardDescription>
            Real security testing for IoT devices using Kali Linux tools
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="discovery" className="w-full">
            <TabsList className="grid w-full grid-cols-4">
              <TabsTrigger value="discovery">Discovery</TabsTrigger>
              <TabsTrigger value="devices">Device Testing</TabsTrigger>
              <TabsTrigger value="protocols">Protocols</TabsTrigger>
              <TabsTrigger value="results">Results</TabsTrigger>
            </TabsList>

            <TabsContent value="discovery" className="space-y-4">
              <div className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="target-ip">Target IP Range</Label>
                  <div className="flex space-x-2">
                    <Input
                      id="target-ip"
                      placeholder="192.168.1.0/24 or 10.0.0.1"
                      value={targetIP}
                      onChange={(e) => setTargetIP(e.target.value)}
                    />
                    <Button onClick={() => startIoTScan("discovery")}>
                      <Network className="h-4 w-4 mr-2" />
                      Discover
                    </Button>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  <Card>
                    <CardContent className="p-4">
                      <div className="flex items-center space-x-2">
                        <Network className="h-5 w-5 text-primary" />
                        <div>
                          <p className="font-medium">Network Scanning</p>
                          <p className="text-sm text-muted-foreground">Nmap IoT discovery</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardContent className="p-4">
                      <div className="flex items-center space-x-2">
                        <Wifi className="h-5 w-5 text-primary" />
                        <div>
                          <p className="font-medium">Wireless Analysis</p>
                          <p className="text-sm text-muted-foreground">WiFi security</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardContent className="p-4">
                      <div className="flex items-center space-x-2">
                        <Bluetooth className="h-5 w-5 text-primary" />
                        <div>
                          <p className="font-medium">Bluetooth Discovery</p>
                          <p className="text-sm text-muted-foreground">BLE scanning</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </div>
              </div>
            </TabsContent>

            <TabsContent value="devices" className="space-y-4">
              <div className="grid grid-cols-1 gap-4">
                {iotDeviceTypes.map((device) => (
                  <Card key={device.id}>
                    <CardContent className="p-6">
                      <div className="flex items-center justify-between mb-4">
                        <div className="flex items-center">
                          <device.icon className="h-6 w-6 mr-3 text-primary" />
                          <div>
                            <h3 className="font-semibold">{device.name}</h3>
                          </div>
                        </div>
                      </div>
                      
                      <div className="space-y-3">
                        <div>
                          <p className="text-sm font-medium mb-2">Common Vulnerabilities:</p>
                          <div className="flex flex-wrap gap-2">
                            {device.vulnerabilities.map((vuln, index) => (
                              <Badge key={index} variant="destructive" className="text-xs">
                                {vuln}
                              </Badge>
                            ))}
                          </div>
                        </div>
                        
                        <Button size="sm" onClick={() => startIoTScan(device.id)} disabled={!targetIP}>
                          Test {device.name}
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </TabsContent>

            <TabsContent value="protocols" className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {communicationProtocols.map((protocol, index) => (
                  <Card key={index}>
                    <CardContent className="p-4">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-3">
                          <protocol.icon className="h-5 w-5 text-primary" />
                          <div>
                            <p className="font-medium">{protocol.name}</p>
                            <p className="text-sm text-muted-foreground">
                              {protocol.secure ? "Generally secure" : "Requires assessment"}
                            </p>
                          </div>
                        </div>
                        {protocol.secure ? (
                          <Lock className="h-4 w-4 text-success" />
                        ) : (
                          <Unlock className="h-4 w-4 text-warning" />
                        )}
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </TabsContent>

            <TabsContent value="results" className="space-y-4">
              {activeSessions.length === 0 ? (
                <div className="text-center p-8">
                  <Router className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                  <p className="text-lg font-medium mb-2">No Scan Results</p>
                  <p className="text-muted-foreground">Start an IoT scan to see results</p>
                </div>
              ) : (
                <div className="space-y-4">
                  {activeSessions.map((session) => (
                    <Card key={session.id}>
                      <CardContent className="p-4">
                        <div className="flex items-center justify-between mb-3">
                          <div>
                            <h4 className="font-medium">{session.tool} Scan</h4>
                            <p className="text-sm text-muted-foreground">Target: {session.target}</p>
                          </div>
                          <Badge>{session.findings.length} findings</Badge>
                        </div>
                        <div className="space-y-2">
                          {session.findings.slice(0, 3).map((finding: any, index: number) => (
                            <div key={index} className="flex items-center justify-between p-2 bg-muted/50 rounded">
                              <span className="text-sm">{finding.title || finding.vulnerability}</span>
                              <AlertTriangle className="h-4 w-4 text-destructive" />
                            </div>
                          ))}
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              )}
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
};

export default IoTSecurity;
