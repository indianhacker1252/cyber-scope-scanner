import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { 
  Wifi, 
  Router, 
  Camera, 
  Smartphone,
  Bluetooth,
  Radio,
  Shield,
  AlertTriangle,
  Play,
  Pause,
  RotateCcw,
  Eye,
  Network,
  Lock,
  Unlock,
  Bug,
  Zap
} from "lucide-react";
import { useState } from "react";
import { useToast } from "@/hooks/use-toast";

const IoTSecurity = () => {
  const { toast } = useToast();
  const [targetIP, setTargetIP] = useState("");
  const [scanResults, setScanResults] = useState<any[]>([]);
  const [activeScans, setActiveScans] = useState<any[]>([]);

  const iotDeviceTypes = [
    {
      id: "router",
      name: "Router/Gateway",
      icon: Router,
      description: "Network routers, gateways, and access points",
      vulnerabilities: ["Default credentials", "Firmware vulnerabilities", "Weak encryption"],
      status: "pending"
    },
    {
      id: "camera",
      name: "IP Cameras",
      icon: Camera,
      description: "Security cameras and surveillance systems",
      vulnerabilities: ["Insecure streaming", "Authentication bypass", "Privacy issues"],
      status: "pending"
    },
    {
      id: "smart-home",
      name: "Smart Home Devices",
      icon: Smartphone,
      description: "Smart thermostats, lights, locks, and appliances",
      vulnerabilities: ["Weak pairing", "Command injection", "Privacy leaks"],
      status: "pending"
    },
    {
      id: "industrial",
      name: "Industrial IoT",
      icon: Zap,
      description: "SCADA systems, PLCs, and industrial controllers",
      vulnerabilities: ["Unencrypted protocols", "Remote access", "System disruption"],
      status: "pending"
    }
  ];

  const communicationProtocols = [
    { name: "WiFi (802.11)", icon: Wifi, secure: false },
    { name: "Bluetooth", icon: Bluetooth, secure: false },
    { name: "Zigbee", icon: Radio, secure: true },
    { name: "Z-Wave", icon: Radio, secure: true },
    { name: "LoRaWAN", icon: Radio, secure: true },
    { name: "Cellular", icon: Smartphone, secure: true }
  ];

  const startIoTScan = (deviceType: string) => {
    if (!targetIP && deviceType !== "discovery") {
      toast({
        title: "Target Required",
        description: "Please enter a target IP address or range",
        variant: "destructive"
      });
      return;
    }

    const newScan = {
      id: Date.now(),
      type: deviceType,
      target: targetIP || "Auto Discovery",
      status: "running",
      progress: 0,
      findings: 0,
      startTime: new Date()
    };

    setActiveScans(prev => [...prev, newScan]);

    // Simulate scan progress
    const interval = setInterval(() => {
      setActiveScans(prev => prev.map(scan => {
        if (scan.id === newScan.id && scan.progress < 100) {
          const newProgress = Math.min(scan.progress + Math.random() * 20, 100);
          if (newProgress >= 100) {
            setScanResults(prevResults => [...prevResults, {
              ...scan,
              status: "completed",
              progress: 100,
              findings: Math.floor(Math.random() * 10) + 1,
              vulnerabilities: iotDeviceTypes.find(d => d.id === deviceType)?.vulnerabilities || []
            }]);
            clearInterval(interval);
          }
          return { ...scan, progress: newProgress };
        }
        return scan;
      }));
    }, 1000);

    toast({
      title: "IoT Scan Started",
      description: `Scanning for ${deviceType} vulnerabilities`,
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
            <Router className="h-5 w-5 mr-2 text-primary" />
            IoT Security Assessment
          </CardTitle>
          <CardDescription>
            Comprehensive security testing for Internet of Things devices and networks
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="discovery" className="w-full">
            <TabsList className="grid w-full grid-cols-5">
              <TabsTrigger value="discovery">Discovery</TabsTrigger>
              <TabsTrigger value="devices">Device Testing</TabsTrigger>
              <TabsTrigger value="protocols">Protocols</TabsTrigger>
              <TabsTrigger value="firmware">Firmware</TabsTrigger>
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
                          <p className="text-sm text-muted-foreground">Discover IoT devices on network</p>
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
                          <p className="text-sm text-muted-foreground">WiFi security assessment</p>
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
                          <p className="text-sm text-muted-foreground">BLE and classic Bluetooth</p>
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
                            <p className="text-sm text-muted-foreground">{device.description}</p>
                          </div>
                        </div>
                        <Badge variant="outline">{device.status}</Badge>
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
                        
                        <div className="flex justify-end space-x-2">
                          <Button size="sm" variant="outline">
                            <Eye className="h-4 w-4 mr-1" />
                            View Details
                          </Button>
                          <Button size="sm" onClick={() => startIoTScan(device.id)}>
                            <Play className="h-4 w-4 mr-1" />
                            Test Device
                          </Button>
                        </div>
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
                              {protocol.secure ? "Generally secure" : "Requires security assessment"}
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

            <TabsContent value="firmware" className="space-y-4">
              <div className="text-center p-8">
                <Bug className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                <p className="text-lg font-medium mb-2">Firmware Analysis</p>
                <p className="text-muted-foreground mb-4">
                  Extract and analyze firmware for security vulnerabilities
                </p>
                <Button variant="outline">
                  <Shield className="h-4 w-4 mr-2" />
                  Upload Firmware
                </Button>
              </div>
            </TabsContent>

            <TabsContent value="results" className="space-y-4">
              {scanResults.length === 0 ? (
                <div className="text-center p-8">
                  <Router className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                  <p className="text-lg font-medium mb-2">No Scan Results</p>
                  <p className="text-muted-foreground">Start an IoT security scan to see results here</p>
                </div>
              ) : (
                <div className="space-y-4">
                  {scanResults.map((result) => (
                    <Card key={result.id}>
                      <CardContent className="p-4">
                        <div className="flex items-center justify-between mb-3">
                          <div>
                            <h4 className="font-medium">{result.type} Scan</h4>
                            <p className="text-sm text-muted-foreground">Target: {result.target}</p>
                          </div>
                          <Badge className={getSeverityColor("high")}>
                            {result.findings} issues found
                          </Badge>
                        </div>
                        <div className="space-y-2">
                          {result.vulnerabilities.map((vuln: string, index: number) => (
                            <div key={index} className="flex items-center justify-between p-2 bg-muted/50 rounded">
                              <span className="text-sm">{vuln}</span>
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