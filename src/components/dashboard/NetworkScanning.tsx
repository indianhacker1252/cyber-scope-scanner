import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { 
  Network, 
  Wifi, 
  Shield, 
  Zap,
  Router,
  Server,
  Lock
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { useState } from "react";

const NetworkScanning = () => {
  const [targetRange, setTargetRange] = useState("");
  const { toast } = useToast();

  const handleNetworkScan = () => {
    if (!targetRange) {
      toast({
        title: "Error",
        description: "Please enter a network range to scan",
        variant: "destructive"
      });
      return;
    }

    toast({
      title: "Network Scan Started",
      description: `Scanning network range: ${targetRange}`,
    });
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <Network className="h-5 w-5 mr-2 text-primary" />
            Network Security Scanning
          </CardTitle>
          <CardDescription>
            Comprehensive network infrastructure assessment and vulnerability scanning
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="discovery" className="w-full">
            <TabsList className="grid w-full grid-cols-4">
              <TabsTrigger value="discovery">Discovery</TabsTrigger>
              <TabsTrigger value="ports">Port Scanning</TabsTrigger>
              <TabsTrigger value="services">Services</TabsTrigger>
              <TabsTrigger value="vulnerabilities">Vulnerabilities</TabsTrigger>
            </TabsList>

            <TabsContent value="discovery" className="space-y-4">
              <div className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="network-range">Network Range</Label>
                    <Input
                      id="network-range"
                      placeholder="192.168.1.0/24 or 10.0.0.1-254"
                      value={targetRange}
                      onChange={(e) => setTargetRange(e.target.value)}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="scan-type">Scan Type</Label>
                    <Select>
                      <SelectTrigger>
                        <SelectValue placeholder="Select scan type" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="ping">Ping Sweep</SelectItem>
                        <SelectItem value="arp">ARP Discovery</SelectItem>
                        <SelectItem value="tcp">TCP SYN Discovery</SelectItem>
                        <SelectItem value="udp">UDP Discovery</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>

                <Button onClick={handleNetworkScan} className="w-full md:w-auto">
                  <Network className="h-4 w-4 mr-2" />
                  Start Network Discovery
                </Button>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <Card>
                    <CardContent className="p-4">
                      <div className="flex items-center space-x-2">
                        <Server className="h-5 w-5 text-primary" />
                        <div>
                          <p className="font-medium">Host Discovery</p>
                          <p className="text-sm text-muted-foreground">Find active hosts</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardContent className="p-4">
                      <div className="flex items-center space-x-2">
                        <Router className="h-5 w-5 text-primary" />
                        <div>
                          <p className="font-medium">Network Mapping</p>
                          <p className="text-sm text-muted-foreground">Topology discovery</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardContent className="p-4">
                      <div className="flex items-center space-x-2">
                        <Wifi className="h-5 w-5 text-primary" />
                        <div>
                          <p className="font-medium">OS Detection</p>
                          <p className="text-sm text-muted-foreground">Operating system fingerprinting</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </div>
              </div>
            </TabsContent>

            <TabsContent value="ports" className="space-y-4">
              <div className="text-center p-8">
                <Shield className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                <p className="text-lg font-medium mb-2">Port Scanning</p>
                <p className="text-muted-foreground">
                  Comprehensive port scanning with various techniques
                </p>
              </div>
            </TabsContent>

            <TabsContent value="services" className="space-y-4">
              <div className="text-center p-8">
                <Server className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                <p className="text-lg font-medium mb-2">Service Enumeration</p>
                <p className="text-muted-foreground">
                  Identify and fingerprint running services
                </p>
              </div>
            </TabsContent>

            <TabsContent value="vulnerabilities" className="space-y-4">
              <div className="text-center p-8">
                <Zap className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                <p className="text-lg font-medium mb-2">Network Vulnerabilities</p>
                <p className="text-muted-foreground">
                  Automated vulnerability assessment for network services
                </p>
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
};

export default NetworkScanning;