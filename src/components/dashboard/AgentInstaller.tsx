import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { 
  Download, 
  Smartphone,
  Monitor,
  Server,
  Globe,
  CheckCircle,
  AlertTriangle,
  Play,
  Settings,
  Copy,
  QrCode
} from "lucide-react";
import { useState } from "react";
import { useToast } from "@/hooks/use-toast";

const AgentInstaller = () => {
  const { toast } = useToast();
  const [selectedPlatform, setSelectedPlatform] = useState("android");
  const [agentConfig, setAgentConfig] = useState({
    serverUrl: "https://vapt-server.example.com",
    apiKey: "sk_test_123456789abcdef",
    deviceId: "",
    autoStart: true
  });

  const platforms = [
    {
      id: "android",
      name: "Android",
      icon: Smartphone,
      description: "Android mobile devices and tablets",
      downloadUrl: "/agents/android/vapt-agent.apk",
      installSteps: [
        "Enable 'Unknown Sources' in Android settings",
        "Download and install the APK file",
        "Grant necessary permissions when prompted",
        "Configure connection settings"
      ]
    },
    {
      id: "ios",
      name: "iOS",
      icon: Smartphone,
      description: "iPhone and iPad devices",
      downloadUrl: "/agents/ios/vapt-agent.ipa",
      installSteps: [
        "Install via TestFlight or enterprise distribution",
        "Trust the developer certificate in settings",
        "Configure network permissions",
        "Enter server configuration"
      ]
    },
    {
      id: "windows",
      name: "Windows",
      icon: Monitor,
      description: "Windows desktop and server systems",
      downloadUrl: "/agents/windows/vapt-agent.exe",
      installSteps: [
        "Download the executable file",
        "Run as administrator",
        "Configure Windows Defender exclusions if needed",
        "Complete the setup wizard"
      ]
    },
    {
      id: "linux",
      name: "Linux",
      icon: Server,
      description: "Linux servers and workstations",
      downloadUrl: "/agents/linux/vapt-agent.sh",
      installSteps: [
        "Download the installation script",
        "Make the script executable: chmod +x vapt-agent.sh",
        "Run with sudo privileges: sudo ./vapt-agent.sh",
        "Configure systemd service if needed"
      ]
    },
    {
      id: "web",
      name: "Web Browser",
      icon: Globe,
      description: "Browser-based agent for web applications",
      downloadUrl: "/agents/web/vapt-extension.zip",
      installSteps: [
        "Download the browser extension",
        "Open browser extension management",
        "Enable developer mode and load unpacked",
        "Configure target applications"
      ]
    }
  ];

  const downloadAgent = (platform: string) => {
    const platformInfo = platforms.find(p => p.id === platform);
    if (platformInfo) {
      // Simulate download
      toast({
        title: "Download Started",
        description: `Downloading VAPT agent for ${platformInfo.name}`,
      });
      
      // Create a mock download link
      const link = document.createElement('a');
      link.href = '#';
      link.download = `vapt-agent-${platform}`;
      link.click();
    }
  };

  const installAgent = (platform: string) => {
    toast({
      title: "Installation Started",
      description: `Installing VAPT agent on ${platform} device`,
    });

    // Simulate installation process
    setTimeout(() => {
      toast({
        title: "Installation Complete",
        description: "VAPT agent has been successfully installed and configured",
      });
    }, 3000);
  };

  const generateQRCode = () => {
    toast({
      title: "QR Code Generated",
      description: "Scan with mobile device to download agent",
    });
  };

  const copyConfigCommand = () => {
    const command = `curl -sSL ${agentConfig.serverUrl}/install | bash -s -- --api-key ${agentConfig.apiKey}`;
    navigator.clipboard.writeText(command);
    toast({
      title: "Command Copied",
      description: "Installation command copied to clipboard",
    });
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <Download className="h-5 w-5 mr-2 text-primary" />
            Agent Installation & Management
          </CardTitle>
          <CardDescription>
            Deploy VAPT agents on target devices for comprehensive security testing
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="download" className="w-full">
            <TabsList className="grid w-full grid-cols-4">
              <TabsTrigger value="download">Download</TabsTrigger>
              <TabsTrigger value="install">Install</TabsTrigger>
              <TabsTrigger value="config">Configure</TabsTrigger>
              <TabsTrigger value="manage">Manage</TabsTrigger>
            </TabsList>

            <TabsContent value="download" className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {platforms.map((platform) => (
                  <Card key={platform.id} className={`cursor-pointer transition-colors ${
                    selectedPlatform === platform.id ? 'ring-2 ring-primary' : ''
                  }`} onClick={() => setSelectedPlatform(platform.id)}>
                    <CardContent className="p-4">
                      <div className="flex items-center space-x-3 mb-3">
                        <platform.icon className="h-8 w-8 text-primary" />
                        <div>
                          <h3 className="font-semibold">{platform.name}</h3>
                          <p className="text-sm text-muted-foreground">{platform.description}</p>
                        </div>
                      </div>
                      <div className="space-y-2">
                        <Button 
                          size="sm" 
                          className="w-full"
                          onClick={(e) => {
                            e.stopPropagation();
                            downloadAgent(platform.id);
                          }}
                        >
                          <Download className="h-4 w-4 mr-2" />
                          Download
                        </Button>
                        {(platform.id === 'android' || platform.id === 'ios') && (
                          <Button 
                            size="sm" 
                            variant="outline" 
                            className="w-full"
                            onClick={(e) => {
                              e.stopPropagation();
                              generateQRCode();
                            }}
                          >
                            <QrCode className="h-4 w-4 mr-2" />
                            QR Code
                          </Button>
                        )}
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </TabsContent>

            <TabsContent value="install" className="space-y-4">
              {selectedPlatform && (
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center">
                      {(() => {
                        const platform = platforms.find(p => p.id === selectedPlatform);
                        const Icon = platform?.icon || Monitor;
                        return <Icon className="h-5 w-5 mr-2 text-primary" />;
                      })()}
                      Installation Instructions - {platforms.find(p => p.id === selectedPlatform)?.name}
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      <ol className="space-y-3">
                        {platforms.find(p => p.id === selectedPlatform)?.installSteps.map((step, index) => (
                          <li key={index} className="flex items-start space-x-3">
                            <Badge variant="outline" className="mt-0.5">{index + 1}</Badge>
                            <span className="text-sm">{step}</span>
                          </li>
                        ))}
                      </ol>
                      
                      <div className="flex space-x-2">
                        <Button onClick={() => installAgent(selectedPlatform)}>
                          <Play className="h-4 w-4 mr-2" />
                          Start Installation
                        </Button>
                        <Button variant="outline" onClick={copyConfigCommand}>
                          <Copy className="h-4 w-4 mr-2" />
                          Copy Command
                        </Button>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              )}
            </TabsContent>

            <TabsContent value="config" className="space-y-4">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <Settings className="h-5 w-5 mr-2 text-primary" />
                    Agent Configuration
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="server-url">Server URL</Label>
                      <Input
                        id="server-url"
                        value={agentConfig.serverUrl}
                        onChange={(e) => setAgentConfig({...agentConfig, serverUrl: e.target.value})}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="api-key">API Key</Label>
                      <Input
                        id="api-key"
                        type="password"
                        value={agentConfig.apiKey}
                        onChange={(e) => setAgentConfig({...agentConfig, apiKey: e.target.value})}
                      />
                    </div>
                  </div>
                  
                  <div className="space-y-2">
                    <Label htmlFor="device-id">Device ID (Optional)</Label>
                    <Input
                      id="device-id"
                      placeholder="Leave empty for auto-generation"
                      value={agentConfig.deviceId}
                      onChange={(e) => setAgentConfig({...agentConfig, deviceId: e.target.value})}
                    />
                  </div>

                  <div className="flex items-center space-x-2">
                    <input
                      type="checkbox"
                      id="auto-start"
                      checked={agentConfig.autoStart}
                      onChange={(e) => setAgentConfig({...agentConfig, autoStart: e.target.checked})}
                    />
                    <Label htmlFor="auto-start">Auto-start agent on device boot</Label>
                  </div>

                  <Button>
                    <Settings className="h-4 w-4 mr-2" />
                    Save Configuration
                  </Button>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="manage" className="space-y-4">
              <div className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <Card>
                    <CardContent className="p-4 text-center">
                      <CheckCircle className="h-8 w-8 mx-auto mb-2 text-success" />
                      <p className="font-medium">3 Active</p>
                      <p className="text-sm text-muted-foreground">Connected agents</p>
                    </CardContent>
                  </Card>
                  <Card>
                    <CardContent className="p-4 text-center">
                      <AlertTriangle className="h-8 w-8 mx-auto mb-2 text-warning" />
                      <p className="font-medium">1 Offline</p>
                      <p className="text-sm text-muted-foreground">Disconnected agents</p>
                    </CardContent>
                  </Card>
                  <Card>
                    <CardContent className="p-4 text-center">
                      <Download className="h-8 w-8 mx-auto mb-2 text-primary" />
                      <p className="font-medium">12 Total</p>
                      <p className="text-sm text-muted-foreground">Downloaded agents</p>
                    </CardContent>
                  </Card>
                </div>

                <Card>
                  <CardHeader>
                    <CardTitle>Connected Agents</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3">
                      {[
                        { id: "agent-001", name: "Android Phone", platform: "Android", status: "active", lastSeen: "2 minutes ago" },
                        { id: "agent-002", name: "Windows Laptop", platform: "Windows", status: "active", lastSeen: "5 minutes ago" },
                        { id: "agent-003", name: "Linux Server", platform: "Linux", status: "active", lastSeen: "1 minute ago" },
                        { id: "agent-004", name: "iOS Device", platform: "iOS", status: "offline", lastSeen: "2 hours ago" }
                      ].map((agent) => (
                        <div key={agent.id} className="flex items-center justify-between p-3 bg-muted/50 rounded-lg">
                          <div className="flex items-center space-x-3">
                            <div className={`w-3 h-3 rounded-full ${
                              agent.status === 'active' ? 'bg-success' : 'bg-muted-foreground'
                            }`} />
                            <div>
                              <p className="font-medium">{agent.name}</p>
                              <p className="text-sm text-muted-foreground">{agent.platform} • {agent.lastSeen}</p>
                            </div>
                          </div>
                          <Badge variant={agent.status === 'active' ? 'default' : 'secondary'}>
                            {agent.status}
                          </Badge>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
};

export default AgentInstaller;