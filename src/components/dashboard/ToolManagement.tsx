import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { 
  Settings, 
  Download, 
  Play, 
  Pause,
  RefreshCw,
  CheckCircle,
  AlertCircle,
  Terminal
} from "lucide-react";

const ToolManagement = () => {
  const tools = [
    { name: "Nmap", version: "7.94", status: "active", category: "Network" },
    { name: "Nikto", version: "2.5.0", status: "active", category: "Web" },
    { name: "SQLMap", version: "1.7.2", status: "active", category: "Database" },
    { name: "Gobuster", version: "3.6", status: "inactive", category: "Discovery" },
    { name: "Burp Suite", version: "2023.10", status: "active", category: "Web" },
    { name: "OWASP ZAP", version: "2.14.0", status: "active", category: "Web" },
  ];

  const getStatusIcon = (status: string) => {
    return status === "active" ? CheckCircle : AlertCircle;
  };

  const getStatusColor = (status: string) => {
    return status === "active" ? "text-success" : "text-warning";
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <Settings className="h-5 w-5 mr-2 text-primary" />
            Security Tool Management
          </CardTitle>
          <CardDescription>
            Manage and configure security testing tools and frameworks
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="tools" className="w-full">
            <TabsList className="grid w-full grid-cols-4">
              <TabsTrigger value="tools">Installed Tools</TabsTrigger>
              <TabsTrigger value="marketplace">Tool Marketplace</TabsTrigger>
              <TabsTrigger value="config">Configuration</TabsTrigger>
              <TabsTrigger value="updates">Updates</TabsTrigger>
            </TabsList>

            <TabsContent value="tools" className="space-y-4">
              <div className="grid grid-cols-1 gap-4">
                {tools.map((tool, index) => {
                  const StatusIcon = getStatusIcon(tool.status);
                  return (
                    <Card key={index}>
                      <CardContent className="p-4">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center space-x-3">
                            <Terminal className="h-6 w-6 text-primary" />
                            <div>
                              <h4 className="font-medium">{tool.name}</h4>
                              <p className="text-sm text-muted-foreground">Version {tool.version}</p>
                            </div>
                          </div>
                          <div className="flex items-center space-x-3">
                            <Badge variant="outline">{tool.category}</Badge>
                            <StatusIcon className={`h-5 w-5 ${getStatusColor(tool.status)}`} />
                            <div className="space-x-2">
                              {tool.status === "active" ? (
                                <Button size="sm" variant="outline">
                                  <Pause className="h-4 w-4 mr-1" />
                                  Stop
                                </Button>
                              ) : (
                                <Button size="sm">
                                  <Play className="h-4 w-4 mr-1" />
                                  Start
                                </Button>
                              )}
                              <Button size="sm" variant="outline">
                                <Settings className="h-4 w-4 mr-1" />
                                Configure
                              </Button>
                            </div>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  );
                })}
              </div>
            </TabsContent>

            <TabsContent value="marketplace" className="space-y-4">
              <div className="text-center p-8">
                <Download className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                <p className="text-lg font-medium mb-2">Tool Marketplace</p>
                <p className="text-muted-foreground">
                  Browse and install additional security testing tools
                </p>
              </div>
            </TabsContent>

            <TabsContent value="config" className="space-y-4">
              <div className="text-center p-8">
                <Settings className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                <p className="text-lg font-medium mb-2">Global Configuration</p>
                <p className="text-muted-foreground">
                  Configure global settings for all security tools
                </p>
              </div>
            </TabsContent>

            <TabsContent value="updates" className="space-y-4">
              <div className="text-center p-8">
                <RefreshCw className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                <p className="text-lg font-medium mb-2">Tool Updates</p>
                <p className="text-muted-foreground">
                  Check for and install tool updates and security patches
                </p>
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
};

export default ToolManagement;