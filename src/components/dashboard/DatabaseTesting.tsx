import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { 
  Database, 
  Key, 
  Shield, 
  Search,
  Lock,
  Users,
  FileText
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { useState } from "react";

const DatabaseTesting = () => {
  const [connectionString, setConnectionString] = useState("");
  const { toast } = useToast();

  const handleDatabaseTest = () => {
    if (!connectionString) {
      toast({
        title: "Error",
        description: "Please provide database connection details",
        variant: "destructive"
      });
      return;
    }

    toast({
      title: "Database Security Test Started",
      description: "Analyzing database security configuration",
    });
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <Database className="h-5 w-5 mr-2 text-primary" />
            Database Security Testing
          </CardTitle>
          <CardDescription>
            Comprehensive database security assessment and penetration testing
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="connection" className="w-full">
            <TabsList className="grid w-full grid-cols-4">
              <TabsTrigger value="connection">Connection</TabsTrigger>
              <TabsTrigger value="injection">SQL Injection</TabsTrigger>
              <TabsTrigger value="privileges">Privileges</TabsTrigger>
              <TabsTrigger value="config">Configuration</TabsTrigger>
            </TabsList>

            <TabsContent value="connection" className="space-y-4">
              <div className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="db-type">Database Type</Label>
                    <Select>
                      <SelectTrigger>
                        <SelectValue placeholder="Select database type" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="mysql">MySQL</SelectItem>
                        <SelectItem value="postgresql">PostgreSQL</SelectItem>
                        <SelectItem value="mssql">Microsoft SQL Server</SelectItem>
                        <SelectItem value="oracle">Oracle</SelectItem>
                        <SelectItem value="mongodb">MongoDB</SelectItem>
                        <SelectItem value="redis">Redis</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="host">Host</Label>
                    <Input
                      id="host"
                      placeholder="localhost or IP address"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="port">Port</Label>
                    <Input
                      id="port"
                      placeholder="3306"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="username">Username</Label>
                    <Input
                      id="username"
                      placeholder="Database username"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="password">Password</Label>
                    <Input
                      id="password"
                      type="password"
                      placeholder="Database password"
                    />
                  </div>
                </div>

                <Button onClick={handleDatabaseTest} className="w-full md:w-auto">
                  <Database className="h-4 w-4 mr-2" />
                  Test Database Security
                </Button>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <Card>
                    <CardContent className="p-4">
                      <div className="flex items-center space-x-2">
                        <Key className="h-5 w-5 text-primary" />
                        <div>
                          <p className="font-medium">Authentication</p>
                          <p className="text-sm text-muted-foreground">Connection security</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardContent className="p-4">
                      <div className="flex items-center space-x-2">
                        <Shield className="h-5 w-5 text-primary" />
                        <div>
                          <p className="font-medium">Encryption</p>
                          <p className="text-sm text-muted-foreground">Data in transit/rest</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardContent className="p-4">
                      <div className="flex items-center space-x-2">
                        <Users className="h-5 w-5 text-primary" />
                        <div>
                          <p className="font-medium">User Management</p>
                          <p className="text-sm text-muted-foreground">Access controls</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </div>
              </div>
            </TabsContent>

            <TabsContent value="injection" className="space-y-4">
              <div className="text-center p-8">
                <Search className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                <p className="text-lg font-medium mb-2">SQL Injection Testing</p>
                <p className="text-muted-foreground">
                  Automated SQL injection vulnerability detection
                </p>
              </div>
            </TabsContent>

            <TabsContent value="privileges" className="space-y-4">
              <div className="text-center p-8">
                <Lock className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                <p className="text-lg font-medium mb-2">Privilege Escalation</p>
                <p className="text-muted-foreground">
                  Test for privilege escalation vulnerabilities
                </p>
              </div>
            </TabsContent>

            <TabsContent value="config" className="space-y-4">
              <div className="text-center p-8">
                <FileText className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                <p className="text-lg font-medium mb-2">Configuration Review</p>
                <p className="text-muted-foreground">
                  Security configuration assessment
                </p>
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
};

export default DatabaseTesting;