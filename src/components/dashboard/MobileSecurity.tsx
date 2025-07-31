import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { 
  Smartphone, 
  Shield, 
  Lock, 
  Upload,
  FileCode,
  Wifi,
  Database
} from "lucide-react";

const MobileSecurity = () => {
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
                <Button variant="outline">
                  <Upload className="h-4 w-4 mr-2" />
                  Choose Application File
                </Button>
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
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {[
                  "M1: Improper Platform Usage",
                  "M2: Insecure Data Storage",
                  "M3: Insecure Communication",
                  "M4: Insecure Authentication",
                  "M5: Insufficient Cryptography",
                  "M6: Insecure Authorization",
                  "M7: Client Code Quality",
                  "M8: Code Tampering",
                  "M9: Reverse Engineering",
                  "M10: Extraneous Functionality"
                ].map((item, index) => (
                  <Card key={index}>
                    <CardContent className="p-4">
                      <p className="font-medium">{item}</p>
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