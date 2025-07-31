import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { 
  Code, 
  Upload, 
  GitBranch, 
  Bug,
  Shield,
  FileText,
  Search
} from "lucide-react";

const CodeAnalysis = () => {
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <Code className="h-5 w-5 mr-2 text-primary" />
            Static Code Analysis
          </CardTitle>
          <CardDescription>
            Automated security code review and vulnerability detection
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="upload" className="w-full">
            <TabsList className="grid w-full grid-cols-4">
              <TabsTrigger value="upload">Upload Code</TabsTrigger>
              <TabsTrigger value="git">Git Repository</TabsTrigger>
              <TabsTrigger value="rules">Security Rules</TabsTrigger>
              <TabsTrigger value="results">Results</TabsTrigger>
            </TabsList>

            <TabsContent value="upload" className="space-y-4">
              <div className="border-2 border-dashed border-border rounded-lg p-8 text-center">
                <Upload className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                <p className="text-lg font-medium mb-2">Upload Source Code</p>
                <p className="text-muted-foreground mb-4">
                  Upload a ZIP file containing your source code for analysis
                </p>
                <Button variant="outline">
                  <Upload className="h-4 w-4 mr-2" />
                  Choose Code Archive
                </Button>
              </div>

              <div className="space-y-4">
                <div className="space-y-2">
                  <label className="text-sm font-medium">Programming Language</label>
                  <Select>
                    <SelectTrigger>
                      <SelectValue placeholder="Select language" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="javascript">JavaScript/TypeScript</SelectItem>
                      <SelectItem value="python">Python</SelectItem>
                      <SelectItem value="java">Java</SelectItem>
                      <SelectItem value="csharp">C#</SelectItem>
                      <SelectItem value="php">PHP</SelectItem>
                      <SelectItem value="go">Go</SelectItem>
                      <SelectItem value="ruby">Ruby</SelectItem>
                      <SelectItem value="cpp">C/C++</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
            </TabsContent>

            <TabsContent value="git" className="space-y-4">
              <div className="text-center p-8">
                <GitBranch className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                <p className="text-lg font-medium mb-2">Git Repository Analysis</p>
                <p className="text-muted-foreground">
                  Connect to Git repositories for continuous security analysis
                </p>
              </div>
            </TabsContent>

            <TabsContent value="rules" className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                <Card>
                  <CardContent className="p-4">
                    <div className="flex items-center space-x-2">
                      <Bug className="h-5 w-5 text-primary" />
                      <div>
                        <p className="font-medium">Vulnerability Detection</p>
                        <p className="text-sm text-muted-foreground">SQL injection, XSS, etc.</p>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                <Card>
                  <CardContent className="p-4">
                    <div className="flex items-center space-x-2">
                      <Shield className="h-5 w-5 text-primary" />
                      <div>
                        <p className="font-medium">Security Patterns</p>
                        <p className="text-sm text-muted-foreground">Crypto, auth patterns</p>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                <Card>
                  <CardContent className="p-4">
                    <div className="flex items-center space-x-2">
                      <FileText className="h-5 w-5 text-primary" />
                      <div>
                        <p className="font-medium">Code Quality</p>
                        <p className="text-sm text-muted-foreground">Best practices</p>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>

            <TabsContent value="results" className="space-y-4">
              <div className="text-center p-8">
                <Search className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                <p className="text-lg font-medium mb-2">Analysis Results</p>
                <p className="text-muted-foreground">
                  Upload code to see detailed security analysis results
                </p>
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
};

export default CodeAnalysis;