import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { 
  Code, 
  GitBranch, 
  Bug,
  Shield,
  FileText,
  Search
} from "lucide-react";
import { useState } from "react";
import { useToast } from "@/hooks/use-toast";
import { supabase } from "@/integrations/supabase/client";

const CodeAnalysis = () => {
  const { toast } = useToast();
  const [gitUrl, setGitUrl] = useState("");
  const [codeSnippet, setCodeSnippet] = useState("");
  const [language, setLanguage] = useState("javascript");
  const [analysis, setAnalysis] = useState("");
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  const analyzeCode = async () => {
    if (!codeSnippet.trim() && !gitUrl.trim()) {
      toast({ title: "Error", description: "Provide code or Git URL", variant: "destructive" });
      return;
    }

    setIsAnalyzing(true);
    try {
      const { data, error } = await supabase.functions.invoke('security-advisor', {
        body: { 
          domain: 'application-security',
          task: `Analyze this ${language} code for security vulnerabilities:\n\n${codeSnippet || `Git repository: ${gitUrl}`}`
        }
      });

      if (error) throw error;
      setAnalysis(data.advice);
      toast({ title: "Analysis Complete", description: "Security review finished" });
    } catch (error: any) {
      toast({ title: "Analysis Failed", description: error.message, variant: "destructive" });
    } finally {
      setIsAnalyzing(false);
    }
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <Code className="h-5 w-5 mr-2 text-primary" />
            AI-Powered Code Security Analysis
          </CardTitle>
          <CardDescription>
            Real security code review using AI analysis
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="upload" className="w-full">
            <TabsList className="grid w-full grid-cols-3">
              <TabsTrigger value="upload">Code Upload</TabsTrigger>
              <TabsTrigger value="git">Git Repository</TabsTrigger>
              <TabsTrigger value="results">Results</TabsTrigger>
            </TabsList>

            <TabsContent value="upload" className="space-y-4">
              <div className="space-y-4">
                <div className="space-y-2">
                  <Label>Programming Language</Label>
                  <Select value={language} onValueChange={setLanguage}>
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

                <div className="space-y-2">
                  <Label>Code to Analyze</Label>
                  <Textarea
                    placeholder="Paste your code here for security analysis..."
                    value={codeSnippet}
                    onChange={(e) => setCodeSnippet(e.target.value)}
                    rows={15}
                    className="font-mono"
                  />
                </div>

                <Button onClick={analyzeCode} disabled={isAnalyzing}>
                  <Shield className="h-4 w-4 mr-2" />
                  {isAnalyzing ? "Analyzing..." : "Analyze Code Security"}
                </Button>
              </div>
            </TabsContent>

            <TabsContent value="git" className="space-y-4">
              <div className="space-y-4">
                <div className="space-y-2">
                  <Label>Git Repository URL</Label>
                  <Input
                    placeholder="https://github.com/username/repo"
                    value={gitUrl}
                    onChange={(e) => setGitUrl(e.target.value)}
                  />
                </div>

                <Button onClick={analyzeCode} disabled={isAnalyzing}>
                  <GitBranch className="h-4 w-4 mr-2" />
                  {isAnalyzing ? "Analyzing..." : "Analyze Repository"}
                </Button>
              </div>
            </TabsContent>

            <TabsContent value="results" className="space-y-4">
              {!analysis ? (
                <div className="text-center p-8">
                  <Search className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                  <p className="text-lg font-medium mb-2">Analysis Results</p>
                  <p className="text-muted-foreground">
                    Upload code to see AI-powered security analysis
                  </p>
                </div>
              ) : (
                <div className="p-4 bg-muted rounded-lg">
                  <h3 className="font-semibold mb-2 flex items-center">
                    <Bug className="h-5 w-5 mr-2 text-destructive" />
                    Security Analysis Results
                  </h3>
                  <div className="whitespace-pre-wrap text-sm">{analysis}</div>
                </div>
              )}
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
};

export default CodeAnalysis;
