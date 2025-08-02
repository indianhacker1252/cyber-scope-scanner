import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { 
  FileText, 
  Download, 
  Eye, 
  Calendar,
  BarChart3,
  PieChart,
  Share,
  Bot,
  RefreshCw,
  Sparkles
} from "lucide-react";
import { useState } from "react";
import { useToast } from "@/hooks/use-toast";
import OpenAIService from "@/utils/openaiService";
import { useKaliTools } from "@/hooks/useKaliTools";

const Reports = () => {
  const { activeSessions } = useKaliTools();
  const [aiAnalysis, setAiAnalysis] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [finalReport, setFinalReport] = useState('');
  const [isGeneratingReport, setIsGeneratingReport] = useState(false);
  const { toast } = useToast();

  const analyzeVulnerabilities = async () => {
    if (!OpenAIService.hasApiKey()) {
      toast({
        title: "API Key Required",
        description: "Please configure your OpenAI API key in Tool Management",
        variant: "destructive"
      });
      return;
    }

    const completedScans = activeSessions.filter(session => session.status === 'completed');
    if (completedScans.length === 0) {
      toast({
        title: "No Scan Results",
        description: "Run some security scans first to generate analysis",
        variant: "destructive"
      });
      return;
    }

    setIsAnalyzing(true);
    try {
      const analysis = await OpenAIService.analyzeVulnerabilities(completedScans);
      setAiAnalysis(analysis);
      toast({
        title: "Analysis Complete",
        description: "AI vulnerability analysis has been generated"
      });
    } catch (error: any) {
      toast({
        title: "Analysis Failed",
        description: error.message,
        variant: "destructive"
      });
    } finally {
      setIsAnalyzing(false);
    }
  };

  const generateAwesomeReport = async () => {
    if (!aiAnalysis) {
      toast({
        title: "Analysis Required",
        description: "Run AI analysis first before generating the report",
        variant: "destructive"
      });
      return;
    }

    setIsGeneratingReport(true);
    try {
      const report = await OpenAIService.generateTechnicalReport(aiAnalysis, activeSessions);
      setFinalReport(report);
      toast({
        title: "Awesome Report Generated!",
        description: "Professional penetration testing report is ready"
      });
    } catch (error: any) {
      toast({
        title: "Report Generation Failed",
        description: error.message,
        variant: "destructive"
      });
    } finally {
      setIsGeneratingReport(false);
    }
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <FileText className="h-5 w-5 mr-2 text-primary" />
            AI-Powered Security Reports
          </CardTitle>
          <CardDescription>
            Generate comprehensive reports with ChatGPT analysis
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="ai-analysis" className="w-full">
            <TabsList className="grid w-full grid-cols-5">
              <TabsTrigger value="ai-analysis">AI Analysis</TabsTrigger>
              <TabsTrigger value="generate">Generate Report</TabsTrigger>
              <TabsTrigger value="templates">Templates</TabsTrigger>
              <TabsTrigger value="history">History</TabsTrigger>
              <TabsTrigger value="dashboard">Dashboard</TabsTrigger>
            </TabsList>

            <TabsContent value="ai-analysis" className="space-y-4">
              <div className="grid grid-cols-1 gap-6">
                {/* AI Analysis Controls */}
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center">
                      <Bot className="h-5 w-5 mr-2" />
                      ChatGPT Vulnerability Analysis
                    </CardTitle>
                    <CardDescription>
                      AI-powered analysis of your security scan results
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="font-medium">Active Sessions: {activeSessions.length}</p>
                        <p className="text-sm text-muted-foreground">
                          Completed: {activeSessions.filter(s => s.status === 'completed').length}
                        </p>
                      </div>
                      <Button 
                        onClick={analyzeVulnerabilities}
                        disabled={isAnalyzing}
                      >
                        {isAnalyzing ? (
                          <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                        ) : (
                          <Sparkles className="h-4 w-4 mr-2" />
                        )}
                        Analyze with AI
                      </Button>
                    </div>
                  </CardContent>
                </Card>

                {/* AI Analysis Results */}
                {aiAnalysis && (
                  <Card>
                    <CardHeader>
                      <CardTitle>AI Analysis Results</CardTitle>
                      <CardDescription>
                        Comprehensive vulnerability assessment by ChatGPT
                      </CardDescription>
                    </CardHeader>
                    <CardContent>
                      <Textarea
                        value={aiAnalysis}
                        readOnly
                        className="min-h-[400px] font-mono text-sm"
                        placeholder="AI analysis will appear here..."
                      />
                    </CardContent>
                  </Card>
                )}
              </div>
            </TabsContent>

            <TabsContent value="generate" className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                <Card className="col-span-full mb-4">
                  <CardHeader>
                    <CardTitle className="flex items-center">
                      <Sparkles className="h-5 w-5 mr-2" />
                      Awesome AI Report Generator
                    </CardTitle>
                    <CardDescription>
                      Generate professional reports with AI analysis integration
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <Button 
                      onClick={generateAwesomeReport}
                      disabled={isGeneratingReport || !aiAnalysis}
                      className="w-full mb-4"
                    >
                      {isGeneratingReport ? (
                        <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                      ) : (
                        <FileText className="h-4 w-4 mr-2" />
                      )}
                      Generate Awesome Report
                    </Button>
                    
                    {finalReport && (
                      <Textarea
                        value={finalReport}
                        readOnly
                        className="min-h-[300px] font-mono text-sm"
                        placeholder="Generated report will appear here..."
                      />
                    )}
                  </CardContent>
                </Card>

                <Card>
                  <CardContent className="p-4">
                    <div className="flex items-center space-x-2 mb-3">
                      <FileText className="h-5 w-5 text-primary" />
                      <div>
                        <p className="font-medium">Executive Summary</p>
                        <p className="text-sm text-muted-foreground">High-level overview with AI insights</p>
                      </div>
                    </div>
                    <Button size="sm" className="w-full" disabled={!finalReport}>
                      <Download className="h-4 w-4 mr-1" />
                      Download PDF
                    </Button>
                  </CardContent>
                </Card>

                <Card>
                  <CardContent className="p-4">
                    <div className="flex items-center space-x-2 mb-3">
                      <BarChart3 className="h-5 w-5 text-primary" />
                      <div>
                        <p className="font-medium">Technical Report</p>
                        <p className="text-sm text-muted-foreground">AI-enhanced technical findings</p>
                      </div>
                    </div>
                    <Button size="sm" className="w-full" disabled={!finalReport}>
                      <Download className="h-4 w-4 mr-1" />
                      Download PDF
                    </Button>
                  </CardContent>
                </Card>

                <Card>
                  <CardContent className="p-4">
                    <div className="flex items-center space-x-2 mb-3">
                      <PieChart className="h-5 w-5 text-primary" />
                      <div>
                        <p className="font-medium">Compliance Report</p>
                        <p className="text-sm text-muted-foreground">AI compliance assessment</p>
                      </div>
                    </div>
                    <Button size="sm" className="w-full" disabled={!finalReport}>
                      <Download className="h-4 w-4 mr-1" />
                      Download PDF
                    </Button>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>

            <TabsContent value="templates" className="space-y-4">
              <div className="text-center p-8">
                <FileText className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                <p className="text-lg font-medium mb-2">AI Report Templates</p>
                <p className="text-muted-foreground">
                  Customizable templates enhanced with AI analysis
                </p>
              </div>
            </TabsContent>

            <TabsContent value="history" className="space-y-4">
              <div className="text-center p-8">
                <Calendar className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                <p className="text-lg font-medium mb-2">Report History</p>
                <p className="text-muted-foreground">
                  View and download previously generated AI-enhanced reports
                </p>
              </div>
            </TabsContent>

            <TabsContent value="dashboard" className="space-y-4">
              <div className="text-center p-8">
                <BarChart3 className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                <p className="text-lg font-medium mb-2">AI Dashboard</p>
                <p className="text-muted-foreground">
                  Interactive dashboard with AI-powered analytics and trends
                </p>
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
};

export default Reports;