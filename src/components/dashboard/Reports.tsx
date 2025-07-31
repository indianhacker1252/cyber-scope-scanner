import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { 
  FileText, 
  Download, 
  Eye, 
  Calendar,
  BarChart3,
  PieChart,
  Share
} from "lucide-react";

const Reports = () => {
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <FileText className="h-5 w-5 mr-2 text-primary" />
            Security Assessment Reports
          </CardTitle>
          <CardDescription>
            Generate and manage comprehensive security reports
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="generate" className="w-full">
            <TabsList className="grid w-full grid-cols-4">
              <TabsTrigger value="generate">Generate Report</TabsTrigger>
              <TabsTrigger value="templates">Templates</TabsTrigger>
              <TabsTrigger value="history">Report History</TabsTrigger>
              <TabsTrigger value="dashboard">Dashboard</TabsTrigger>
            </TabsList>

            <TabsContent value="generate" className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                <Card>
                  <CardContent className="p-4">
                    <div className="flex items-center space-x-2 mb-3">
                      <FileText className="h-5 w-5 text-primary" />
                      <div>
                        <p className="font-medium">Executive Summary</p>
                        <p className="text-sm text-muted-foreground">High-level overview for management</p>
                      </div>
                    </div>
                    <Button size="sm" className="w-full">
                      <Download className="h-4 w-4 mr-1" />
                      Generate PDF
                    </Button>
                  </CardContent>
                </Card>

                <Card>
                  <CardContent className="p-4">
                    <div className="flex items-center space-x-2 mb-3">
                      <BarChart3 className="h-5 w-5 text-primary" />
                      <div>
                        <p className="font-medium">Technical Report</p>
                        <p className="text-sm text-muted-foreground">Detailed technical findings</p>
                      </div>
                    </div>
                    <Button size="sm" className="w-full">
                      <Download className="h-4 w-4 mr-1" />
                      Generate PDF
                    </Button>
                  </CardContent>
                </Card>

                <Card>
                  <CardContent className="p-4">
                    <div className="flex items-center space-x-2 mb-3">
                      <PieChart className="h-5 w-5 text-primary" />
                      <div>
                        <p className="font-medium">Compliance Report</p>
                        <p className="text-sm text-muted-foreground">Regulatory compliance status</p>
                      </div>
                    </div>
                    <Button size="sm" className="w-full">
                      <Download className="h-4 w-4 mr-1" />
                      Generate PDF
                    </Button>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>

            <TabsContent value="templates" className="space-y-4">
              <div className="text-center p-8">
                <FileText className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                <p className="text-lg font-medium mb-2">Report Templates</p>
                <p className="text-muted-foreground">
                  Customizable templates for different types of security reports
                </p>
              </div>
            </TabsContent>

            <TabsContent value="history" className="space-y-4">
              <div className="text-center p-8">
                <Calendar className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                <p className="text-lg font-medium mb-2">Report History</p>
                <p className="text-muted-foreground">
                  View and download previously generated reports
                </p>
              </div>
            </TabsContent>

            <TabsContent value="dashboard" className="space-y-4">
              <div className="text-center p-8">
                <BarChart3 className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                <p className="text-lg font-medium mb-2">Report Dashboard</p>
                <p className="text-muted-foreground">
                  Interactive dashboard for report analytics and trends
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