import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { ScrollArea } from "@/components/ui/scroll-area";
import { 
  FileText, 
  Download, 
  Eye, 
  Calendar,
  AlertTriangle,
  Shield,
  Target,
  BarChart3,
  Filter,
  Search,
  Smartphone,
  Laptop,
  Computer
} from "lucide-react";
import { Input } from "@/components/ui/input";

interface VAPTReport {
  id: string;
  endpointName: string;
  platform: 'windows' | 'macos' | 'android';
  scanDate: Date;
  reportType: 'vulnerability_assessment' | 'penetration_test' | 'compliance_audit';
  severity: 'critical' | 'high' | 'medium' | 'low';
  vulnerabilitiesFound: number;
  status: 'completed' | 'in_progress' | 'failed';
  executiveSummary: string;
  detailedFindings: Array<{
    title: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    cvss: number;
    description: string;
    impact: string;
    remediation: string;
  }>;
  complianceResults: {
    framework: string;
    score: number;
    passed: number;
    failed: number;
  }[];
}

const VAPTReports = () => {
  const [reports, setReports] = useState<VAPTReport[]>([]);
  const [selectedReport, setSelectedReport] = useState<VAPTReport | null>(null);
  const [filterPlatform, setFilterPlatform] = useState<string>("all");
  const [filterSeverity, setFilterSeverity] = useState<string>("all");
  const [searchTerm, setSearchTerm] = useState("");

  useEffect(() => {
    // Generate sample VAPT reports
    const sampleReports: VAPTReport[] = [
      {
        id: "vapt_001",
        endpointName: "DESKTOP-WIN-001",
        platform: "windows",
        scanDate: new Date("2024-01-15"),
        reportType: "vulnerability_assessment",
        severity: "high",
        vulnerabilitiesFound: 23,
        status: "completed",
        executiveSummary: "Comprehensive vulnerability assessment revealed 23 security issues across the Windows endpoint. Critical vulnerabilities include outdated system patches and misconfigured security settings. Immediate attention required for 5 high-severity findings.",
        detailedFindings: [
          {
            title: "CVE-2024-0001 - Windows Kernel Privilege Escalation",
            severity: "critical",
            cvss: 9.8,
            description: "A vulnerability in the Windows kernel allows local users to escalate privileges to SYSTEM level.",
            impact: "Complete system compromise, unauthorized access to sensitive data",
            remediation: "Apply Microsoft Security Update KB5034567 immediately"
          },
          {
            title: "Weak Password Policy",
            severity: "high",
            cvss: 7.5,
            description: "The current password policy allows weak passwords and doesn't enforce complexity requirements.",
            impact: "Increased risk of credential-based attacks",
            remediation: "Implement strong password policy with complexity requirements"
          }
        ],
        complianceResults: [
          { framework: "NIST Cybersecurity Framework", score: 72, passed: 156, failed: 44 },
          { framework: "ISO 27001", score: 68, passed: 134, failed: 66 }
        ]
      },
      {
        id: "vapt_002",
        endpointName: "MacBook-Pro-Dev",
        platform: "macos",
        scanDate: new Date("2024-01-12"),
        reportType: "penetration_test",
        severity: "medium",
        vulnerabilitiesFound: 8,
        status: "completed",
        executiveSummary: "Penetration testing on macOS endpoint identified 8 security weaknesses. No critical vulnerabilities found, but several medium-risk issues require attention including outdated software and configuration weaknesses.",
        detailedFindings: [
          {
            title: "Outdated Safari Browser",
            severity: "medium",
            cvss: 6.2,
            description: "Safari browser is running an outdated version with known security vulnerabilities.",
            impact: "Potential for web-based attacks and malicious code execution",
            remediation: "Update Safari to the latest version"
          }
        ],
        complianceResults: [
          { framework: "NIST Cybersecurity Framework", score: 85, passed: 187, failed: 23 },
          { framework: "SOC 2", score: 82, passed: 164, failed: 36 }
        ]
      },
      {
        id: "vapt_003",
        endpointName: "Android-Device-HR",
        platform: "android",
        scanDate: new Date("2024-01-10"),
        reportType: "compliance_audit",
        severity: "low",
        vulnerabilitiesFound: 3,
        status: "completed",
        executiveSummary: "Compliance audit of Android device shows good overall security posture with minimal issues. Device meets most security requirements with only minor configuration adjustments needed.",
        detailedFindings: [
          {
            title: "USB Debugging Enabled",
            severity: "low",
            cvss: 3.2,
            description: "USB debugging is enabled which could allow unauthorized access when connected to untrusted devices.",
            impact: "Low risk of data extraction if device is compromised physically",
            remediation: "Disable USB debugging in Developer Options"
          }
        ],
        complianceResults: [
          { framework: "GDPR", score: 92, passed: 184, failed: 16 },
          { framework: "HIPAA", score: 88, passed: 176, failed: 24 }
        ]
      }
    ];

    setReports(sampleReports);
  }, []);

  const filteredReports = reports.filter(report => {
    const matchesPlatform = filterPlatform === "all" || report.platform === filterPlatform;
    const matchesSeverity = filterSeverity === "all" || report.severity === filterSeverity;
    const matchesSearch = report.endpointName.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         report.id.toLowerCase().includes(searchTerm.toLowerCase());
    
    return matchesPlatform && matchesSeverity && matchesSearch;
  });

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-500 text-white';
      case 'high': return 'bg-orange-500 text-white';
      case 'medium': return 'bg-yellow-500 text-black';
      case 'low': return 'bg-green-500 text-white';
      default: return 'bg-gray-500 text-white';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return 'bg-green-500 text-white';
      case 'in_progress': return 'bg-blue-500 text-white';
      case 'failed': return 'bg-red-500 text-white';
      default: return 'bg-gray-500 text-white';
    }
  };

  const getPlatformIcon = (platform: string) => {
    switch (platform) {
      case 'windows': return Computer;
      case 'macos': return Laptop;
      case 'android': return Smartphone;
      default: return Target;
    }
  };

  const downloadReport = (report: VAPTReport) => {
    const reportContent = `# VAPT Report - ${report.endpointName}

## Executive Summary
${report.executiveSummary}

## Report Details
- **Endpoint**: ${report.endpointName}
- **Platform**: ${report.platform.toUpperCase()}
- **Scan Date**: ${report.scanDate.toLocaleDateString()}
- **Report Type**: ${report.reportType.replace('_', ' ').toUpperCase()}
- **Overall Severity**: ${report.severity.toUpperCase()}
- **Vulnerabilities Found**: ${report.vulnerabilitiesFound}
- **Status**: ${report.status.toUpperCase()}

## Detailed Findings

${report.detailedFindings.map((finding, index) => `
### ${index + 1}. ${finding.title}
- **Severity**: ${finding.severity.toUpperCase()}
- **CVSS Score**: ${finding.cvss}
- **Description**: ${finding.description}
- **Impact**: ${finding.impact}
- **Remediation**: ${finding.remediation}
`).join('\n')}

## Compliance Results

${report.complianceResults.map(compliance => `
### ${compliance.framework}
- **Score**: ${compliance.score}%
- **Tests Passed**: ${compliance.passed}
- **Tests Failed**: ${compliance.failed}
`).join('\n')}

---
Generated by CyberScope Security Platform
Report ID: ${report.id}
`;

    const blob = new Blob([reportContent], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `VAPT_Report_${report.endpointName}_${report.id}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-3xl font-bold tracking-tight">VAPT Reports</h2>
        <div className="flex items-center space-x-2">
          <Badge variant="outline" className="text-sm">
            Total Reports: {reports.length}
          </Badge>
        </div>
      </div>

      {/* Filters */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <Filter className="h-5 w-5 mr-2" />
            Filters
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="space-y-2">
              <label className="text-sm font-medium">Search</label>
              <div className="relative">
                <Search className="h-4 w-4 absolute left-3 top-3 text-muted-foreground" />
                <Input
                  placeholder="Search endpoints..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-9"
                />
              </div>
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Platform</label>
              <Select value={filterPlatform} onValueChange={setFilterPlatform}>
                <SelectTrigger>
                  <SelectValue placeholder="All Platforms" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Platforms</SelectItem>
                  <SelectItem value="windows">Windows</SelectItem>
                  <SelectItem value="macos">macOS</SelectItem>
                  <SelectItem value="android">Android</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Severity</label>
              <Select value={filterSeverity} onValueChange={setFilterSeverity}>
                <SelectTrigger>
                  <SelectValue placeholder="All Severities" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Severities</SelectItem>
                  <SelectItem value="critical">Critical</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Actions</label>
              <Button variant="outline" className="w-full">
                <BarChart3 className="h-4 w-4 mr-2" />
                Export Summary
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Reports Grid */}
      <div className="grid gap-6">
        {filteredReports.map((report) => {
          const PlatformIcon = getPlatformIcon(report.platform);
          return (
            <Card key={report.id} className="hover:shadow-lg transition-shadow">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <PlatformIcon className="h-6 w-6 text-primary" />
                    <div>
                      <CardTitle className="text-lg">{report.endpointName}</CardTitle>
                      <p className="text-sm text-muted-foreground">
                        Report ID: {report.id} • {report.scanDate.toLocaleDateString()}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Badge className={getSeverityColor(report.severity)}>
                      {report.severity.toUpperCase()}
                    </Badge>
                    <Badge className={getStatusColor(report.status)}>
                      {report.status.replace('_', ' ').toUpperCase()}
                    </Badge>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div className="space-y-1">
                      <p className="text-sm font-medium">Report Type</p>
                      <p className="text-sm text-muted-foreground capitalize">
                        {report.reportType.replace('_', ' ')}
                      </p>
                    </div>
                    <div className="space-y-1">
                      <p className="text-sm font-medium">Vulnerabilities Found</p>
                      <p className="text-sm text-muted-foreground">
                        {report.vulnerabilitiesFound} issues
                      </p>
                    </div>
                    <div className="space-y-1">
                      <p className="text-sm font-medium">Platform</p>
                      <p className="text-sm text-muted-foreground capitalize">
                        {report.platform}
                      </p>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <p className="text-sm font-medium">Executive Summary</p>
                    <p className="text-sm text-muted-foreground">
                      {report.executiveSummary.substring(0, 150)}...
                    </p>
                  </div>

                  <div className="flex justify-between items-center pt-4 border-t">
                    <div className="flex space-x-2">
                      <Dialog>
                        <DialogTrigger asChild>
                          <Button 
                            size="sm" 
                            variant="outline"
                            onClick={() => setSelectedReport(report)}
                          >
                            <Eye className="h-4 w-4 mr-1" />
                            View Details
                          </Button>
                        </DialogTrigger>
                        <DialogContent className="max-w-4xl max-h-[80vh]">
                          <DialogHeader>
                            <DialogTitle>
                              VAPT Report - {selectedReport?.endpointName}
                            </DialogTitle>
                          </DialogHeader>
                          <ScrollArea className="h-[60vh]">
                            {selectedReport && (
                              <div className="space-y-6 pr-4">
                                <div className="grid grid-cols-2 gap-4">
                                  <div>
                                    <h4 className="font-semibold mb-2">Report Information</h4>
                                    <div className="space-y-1 text-sm">
                                      <p><strong>ID:</strong> {selectedReport.id}</p>
                                      <p><strong>Platform:</strong> {selectedReport.platform}</p>
                                      <p><strong>Date:</strong> {selectedReport.scanDate.toLocaleDateString()}</p>
                                      <p><strong>Type:</strong> {selectedReport.reportType.replace('_', ' ')}</p>
                                    </div>
                                  </div>
                                  <div>
                                    <h4 className="font-semibold mb-2">Summary</h4>
                                    <div className="space-y-1 text-sm">
                                      <p><strong>Vulnerabilities:</strong> {selectedReport.vulnerabilitiesFound}</p>
                                      <p><strong>Severity:</strong> 
                                        <Badge className={`ml-2 ${getSeverityColor(selectedReport.severity)}`}>
                                          {selectedReport.severity}
                                        </Badge>
                                      </p>
                                      <p><strong>Status:</strong> 
                                        <Badge className={`ml-2 ${getStatusColor(selectedReport.status)}`}>
                                          {selectedReport.status}
                                        </Badge>
                                      </p>
                                    </div>
                                  </div>
                                </div>

                                <div>
                                  <h4 className="font-semibold mb-2">Executive Summary</h4>
                                  <p className="text-sm text-muted-foreground">
                                    {selectedReport.executiveSummary}
                                  </p>
                                </div>

                                <div>
                                  <h4 className="font-semibold mb-2">Detailed Findings</h4>
                                  <div className="space-y-4">
                                    {selectedReport.detailedFindings.map((finding, index) => (
                                      <Card key={index}>
                                        <CardContent className="p-4">
                                          <div className="flex items-center justify-between mb-2">
                                            <h5 className="font-medium">{finding.title}</h5>
                                            <div className="flex items-center space-x-2">
                                              <Badge className={getSeverityColor(finding.severity)}>
                                                {finding.severity}
                                              </Badge>
                                              <Badge variant="outline">
                                                CVSS: {finding.cvss}
                                              </Badge>
                                            </div>
                                          </div>
                                          <div className="space-y-2 text-sm">
                                            <p><strong>Description:</strong> {finding.description}</p>
                                            <p><strong>Impact:</strong> {finding.impact}</p>
                                            <p><strong>Remediation:</strong> {finding.remediation}</p>
                                          </div>
                                        </CardContent>
                                      </Card>
                                    ))}
                                  </div>
                                </div>

                                <div>
                                  <h4 className="font-semibold mb-2">Compliance Results</h4>
                                  <div className="grid gap-4">
                                    {selectedReport.complianceResults.map((compliance, index) => (
                                      <div key={index} className="flex items-center justify-between p-3 border rounded">
                                        <div>
                                          <p className="font-medium">{compliance.framework}</p>
                                          <p className="text-sm text-muted-foreground">
                                            {compliance.passed} passed, {compliance.failed} failed
                                          </p>
                                        </div>
                                        <div className="text-right">
                                          <p className="text-2xl font-bold">{compliance.score}%</p>
                                          <p className="text-xs text-muted-foreground">Compliance Score</p>
                                        </div>
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              </div>
                            )}
                          </ScrollArea>
                        </DialogContent>
                      </Dialog>
                      <Button size="sm" onClick={() => downloadReport(report)}>
                        <Download className="h-4 w-4 mr-1" />
                        Download
                      </Button>
                    </div>
                    <div className="flex items-center text-sm text-muted-foreground">
                      <Calendar className="h-4 w-4 mr-1" />
                      {report.scanDate.toLocaleDateString()}
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {filteredReports.length === 0 && (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <FileText className="h-12 w-12 text-muted-foreground mb-4" />
            <h3 className="text-lg font-medium mb-2">No Reports Found</h3>
            <p className="text-muted-foreground text-center">
              {searchTerm || filterPlatform !== "all" || filterSeverity !== "all" 
                ? "Try adjusting your filters to see more results"
                : "VAPT reports will appear here once endpoint scans are completed"
              }
            </p>
          </CardContent>
        </Card>
      )}
    </div>
  );
};

export default VAPTReports;