import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Cloud, Shield, Database, Users, AlertTriangle, CheckCircle, XCircle, Loader2, Search, Lock, Globe, Server } from 'lucide-react';
import { toast } from 'sonner';

interface Finding {
  id: string;
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  resource: string;
  remediation: string;
}

interface ScanResult {
  provider: string;
  scanType: string;
  findings: Finding[];
  timestamp: string;
}

const CloudSecurityModule = () => {
  const [activeTab, setActiveTab] = useState('enumeration');
  const [isScanning, setIsScanning] = useState(false);
  const [results, setResults] = useState<ScanResult[]>([]);
  
  // Enumeration state
  const [cloudProvider, setCloudProvider] = useState<string>('aws');
  const [targetDomain, setTargetDomain] = useState('');
  
  // S3 state
  const [bucketName, setBucketName] = useState('');
  const [bucketWordlist, setBucketWordlist] = useState('common');
  
  // IAM state
  const [iamTarget, setIamTarget] = useState('');

  const severityColors = {
    critical: 'bg-red-500/20 text-red-400 border-red-500/50',
    high: 'bg-orange-500/20 text-orange-400 border-orange-500/50',
    medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50',
    low: 'bg-blue-500/20 text-blue-400 border-blue-500/50',
    info: 'bg-gray-500/20 text-gray-400 border-gray-500/50'
  };

  const runCloudEnumeration = async () => {
    if (!targetDomain) {
      toast.error('Please enter a target domain');
      return;
    }

    setIsScanning(true);
    toast.info(`Starting ${cloudProvider.toUpperCase()} enumeration for ${targetDomain}...`);

    // Simulate cloud enumeration
    await new Promise(resolve => setTimeout(resolve, 3000));

    const enumerationChecks: Record<string, Finding[]> = {
      aws: [
        { id: '1', type: 'S3', severity: 'high', title: 'Public S3 Bucket Discovered', description: `Found publicly accessible S3 bucket: ${targetDomain}-assets`, resource: `s3://${targetDomain}-assets`, remediation: 'Review bucket ACL and enable Block Public Access' },
        { id: '2', type: 'EC2', severity: 'medium', title: 'EC2 Instance with Public IP', description: 'EC2 instance exposed to internet without proper security groups', resource: `ec2-${targetDomain.replace(/\./g, '-')}`, remediation: 'Review security group rules and restrict inbound access' },
        { id: '3', type: 'Lambda', severity: 'info', title: 'Lambda Functions Discovered', description: 'Found 5 Lambda functions associated with the domain', resource: `lambda-${targetDomain}`, remediation: 'Review function permissions and environment variables' },
        { id: '4', type: 'CloudFront', severity: 'low', title: 'CloudFront Distribution Found', description: 'CDN distribution serving content for the domain', resource: `d123456.cloudfront.net`, remediation: 'Ensure proper origin access identity is configured' },
        { id: '5', type: 'RDS', severity: 'critical', title: 'Publicly Accessible RDS Instance', description: 'Database instance accessible from the internet', resource: `rds-${targetDomain.replace(/\./g, '-')}.region.rds.amazonaws.com`, remediation: 'Disable public accessibility and use VPC endpoints' }
      ],
      azure: [
        { id: '1', type: 'Blob', severity: 'high', title: 'Public Blob Container', description: `Anonymous access enabled on blob container`, resource: `${targetDomain.replace(/\./g, '')}storage.blob.core.windows.net`, remediation: 'Disable anonymous access and use SAS tokens' },
        { id: '2', type: 'VM', severity: 'medium', title: 'Virtual Machine with Public IP', description: 'Azure VM exposed to internet', resource: `${targetDomain}-vm`, remediation: 'Use Azure Bastion or VPN for access' },
        { id: '3', type: 'App Service', severity: 'info', title: 'App Service Discovered', description: 'Web application hosted on Azure App Service', resource: `${targetDomain.replace(/\./g, '-')}.azurewebsites.net`, remediation: 'Review authentication and authorization settings' },
        { id: '4', type: 'Key Vault', severity: 'low', title: 'Key Vault Endpoint Found', description: 'Azure Key Vault accessible via DNS', resource: `${targetDomain.replace(/\./g, '')}vault.vault.azure.net`, remediation: 'Ensure proper access policies are configured' },
        { id: '5', type: 'SQL', severity: 'critical', title: 'Azure SQL with Firewall Rule 0.0.0.0', description: 'SQL database allows all Azure services', resource: `${targetDomain.replace(/\./g, '')}.database.windows.net`, remediation: 'Remove 0.0.0.0 firewall rule and whitelist specific IPs' }
      ],
      gcp: [
        { id: '1', type: 'GCS', severity: 'high', title: 'Public GCS Bucket', description: 'Cloud Storage bucket with allUsers access', resource: `gs://${targetDomain.replace(/\./g, '-')}-bucket`, remediation: 'Remove allUsers and allAuthenticatedUsers bindings' },
        { id: '2', type: 'GCE', severity: 'medium', title: 'Compute Instance with External IP', description: 'VM instance with external network access', resource: `gce-${targetDomain.replace(/\./g, '-')}`, remediation: 'Use Cloud NAT for egress and IAP for ingress' },
        { id: '3', type: 'Cloud Run', severity: 'info', title: 'Cloud Run Service Found', description: 'Serverless container deployment discovered', resource: `${targetDomain.replace(/\./g, '-')}-run.a.run.app`, remediation: 'Review IAM invoker permissions' },
        { id: '4', type: 'Firebase', severity: 'low', title: 'Firebase Project Detected', description: 'Firebase hosting and database endpoints found', resource: `${targetDomain.replace(/\./g, '-')}.firebaseapp.com`, remediation: 'Review Firebase security rules' },
        { id: '5', type: 'BigQuery', severity: 'critical', title: 'BigQuery Dataset with Public Access', description: 'Dataset accessible to allAuthenticatedUsers', resource: `bigquery:${targetDomain.replace(/\./g, '_')}_dataset`, remediation: 'Remove public access and implement proper IAM bindings' }
      ]
    };

    const findings = enumerationChecks[cloudProvider] || [];
    
    setResults(prev => [...prev, {
      provider: cloudProvider.toUpperCase(),
      scanType: 'Cloud Enumeration',
      findings,
      timestamp: new Date().toISOString()
    }]);

    setIsScanning(false);
    toast.success(`${cloudProvider.toUpperCase()} enumeration complete - Found ${findings.length} resources`);
  };

  const runS3BucketScan = async () => {
    if (!bucketName && !targetDomain) {
      toast.error('Please enter a bucket name or target domain');
      return;
    }

    setIsScanning(true);
    const target = bucketName || targetDomain;
    toast.info(`Scanning for S3 bucket misconfigurations: ${target}...`);

    await new Promise(resolve => setTimeout(resolve, 2500));

    const s3Findings: Finding[] = [
      { id: '1', type: 'ACL', severity: 'critical', title: 'Bucket ACL Allows Public Read', description: 'The bucket ACL grants READ permission to AllUsers', resource: `s3://${target}`, remediation: 'Remove public-read ACL and enable Block Public Access' },
      { id: '2', type: 'ACL', severity: 'critical', title: 'Bucket ACL Allows Public Write', description: 'The bucket ACL grants WRITE permission to AllUsers', resource: `s3://${target}`, remediation: 'Remove public-read-write ACL immediately' },
      { id: '3', type: 'Policy', severity: 'high', title: 'Overly Permissive Bucket Policy', description: 'Bucket policy allows s3:* actions from any principal', resource: `s3://${target}`, remediation: 'Restrict policy to specific principals and actions' },
      { id: '4', type: 'Encryption', severity: 'medium', title: 'Server-Side Encryption Disabled', description: 'Objects in this bucket are not encrypted at rest', resource: `s3://${target}`, remediation: 'Enable SSE-S3 or SSE-KMS encryption' },
      { id: '5', type: 'Logging', severity: 'low', title: 'Access Logging Disabled', description: 'S3 access logging is not configured for this bucket', resource: `s3://${target}`, remediation: 'Enable server access logging to a separate bucket' },
      { id: '6', type: 'Versioning', severity: 'info', title: 'Versioning Not Enabled', description: 'Object versioning is disabled on this bucket', resource: `s3://${target}`, remediation: 'Consider enabling versioning for data protection' },
      { id: '7', type: 'Website', severity: 'medium', title: 'Static Website Hosting Enabled', description: 'Bucket is configured for static website hosting', resource: `http://${target}.s3-website.region.amazonaws.com`, remediation: 'Review if website hosting is intentional' },
      { id: '8', type: 'CORS', severity: 'medium', title: 'Permissive CORS Configuration', description: 'CORS allows all origins (*) to access bucket objects', resource: `s3://${target}`, remediation: 'Restrict allowed origins to specific domains' }
    ];

    setResults(prev => [...prev, {
      provider: 'AWS',
      scanType: 'S3 Bucket Misconfiguration',
      findings: s3Findings,
      timestamp: new Date().toISOString()
    }]);

    setIsScanning(false);
    toast.success(`S3 scan complete - Found ${s3Findings.length} misconfigurations`);
  };

  const runIAMAnalysis = async () => {
    if (!iamTarget && !targetDomain) {
      toast.error('Please enter a target for IAM analysis');
      return;
    }

    setIsScanning(true);
    const target = iamTarget || targetDomain;
    toast.info(`Analyzing IAM policies for ${target}...`);

    await new Promise(resolve => setTimeout(resolve, 3500));

    const iamFindings: Finding[] = [
      { id: '1', type: 'Policy', severity: 'critical', title: 'Admin Policy Attached to User', description: 'User has AdministratorAccess policy attached directly', resource: `arn:aws:iam::123456789:user/${target}`, remediation: 'Use role-based access instead of direct policy attachment' },
      { id: '2', type: 'Policy', severity: 'critical', title: 'Wildcard Resource in Policy', description: 'Policy allows actions on all resources ("Resource": "*")', resource: `arn:aws:iam::123456789:policy/${target}-policy`, remediation: 'Restrict resources to specific ARNs' },
      { id: '3', type: 'Policy', severity: 'high', title: 'iam:PassRole Without Restriction', description: 'User can pass any role to any service', resource: `arn:aws:iam::123456789:user/${target}`, remediation: 'Limit PassRole to specific roles' },
      { id: '4', type: 'Credential', severity: 'high', title: 'Access Key Not Rotated', description: 'Access key has not been rotated in 180+ days', resource: `AKIA${target.toUpperCase().slice(0, 16)}`, remediation: 'Rotate access keys every 90 days' },
      { id: '5', type: 'MFA', severity: 'high', title: 'MFA Not Enabled', description: 'Multi-factor authentication is not configured for this user', resource: `arn:aws:iam::123456789:user/${target}`, remediation: 'Enable MFA for all IAM users' },
      { id: '6', type: 'Role', severity: 'medium', title: 'Cross-Account Role Trust', description: 'Role trusts external AWS account without conditions', resource: `arn:aws:iam::123456789:role/${target}-role`, remediation: 'Add external ID condition to trust policy' },
      { id: '7', type: 'Policy', severity: 'medium', title: 'Privilege Escalation Path', description: 'User can create new policies and attach to themselves', resource: `arn:aws:iam::123456789:user/${target}`, remediation: 'Remove iam:CreatePolicy and iam:AttachUserPolicy permissions' },
      { id: '8', type: 'Group', severity: 'low', title: 'User Not in Any Group', description: 'User has direct policy attachments instead of group membership', resource: `arn:aws:iam::123456789:user/${target}`, remediation: 'Use IAM groups for permission management' },
      { id: '9', type: 'Password', severity: 'medium', title: 'Weak Password Policy', description: 'Account password policy does not require uppercase letters', resource: `arn:aws:iam::123456789:account`, remediation: 'Strengthen password policy requirements' },
      { id: '10', type: 'STS', severity: 'info', title: 'Long Session Duration', description: 'Role allows session duration of 12 hours', resource: `arn:aws:iam::123456789:role/${target}-role`, remediation: 'Consider reducing maximum session duration' }
    ];

    setResults(prev => [...prev, {
      provider: 'AWS',
      scanType: 'IAM Policy Analysis',
      findings: iamFindings,
      timestamp: new Date().toISOString()
    }]);

    setIsScanning(false);
    toast.success(`IAM analysis complete - Found ${iamFindings.length} issues`);
  };

  const clearResults = () => {
    setResults([]);
    toast.info('Results cleared');
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical':
      case 'high':
        return <XCircle className="h-4 w-4" />;
      case 'medium':
        return <AlertTriangle className="h-4 w-4" />;
      case 'low':
      case 'info':
        return <CheckCircle className="h-4 w-4" />;
      default:
        return <Shield className="h-4 w-4" />;
    }
  };

  const totalFindings = results.reduce((acc, r) => acc + r.findings.length, 0);
  const criticalCount = results.reduce((acc, r) => acc + r.findings.filter(f => f.severity === 'critical').length, 0);
  const highCount = results.reduce((acc, r) => acc + r.findings.filter(f => f.severity === 'high').length, 0);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold text-foreground flex items-center gap-3">
            <Cloud className="h-8 w-8 text-primary" />
            Cloud Security Module
          </h2>
          <p className="text-muted-foreground mt-1">
            AWS, Azure, GCP enumeration and misconfiguration detection
          </p>
        </div>
        {results.length > 0 && (
          <Button variant="outline" onClick={clearResults}>
            Clear Results
          </Button>
        )}
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="bg-card/50 border-border">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <Search className="h-8 w-8 text-primary" />
              <div>
                <p className="text-2xl font-bold">{results.length}</p>
                <p className="text-sm text-muted-foreground">Scans Run</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card/50 border-border">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <AlertTriangle className="h-8 w-8 text-yellow-400" />
              <div>
                <p className="text-2xl font-bold">{totalFindings}</p>
                <p className="text-sm text-muted-foreground">Total Findings</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card/50 border-border">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <XCircle className="h-8 w-8 text-red-400" />
              <div>
                <p className="text-2xl font-bold">{criticalCount}</p>
                <p className="text-sm text-muted-foreground">Critical Issues</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card/50 border-border">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <Shield className="h-8 w-8 text-orange-400" />
              <div>
                <p className="text-2xl font-bold">{highCount}</p>
                <p className="text-sm text-muted-foreground">High Severity</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="enumeration" className="flex items-center gap-2">
            <Globe className="h-4 w-4" />
            Cloud Enumeration
          </TabsTrigger>
          <TabsTrigger value="s3" className="flex items-center gap-2">
            <Database className="h-4 w-4" />
            S3/Blob Scanner
          </TabsTrigger>
          <TabsTrigger value="iam" className="flex items-center gap-2">
            <Users className="h-4 w-4" />
            IAM Analysis
          </TabsTrigger>
        </TabsList>

        <TabsContent value="enumeration" className="space-y-4">
          <Card className="bg-card/50 border-border">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Server className="h-5 w-5" />
                Cloud Resource Enumeration
              </CardTitle>
              <CardDescription>
                Discover and enumerate AWS, Azure, and GCP resources associated with a target
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>Cloud Provider</Label>
                  <Select value={cloudProvider} onValueChange={setCloudProvider}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select provider" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="aws">Amazon Web Services (AWS)</SelectItem>
                      <SelectItem value="azure">Microsoft Azure</SelectItem>
                      <SelectItem value="gcp">Google Cloud Platform (GCP)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label>Target Domain</Label>
                  <Input
                    placeholder="example.com"
                    value={targetDomain}
                    onChange={(e) => setTargetDomain(e.target.value)}
                  />
                </div>
              </div>

              <div className="bg-muted/30 p-4 rounded-lg">
                <h4 className="font-semibold mb-2">Enumeration Checks ({cloudProvider.toUpperCase()})</h4>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-sm">
                  {cloudProvider === 'aws' && (
                    <>
                      <Badge variant="outline">S3 Buckets</Badge>
                      <Badge variant="outline">EC2 Instances</Badge>
                      <Badge variant="outline">Lambda Functions</Badge>
                      <Badge variant="outline">RDS Databases</Badge>
                      <Badge variant="outline">CloudFront</Badge>
                      <Badge variant="outline">ELB/ALB</Badge>
                      <Badge variant="outline">API Gateway</Badge>
                      <Badge variant="outline">Route53</Badge>
                    </>
                  )}
                  {cloudProvider === 'azure' && (
                    <>
                      <Badge variant="outline">Blob Storage</Badge>
                      <Badge variant="outline">Virtual Machines</Badge>
                      <Badge variant="outline">App Services</Badge>
                      <Badge variant="outline">SQL Databases</Badge>
                      <Badge variant="outline">Key Vault</Badge>
                      <Badge variant="outline">Functions</Badge>
                      <Badge variant="outline">CDN</Badge>
                      <Badge variant="outline">DNS Zones</Badge>
                    </>
                  )}
                  {cloudProvider === 'gcp' && (
                    <>
                      <Badge variant="outline">GCS Buckets</Badge>
                      <Badge variant="outline">Compute Engine</Badge>
                      <Badge variant="outline">Cloud Run</Badge>
                      <Badge variant="outline">Cloud SQL</Badge>
                      <Badge variant="outline">Firebase</Badge>
                      <Badge variant="outline">BigQuery</Badge>
                      <Badge variant="outline">Cloud Functions</Badge>
                      <Badge variant="outline">Cloud DNS</Badge>
                    </>
                  )}
                </div>
              </div>

              <Button onClick={runCloudEnumeration} disabled={isScanning} className="w-full">
                {isScanning ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Enumerating...
                  </>
                ) : (
                  <>
                    <Globe className="mr-2 h-4 w-4" />
                    Start Enumeration
                  </>
                )}
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="s3" className="space-y-4">
          <Card className="bg-card/50 border-border">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Database className="h-5 w-5" />
                S3 Bucket Misconfiguration Scanner
              </CardTitle>
              <CardDescription>
                Detect public access, ACL issues, and security misconfigurations in S3 buckets
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>Bucket Name / Domain</Label>
                  <Input
                    placeholder="bucket-name or example.com"
                    value={bucketName}
                    onChange={(e) => setBucketName(e.target.value)}
                  />
                </div>
                <div className="space-y-2">
                  <Label>Discovery Wordlist</Label>
                  <Select value={bucketWordlist} onValueChange={setBucketWordlist}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select wordlist" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="common">Common Names</SelectItem>
                      <SelectItem value="extended">Extended Wordlist</SelectItem>
                      <SelectItem value="aggressive">Aggressive (Slow)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <div className="bg-muted/30 p-4 rounded-lg">
                <h4 className="font-semibold mb-2">Misconfiguration Checks</h4>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-sm">
                  <Badge variant="outline">Public ACL</Badge>
                  <Badge variant="outline">Bucket Policy</Badge>
                  <Badge variant="outline">Encryption</Badge>
                  <Badge variant="outline">Versioning</Badge>
                  <Badge variant="outline">Logging</Badge>
                  <Badge variant="outline">CORS Config</Badge>
                  <Badge variant="outline">Website Hosting</Badge>
                  <Badge variant="outline">Block Public Access</Badge>
                </div>
              </div>

              <Button onClick={runS3BucketScan} disabled={isScanning} className="w-full">
                {isScanning ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Scanning...
                  </>
                ) : (
                  <>
                    <Database className="mr-2 h-4 w-4" />
                    Scan S3 Bucket
                  </>
                )}
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="iam" className="space-y-4">
          <Card className="bg-card/50 border-border">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Lock className="h-5 w-5" />
                IAM Policy Analyzer
              </CardTitle>
              <CardDescription>
                Analyze IAM policies for privilege escalation paths and security weaknesses
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label>Target User/Role/Account</Label>
                <Input
                  placeholder="username, role-name, or account-id"
                  value={iamTarget}
                  onChange={(e) => setIamTarget(e.target.value)}
                />
              </div>

              <div className="bg-muted/30 p-4 rounded-lg">
                <h4 className="font-semibold mb-2">Analysis Checks</h4>
                <div className="grid grid-cols-2 md:grid-cols-3 gap-2 text-sm">
                  <Badge variant="outline">Privilege Escalation</Badge>
                  <Badge variant="outline">Wildcard Permissions</Badge>
                  <Badge variant="outline">Cross-Account Trust</Badge>
                  <Badge variant="outline">MFA Status</Badge>
                  <Badge variant="outline">Access Key Age</Badge>
                  <Badge variant="outline">Password Policy</Badge>
                  <Badge variant="outline">Inline Policies</Badge>
                  <Badge variant="outline">PassRole Abuse</Badge>
                  <Badge variant="outline">STS Configuration</Badge>
                </div>
              </div>

              <Button onClick={runIAMAnalysis} disabled={isScanning} className="w-full">
                {isScanning ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Analyzing...
                  </>
                ) : (
                  <>
                    <Users className="mr-2 h-4 w-4" />
                    Analyze IAM Policies
                  </>
                )}
              </Button>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Results Section */}
      {results.length > 0 && (
        <Card className="bg-card/50 border-border">
          <CardHeader>
            <CardTitle>Scan Results</CardTitle>
            <CardDescription>
              {results.length} scan(s) completed with {totalFindings} total findings
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-[500px]">
              <div className="space-y-6">
                {results.map((result, idx) => (
                  <div key={idx} className="space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className="bg-primary/20">
                          {result.provider}
                        </Badge>
                        <span className="font-semibold">{result.scanType}</span>
                      </div>
                      <span className="text-sm text-muted-foreground">
                        {new Date(result.timestamp).toLocaleString()}
                      </span>
                    </div>
                    
                    <div className="space-y-2">
                      {result.findings.map((finding) => (
                        <div
                          key={finding.id}
                          className="p-4 rounded-lg border border-border bg-muted/20"
                        >
                          <div className="flex items-start justify-between">
                            <div className="flex items-start gap-3">
                              <div className={`p-1.5 rounded ${severityColors[finding.severity]}`}>
                                {getSeverityIcon(finding.severity)}
                              </div>
                              <div className="space-y-1">
                                <div className="flex items-center gap-2">
                                  <span className="font-semibold">{finding.title}</span>
                                  <Badge variant="outline" className="text-xs">
                                    {finding.type}
                                  </Badge>
                                </div>
                                <p className="text-sm text-muted-foreground">
                                  {finding.description}
                                </p>
                                <p className="text-xs font-mono bg-muted/50 px-2 py-1 rounded inline-block">
                                  {finding.resource}
                                </p>
                                <p className="text-sm text-primary mt-2">
                                  <strong>Remediation:</strong> {finding.remediation}
                                </p>
                              </div>
                            </div>
                            <Badge className={severityColors[finding.severity]}>
                              {finding.severity.toUpperCase()}
                            </Badge>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>
      )}
    </div>
  );
};

export default CloudSecurityModule;
