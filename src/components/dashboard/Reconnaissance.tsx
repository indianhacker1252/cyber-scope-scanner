import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { 
  Search, 
  Globe, 
  Server, 
  FileText,
  Users,
  MapPin,
  Phone,
  Mail
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { useState } from "react";
import { useKaliTools } from "@/hooks/useKaliTools";

interface ReconnaissanceProps {
  onNavigateToResults?: () => void;
}

const Reconnaissance = ({ onNavigateToResults }: ReconnaissanceProps) => {
  const [domain, setDomain] = useState("");
  const { toast } = useToast();
  const { runWebScan } = useKaliTools();

  const handleDomainRecon = async () => {
    if (!domain) {
      toast({
        title: "Error",
        description: "Please enter a domain to investigate",
        variant: "destructive"
      });
      return;
    }

    try {
      await runWebScan(domain);
      
      toast({
        title: "Reconnaissance Started",
        description: `Starting OSINT gathering for ${domain}`,
      });

      if (onNavigateToResults) {
        setTimeout(() => onNavigateToResults(), 1000);
      }
    } catch (error) {
      toast({
        title: "Scan Failed",
        description: error instanceof Error ? error.message : "Failed to start reconnaissance",
        variant: "destructive"
      });
    }
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <Search className="h-5 w-5 mr-2 text-primary" />
            Reconnaissance & OSINT
          </CardTitle>
          <CardDescription>
            Gather intelligence about targets using open source intelligence
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="domain" className="w-full">
            <TabsList className="grid w-full grid-cols-4">
              <TabsTrigger value="domain">Domain Intel</TabsTrigger>
              <TabsTrigger value="subdomain">Subdomains</TabsTrigger>
              <TabsTrigger value="social">Social Media</TabsTrigger>
              <TabsTrigger value="metadata">Metadata</TabsTrigger>
            </TabsList>

            <TabsContent value="domain" className="space-y-4">
              <div className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="domain-input">Target Domain</Label>
                  <div className="flex space-x-2">
                    <Input
                      id="domain-input"
                      placeholder="example.com"
                      value={domain}
                      onChange={(e) => setDomain(e.target.value)}
                    />
                    <Button onClick={handleDomainRecon}>
                      <Search className="h-4 w-4 mr-2" />
                      Investigate
                    </Button>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  <Card className="cursor-pointer hover:bg-muted/50 transition-colors" onClick={() => {
                    toast({
                      title: "DNS Lookup Started",
                      description: `Gathering DNS records for ${domain}`,
                    });
                  }}>
                    <CardContent className="p-4">
                      <div className="flex items-center space-x-2">
                        <Server className="h-5 w-5 text-primary" />
                        <div>
                          <p className="font-medium">DNS Records</p>
                          <p className="text-sm text-muted-foreground">A, AAAA, MX, TXT, NS</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  <Card className="cursor-pointer hover:bg-muted/50 transition-colors" onClick={() => {
                    toast({
                      title: "WHOIS Lookup Started",
                      description: `Gathering registration details for ${domain}`,
                    });
                  }}>
                    <CardContent className="p-4">
                      <div className="flex items-center space-x-2">
                        <Globe className="h-5 w-5 text-primary" />
                        <div>
                          <p className="font-medium">WHOIS Info</p>
                          <p className="text-sm text-muted-foreground">Registration details</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  <Card className="cursor-pointer hover:bg-muted/50 transition-colors" onClick={() => {
                    toast({
                      title: "SSL Analysis Started",
                      description: `Analyzing SSL certificate for ${domain}`,
                    });
                  }}>
                    <CardContent className="p-4">
                      <div className="flex items-center space-x-2">
                        <FileText className="h-5 w-5 text-primary" />
                        <div>
                          <p className="font-medium">SSL Certificate</p>
                          <p className="text-sm text-muted-foreground">Certificate transparency</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </div>
              </div>
            </TabsContent>

            <TabsContent value="subdomain" className="space-y-4">
              <div className="text-center p-8">
                <Search className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                <p className="text-lg font-medium mb-2">Subdomain Enumeration</p>
                <p className="text-muted-foreground mb-4">
                  Discover subdomains using passive and active techniques
                </p>
                <Button onClick={() => {
                  toast({
                    title: "Subdomain Discovery Started",
                    description: `Enumerating subdomains for ${domain || 'target domain'}`,
                  });
                }}>
                  <Search className="h-4 w-4 mr-2" />
                  Start Subdomain Scan
                </Button>
              </div>
            </TabsContent>

            <TabsContent value="social" className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <Card className="cursor-pointer hover:bg-muted/50 transition-colors" onClick={() => {
                  toast({
                    title: "Social Media Intelligence",
                    description: "Gathering employee information from public sources",
                  });
                }}>
                  <CardContent className="p-4">
                    <div className="flex items-center space-x-2">
                      <Users className="h-5 w-5 text-primary" />
                      <div>
                        <p className="font-medium">Employee Search</p>
                        <p className="text-sm text-muted-foreground">LinkedIn, GitHub profiles</p>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                <Card className="cursor-pointer hover:bg-muted/50 transition-colors" onClick={() => {
                  toast({
                    title: "Email Harvesting Started",
                    description: "Searching for public email addresses",
                  });
                }}>
                  <CardContent className="p-4">
                    <div className="flex items-center space-x-2">
                      <Mail className="h-5 w-5 text-primary" />
                      <div>
                        <p className="font-medium">Email Harvesting</p>
                        <p className="text-sm text-muted-foreground">Public email addresses</p>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>

            <TabsContent value="metadata" className="space-y-4">
              <div className="text-center p-8">
                <FileText className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                <p className="text-lg font-medium mb-2">Metadata Analysis</p>
                <p className="text-muted-foreground mb-4">
                  Extract metadata from documents and files
                </p>
                <Button onClick={() => {
                  toast({
                    title: "Metadata Extraction Started",
                    description: "Analyzing documents for metadata",
                  });
                }}>
                  <FileText className="h-4 w-4 mr-2" />
                  Analyze Metadata
                </Button>
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
};

export default Reconnaissance;