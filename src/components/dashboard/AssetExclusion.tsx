import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Textarea } from "@/components/ui/textarea";
import { 
  Shield, 
  Plus, 
  Trash2, 
  Eye,
  EyeOff,
  AlertTriangle,
  Target,
  Globe,
  Server
} from "lucide-react";
import { useState } from "react";
import { useToast } from "@/hooks/use-toast";

const AssetExclusion = () => {
  const { toast } = useToast();
  const [excludedAssets, setExcludedAssets] = useState([
    {
      id: 1,
      type: "IP Range",
      value: "192.168.1.100-110",
      reason: "Production database servers",
      addedDate: "2024-01-15"
    },
    {
      id: 2,
      type: "Domain",
      value: "admin.example.com",
      reason: "Administrative interface - out of scope",
      addedDate: "2024-01-20"
    },
    {
      id: 3,
      type: "URL Path",
      value: "/payment/*",
      reason: "Payment processing - critical system",
      addedDate: "2024-01-25"
    }
  ]);

  const [newAsset, setNewAsset] = useState({
    type: "IP Address",
    value: "",
    reason: ""
  });

  const assetTypes = [
    { label: "IP Address", value: "IP Address", icon: Server },
    { label: "IP Range", value: "IP Range", icon: Server },
    { label: "Domain", value: "Domain", icon: Globe },
    { label: "Subdomain", value: "Subdomain", icon: Globe },
    { label: "URL Path", value: "URL Path", icon: Target },
    { label: "Port", value: "Port", icon: Shield }
  ];

  const addExclusion = () => {
    if (!newAsset.value || !newAsset.reason) {
      toast({
        title: "Missing Information",
        description: "Please provide both asset value and reason for exclusion",
        variant: "destructive"
      });
      return;
    }

    const asset = {
      id: Date.now(),
      type: newAsset.type,
      value: newAsset.value,
      reason: newAsset.reason,
      addedDate: new Date().toISOString().split('T')[0]
    };

    setExcludedAssets(prev => [...prev, asset]);
    setNewAsset({ type: "IP Address", value: "", reason: "" });
    
    toast({
      title: "Asset Excluded",
      description: `${newAsset.value} has been added to exclusion list`,
    });
  };

  const removeExclusion = (id: number) => {
    setExcludedAssets(prev => prev.filter(asset => asset.id !== id));
    toast({
      title: "Exclusion Removed",
      description: "Asset has been removed from exclusion list",
    });
  };

  const getTypeIcon = (type: string) => {
    const typeConfig = assetTypes.find(t => t.value === type);
    return typeConfig?.icon || Target;
  };

  const getTypeColor = (type: string) => {
    switch (type) {
      case "IP Address":
      case "IP Range":
        return "bg-blue-500/20 text-blue-700";
      case "Domain":
      case "Subdomain":
        return "bg-green-500/20 text-green-700";
      case "URL Path":
        return "bg-purple-500/20 text-purple-700";
      case "Port":
        return "bg-orange-500/20 text-orange-700";
      default:
        return "bg-muted text-muted-foreground";
    }
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <EyeOff className="h-5 w-5 mr-2 text-primary" />
            Asset Exclusion Management
          </CardTitle>
          <CardDescription>
            Manage assets to exclude from security scans to avoid testing critical or out-of-scope systems
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Add New Exclusion */}
          <Card className="bg-muted/30">
            <CardHeader>
              <CardTitle className="text-lg flex items-center">
                <Plus className="h-4 w-4 mr-2" />
                Add New Exclusion
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="asset-type">Asset Type</Label>
                  <select
                    id="asset-type"
                    className="w-full p-2 border rounded-md bg-background"
                    value={newAsset.type}
                    onChange={(e) => setNewAsset({...newAsset, type: e.target.value})}
                  >
                    {assetTypes.map(type => (
                      <option key={type.value} value={type.value}>
                        {type.label}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="asset-value">Asset Value</Label>
                  <Input
                    id="asset-value"
                    placeholder="e.g., 192.168.1.1, example.com, /admin/*"
                    value={newAsset.value}
                    onChange={(e) => setNewAsset({...newAsset, value: e.target.value})}
                  />
                </div>
              </div>
              <div className="space-y-2">
                <Label htmlFor="exclusion-reason">Reason for Exclusion</Label>
                <Textarea
                  id="exclusion-reason"
                  placeholder="Explain why this asset should be excluded from scans..."
                  value={newAsset.reason}
                  onChange={(e) => setNewAsset({...newAsset, reason: e.target.value})}
                  rows={3}
                />
              </div>
              <Button onClick={addExclusion}>
                <Plus className="h-4 w-4 mr-2" />
                Add Exclusion
              </Button>
            </CardContent>
          </Card>

          {/* Current Exclusions */}
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-semibold">Current Exclusions</h3>
              <Badge variant="secondary">{excludedAssets.length} excluded</Badge>
            </div>

            {excludedAssets.length === 0 ? (
              <Card>
                <CardContent className="p-8 text-center">
                  <Shield className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                  <p className="text-lg font-medium mb-2">No Exclusions Set</p>
                  <p className="text-muted-foreground">
                    Add assets to exclude them from security scans
                  </p>
                </CardContent>
              </Card>
            ) : (
              <div className="space-y-3">
                {excludedAssets.map((asset) => {
                  const TypeIcon = getTypeIcon(asset.type);
                  return (
                    <Card key={asset.id}>
                      <CardContent className="p-4">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center space-x-3">
                            <TypeIcon className="h-5 w-5 text-primary" />
                            <div className="flex-1">
                              <div className="flex items-center space-x-2 mb-1">
                                <span className="font-medium">{asset.value}</span>
                                <Badge className={getTypeColor(asset.type)} variant="secondary">
                                  {asset.type}
                                </Badge>
                              </div>
                              <p className="text-sm text-muted-foreground">{asset.reason}</p>
                              <p className="text-xs text-muted-foreground mt-1">
                                Added: {asset.addedDate}
                              </p>
                            </div>
                          </div>
                          <div className="flex items-center space-x-2">
                            <Button size="sm" variant="outline">
                              <Eye className="h-4 w-4" />
                            </Button>
                            <Button 
                              size="sm" 
                              variant="destructive" 
                              onClick={() => removeExclusion(asset.id)}
                            >
                              <Trash2 className="h-4 w-4" />
                            </Button>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  );
                })}
              </div>
            )}
          </div>

          {/* Warning Notice */}
          <Card className="border-warning bg-warning/5">
            <CardContent className="p-4">
              <div className="flex items-start space-x-3">
                <AlertTriangle className="h-5 w-5 text-warning mt-0.5" />
                <div>
                  <p className="font-medium text-warning">Important Notice</p>
                  <p className="text-sm text-muted-foreground mt-1">
                    Excluded assets will be completely skipped during all security scans. 
                    Ensure that exclusions are justified and documented for audit purposes.
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>
        </CardContent>
      </Card>
    </div>
  );
};

export default AssetExclusion;