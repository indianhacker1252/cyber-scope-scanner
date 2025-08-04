import { useState, useEffect } from "react";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Separator } from "@/components/ui/separator";
import { Settings, Shield, Bell, Database, Network, Key } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import openaiService from "@/utils/openaiService";

interface SettingsDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

const SettingsDialog = ({ open, onOpenChange }: SettingsDialogProps) => {
  const { toast } = useToast();
  const [settings, setSettings] = useState({
    // General Settings
    autoSave: true,
    darkMode: false,
    notifications: true,
    soundEffects: false,
    
    // Scanning Settings
    maxConcurrentScans: 5,
    scanTimeout: 300,
    verboseLogging: true,
    saveRawOutput: true,
    
    // API Settings
    openaiApiKey: "",
    scanHistoryLimit: 100,
    reportFormat: "pdf",
    
    // Security Settings
    sessionTimeout: 30,
    requireAuth: false,
    encryptReports: true
  });

  useEffect(() => {
    // Load settings from localStorage
    const savedSettings = localStorage.getItem('app_settings');
    if (savedSettings) {
      setSettings(JSON.parse(savedSettings));
    }
    
    // Load OpenAI API key
    const apiKey = openaiService.getApiKey();
    if (apiKey) {
      setSettings(prev => ({ ...prev, openaiApiKey: apiKey }));
    }
  }, []);

  const handleSave = () => {
    // Save general settings
    localStorage.setItem('app_settings', JSON.stringify(settings));
    
    // Save OpenAI API key
    if (settings.openaiApiKey) {
      openaiService.setApiKey(settings.openaiApiKey);
    }
    
    toast({
      title: "Settings Saved",
      description: "Your settings have been saved successfully."
    });
  };

  const handleReset = () => {
    // Reset to defaults
    const defaultSettings = {
      autoSave: true,
      darkMode: false,
      notifications: true,
      soundEffects: false,
      maxConcurrentScans: 5,
      scanTimeout: 300,
      verboseLogging: true,
      saveRawOutput: true,
      openaiApiKey: "",
      scanHistoryLimit: 100,
      reportFormat: "pdf",
      sessionTimeout: 30,
      requireAuth: false,
      encryptReports: true
    };
    
    setSettings(defaultSettings);
    localStorage.removeItem('app_settings');
    openaiService.clearApiKey();
    
    toast({
      title: "Settings Reset",
      description: "All settings have been reset to defaults."
    });
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Settings className="h-5 w-5" />
            Application Settings
          </DialogTitle>
          <DialogDescription>
            Configure your application preferences and security settings.
          </DialogDescription>
        </DialogHeader>

        <Tabs defaultValue="general" className="w-full">
          <TabsList className="grid w-full grid-cols-4">
            <TabsTrigger value="general">General</TabsTrigger>
            <TabsTrigger value="scanning">Scanning</TabsTrigger>
            <TabsTrigger value="api">API & AI</TabsTrigger>
            <TabsTrigger value="security">Security</TabsTrigger>
          </TabsList>

          <TabsContent value="general" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>General Preferences</CardTitle>
                <CardDescription>Basic application settings and preferences.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label>Auto-save results</Label>
                    <p className="text-sm text-muted-foreground">
                      Automatically save scan results and reports
                    </p>
                  </div>
                  <Switch
                    checked={settings.autoSave}
                    onCheckedChange={(checked) => setSettings({...settings, autoSave: checked})}
                  />
                </div>
                
                <Separator />
                
                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label>Notifications</Label>
                    <p className="text-sm text-muted-foreground">
                      Show desktop notifications for scan completion
                    </p>
                  </div>
                  <Switch
                    checked={settings.notifications}
                    onCheckedChange={(checked) => setSettings({...settings, notifications: checked})}
                  />
                </div>
                
                <Separator />
                
                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label>Sound effects</Label>
                    <p className="text-sm text-muted-foreground">
                      Play sounds for scan events
                    </p>
                  </div>
                  <Switch
                    checked={settings.soundEffects}
                    onCheckedChange={(checked) => setSettings({...settings, soundEffects: checked})}
                  />
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="scanning" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Network className="h-5 w-5" />
                  Scanning Configuration
                </CardTitle>
                <CardDescription>Configure scanning behavior and performance settings.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="maxScans">Max Concurrent Scans</Label>
                    <Input
                      id="maxScans"
                      type="number"
                      min="1"
                      max="10"
                      value={settings.maxConcurrentScans}
                      onChange={(e) => setSettings({...settings, maxConcurrentScans: parseInt(e.target.value)})}
                    />
                  </div>
                  
                  <div className="space-y-2">
                    <Label htmlFor="timeout">Scan Timeout (seconds)</Label>
                    <Input
                      id="timeout"
                      type="number"
                      min="60"
                      max="3600"
                      value={settings.scanTimeout}
                      onChange={(e) => setSettings({...settings, scanTimeout: parseInt(e.target.value)})}
                    />
                  </div>
                </div>
                
                <Separator />
                
                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label>Verbose logging</Label>
                    <p className="text-sm text-muted-foreground">
                      Enable detailed logging for troubleshooting
                    </p>
                  </div>
                  <Switch
                    checked={settings.verboseLogging}
                    onCheckedChange={(checked) => setSettings({...settings, verboseLogging: checked})}
                  />
                </div>
                
                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label>Save raw output</Label>
                    <p className="text-sm text-muted-foreground">
                      Store complete tool output for analysis
                    </p>
                  </div>
                  <Switch
                    checked={settings.saveRawOutput}
                    onCheckedChange={(checked) => setSettings({...settings, saveRawOutput: checked})}
                  />
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="api" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Key className="h-5 w-5" />
                  API & AI Configuration
                </CardTitle>
                <CardDescription>Configure external API integrations and AI features.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="openaiKey">OpenAI API Key</Label>
                  <Input
                    id="openaiKey"
                    type="password"
                    placeholder="sk-..."
                    value={settings.openaiApiKey}
                    onChange={(e) => setSettings({...settings, openaiApiKey: e.target.value})}
                  />
                  <p className="text-sm text-muted-foreground">
                    Required for PentestGPT and AI-powered analysis features
                  </p>
                </div>
                
                <Separator />
                
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="historyLimit">Scan History Limit</Label>
                    <Input
                      id="historyLimit"
                      type="number"
                      min="10"
                      max="1000"
                      value={settings.scanHistoryLimit}
                      onChange={(e) => setSettings({...settings, scanHistoryLimit: parseInt(e.target.value)})}
                    />
                  </div>
                  
                  <div className="space-y-2">
                    <Label htmlFor="reportFormat">Default Report Format</Label>
                    <Select 
                      value={settings.reportFormat} 
                      onValueChange={(value) => setSettings({...settings, reportFormat: value})}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="pdf">PDF</SelectItem>
                        <SelectItem value="html">HTML</SelectItem>
                        <SelectItem value="json">JSON</SelectItem>
                        <SelectItem value="xml">XML</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="security" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Shield className="h-5 w-5" />
                  Security Settings
                </CardTitle>
                <CardDescription>Configure security and privacy settings.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="sessionTimeout">Session Timeout (minutes)</Label>
                  <Input
                    id="sessionTimeout"
                    type="number"
                    min="5"
                    max="120"
                    value={settings.sessionTimeout}
                    onChange={(e) => setSettings({...settings, sessionTimeout: parseInt(e.target.value)})}
                  />
                </div>
                
                <Separator />
                
                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label>Require authentication</Label>
                    <p className="text-sm text-muted-foreground">
                      Enable user authentication for access
                    </p>
                  </div>
                  <Switch
                    checked={settings.requireAuth}
                    onCheckedChange={(checked) => setSettings({...settings, requireAuth: checked})}
                  />
                </div>
                
                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label>Encrypt reports</Label>
                    <p className="text-sm text-muted-foreground">
                      Encrypt generated reports for security
                    </p>
                  </div>
                  <Switch
                    checked={settings.encryptReports}
                    onCheckedChange={(checked) => setSettings({...settings, encryptReports: checked})}
                  />
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>

        <div className="flex justify-between pt-4">
          <Button variant="outline" onClick={handleReset}>
            Reset to Defaults
          </Button>
          <div className="space-x-2">
            <Button variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button onClick={handleSave}>
              Save Settings
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
};

export default SettingsDialog;