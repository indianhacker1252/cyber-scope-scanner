import { useState } from "react";
import { Shield, Settings, User, Activity } from "lucide-react";
import { Button } from "@/components/ui/button";
import ProfileDialog from "./ProfileDialog";
import SettingsDialog from "./SettingsDialog";
import StatusIndicator from "./StatusIndicator";
import DiagnosticsDialog from "./DiagnosticsDialog";

const Header = () => {
  const [profileOpen, setProfileOpen] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [diagOpen, setDiagOpen] = useState(false);

  return (
    <>
      <ProfileDialog open={profileOpen} onOpenChange={setProfileOpen} />
      <SettingsDialog open={settingsOpen} onOpenChange={setSettingsOpen} />
      <DiagnosticsDialog open={diagOpen} onOpenChange={setDiagOpen} />
    <header className="bg-card border-b border-border px-6 py-4 flex items-center justify-between">
      <div className="flex items-center space-x-4">
        <div className="flex items-center space-x-2">
          <Shield className="h-8 w-8 text-primary" />
          <div>
            <h1 className="text-2xl font-bold bg-gradient-to-r from-primary to-primary-glow bg-clip-text text-transparent">
              VAPT Arsenal
            </h1>
            <p className="text-sm text-muted-foreground">Vulnerability Assessment & Penetration Testing</p>
          </div>
        </div>
      </div>
      
      <div className="flex items-center space-x-2">
        <StatusIndicator />
        <Button variant="ghost" size="sm" onClick={() => setDiagOpen(true)}>
          <Activity className="h-4 w-4" />
        </Button>
        <Button variant="ghost" size="sm" onClick={() => setSettingsOpen(true)}>
          <Settings className="h-4 w-4" />
        </Button>
        <Button variant="ghost" size="sm" onClick={() => setProfileOpen(true)}>
          <User className="h-4 w-4" />
        </Button>
      </div>
      </header>
    </>
  );
};

export default Header;