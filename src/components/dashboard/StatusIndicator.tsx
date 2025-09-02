import { Badge } from "@/components/ui/badge";
import { AlertCircle, CheckCircle, Wifi, WifiOff } from "lucide-react";
import { useKaliTools } from "@/hooks/useKaliTools";

const StatusIndicator = () => {
  const { isKaliEnvironment, isDemoMode, isLoading } = useKaliTools();

  if (isLoading) {
    return (
      <Badge variant="secondary" className="flex items-center gap-2">
        <div className="w-2 h-2 bg-muted-foreground rounded-full animate-pulse" />
        Checking Environment
      </Badge>
    );
  }

  if (isDemoMode) {
    return (
      <Badge variant="outline" className="flex items-center gap-2 text-orange-600 border-orange-600">
        <WifiOff className="w-3 h-3" />
        Demo Mode
      </Badge>
    );
  }

  if (isKaliEnvironment) {
    return (
      <Badge variant="default" className="flex items-center gap-2 bg-green-600 hover:bg-green-700">
        <CheckCircle className="w-3 h-3" />
        Kali Linux
      </Badge>
    );
  }

  return (
    <Badge variant="destructive" className="flex items-center gap-2">
      <AlertCircle className="w-3 h-3" />
      Limited Mode
    </Badge>
  );
};

export default StatusIndicator;