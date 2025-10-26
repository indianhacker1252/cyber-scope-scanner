/**
 * VAPT Security Scanner - Status Indicator
 * Copyright (c) 2024 Harsh Malik - All Rights Reserved
 */

import { Badge } from "@/components/ui/badge";
import { CheckCircle, WifiOff, AlertCircle } from "lucide-react";
import { useKaliTools } from "@/hooks/useKaliTools";

const StatusIndicator = () => {
  const { isKaliEnvironment, isLoading } = useKaliTools();

  if (isLoading) {
    return (
      <Badge variant="secondary" className="flex items-center gap-2">
        <div className="w-2 h-2 bg-muted-foreground rounded-full animate-pulse" />
        Checking Backend...
      </Badge>
    );
  }

  if (isKaliEnvironment) {
    return (
      <Badge variant="default" className="flex items-center gap-2 bg-green-600 hover:bg-green-700">
        <CheckCircle className="w-3 h-3" />
        ✓ Kali Linux Active
      </Badge>
    );
  }

  return (
    <Badge variant="outline" className="flex items-center gap-2 text-destructive border-destructive animate-pulse">
      <WifiOff className="w-3 h-3" />
      ⚠️ Backend Offline
    </Badge>
  );
};

export default StatusIndicator;