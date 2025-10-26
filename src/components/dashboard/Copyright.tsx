/**
 * VAPT Security Scanner - Copyright Notice
 * Copyright (c) 2024 Harsh Malik - All Rights Reserved
 */

import { Shield } from "lucide-react";

export const Copyright = () => {
  return (
    <div className="fixed bottom-4 right-4 z-50">
      <div className="bg-card/95 backdrop-blur-sm border rounded-lg shadow-lg px-4 py-2">
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <Shield className="h-3 w-3" />
          <span>© 2024 <strong className="text-foreground">Harsh Malik</strong> - All Rights Reserved</span>
        </div>
      </div>
    </div>
  );
};
