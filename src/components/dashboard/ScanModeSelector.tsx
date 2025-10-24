import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Shield, Zap, Info } from "lucide-react";

export type ScanMode = 'passive' | 'active';

interface ScanModeSelectorProps {
  value: ScanMode;
  onChange: (mode: ScanMode) => void;
  className?: string;
}

export const ScanModeSelector = ({ value, onChange, className = "" }: ScanModeSelectorProps) => {
  return (
    <Card className={className}>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Shield className="h-5 w-5" />
          Select Scan Mode
        </CardTitle>
        <CardDescription>
          Choose between passive observation or active vulnerability testing
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <RadioGroup value={value} onValueChange={(v) => onChange(v as ScanMode)}>
          <div className="flex items-start space-x-3 space-y-0 rounded-md border p-4 cursor-pointer hover:bg-accent transition-colors">
            <RadioGroupItem value="passive" id="passive" />
            <div className="flex-1">
              <Label htmlFor="passive" className="cursor-pointer">
                <div className="flex items-center gap-2 mb-1">
                  <Info className="h-4 w-4 text-blue-500" />
                  <span className="font-semibold">Passive Scan</span>
                </div>
                <p className="text-sm text-muted-foreground">
                  Non-intrusive scanning that observes and analyzes the target without active testing.
                  Safe for production environments. Includes reconnaissance, port scanning, and technology detection.
                </p>
              </Label>
            </div>
          </div>
          
          <div className="flex items-start space-x-3 space-y-0 rounded-md border p-4 cursor-pointer hover:bg-accent transition-colors">
            <RadioGroupItem value="active" id="active" />
            <div className="flex-1">
              <Label htmlFor="active" className="cursor-pointer">
                <div className="flex items-center gap-2 mb-1">
                  <Zap className="h-4 w-4 text-orange-500" />
                  <span className="font-semibold">Active Scan</span>
                </div>
                <p className="text-sm text-muted-foreground">
                  Comprehensive vulnerability testing with active exploitation attempts.
                  May impact target systems. Includes SQL injection, XSS testing, and exploit verification.
                  Only use with proper authorization.
                </p>
              </Label>
            </div>
          </div>
        </RadioGroup>

        {value === 'active' && (
          <Alert variant="destructive">
            <AlertDescription className="text-sm">
              <strong>Warning:</strong> Active scanning may disrupt services or trigger security alerts.
              Ensure you have explicit authorization before proceeding.
            </AlertDescription>
          </Alert>
        )}
      </CardContent>
    </Card>
  );
};
