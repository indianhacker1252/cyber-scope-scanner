import { useEffect, useMemo, useState } from "react";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { API_CONFIG } from "@/config/apiConfig";
import { Copy, Activity, Globe, Link2, Server, ShieldAlert } from "lucide-react";

interface DiagnosticsDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

type CheckStatus = 'pending' | 'pass' | 'fail';

interface CheckResult {
  label: string;
  status: CheckStatus;
  message: string;
  details?: string;
}

const DiagnosticsDialog = ({ open, onOpenChange }: DiagnosticsDialogProps) => {
  const [results, setResults] = useState<CheckResult[]>([]);
  const [running, setRunning] = useState(false);

  const BASE_URL = API_CONFIG.BASE_URL;
  const WS_URL = API_CONFIG.WS_URL;

  const crossOriginWarning = useMemo(() => {
    try {
      const isHosted = !['localhost', '127.0.0.1'].includes(window.location.hostname);
      const usesLocalhost = /localhost|127.0.0.1/.test(BASE_URL);
      return isHosted && usesLocalhost;
    } catch {
      return false;
    }
  }, [BASE_URL]);

  useEffect(() => {
    if (!open) return;
    const run = async () => {
      setRunning(true);
      const items: CheckResult[] = [
        { label: 'Backend URL', status: 'pending', message: `Using ${BASE_URL}` },
        { label: 'API Reachable', status: 'pending', message: 'Checking /api/check-kali...' },
        { label: 'Tools Endpoint', status: 'pending', message: 'Checking /api/tools/installed...' },
        { label: 'WebSocket URL', status: 'pending', message: `Using ${WS_URL}` },
      ];
      setResults(items);

      const setItem = (label: string, patch: Partial<CheckResult>) => {
        setResults(prev => prev.map(r => r.label === label ? { ...r, ...patch } : r));
      };

      // Check API base reachability
      try {
        const res = await fetch(`${BASE_URL}/api/check-kali`, { method: 'GET' });
        if (res.ok) {
          const json = await res.json().catch(() => ({}));
          setItem('API Reachable', { status: 'pass', message: `OK (${res.status})`, details: `isKali=${json?.isKali}` });
        } else {
          setItem('API Reachable', { status: 'fail', message: `HTTP ${res.status} ${res.statusText}` });
        }
      } catch (e: any) {
        setItem('API Reachable', { status: 'fail', message: `Network error: ${e?.message || 'unknown'}` });
      }

      // Check tools endpoint
      try {
        const res = await fetch(`${BASE_URL}/api/tools/installed`, { method: 'GET' });
        if (res.ok) {
          const tools = await res.json().catch(() => []);
          const installed = Array.isArray(tools) ? tools.filter((t: any) => t.installed).length : 0;
          setItem('Tools Endpoint', { status: 'pass', message: `OK (${installed} tools detected)` });
        } else {
          setItem('Tools Endpoint', { status: 'fail', message: `HTTP ${res.status} ${res.statusText}` });
        }
      } catch (e: any) {
        setItem('Tools Endpoint', { status: 'fail', message: `Network error: ${e?.message || 'unknown'}` });
      }

      // Test WebSocket connectivity
      try {
        const testWs = new WebSocket(`${WS_URL}/stream/health-check`);
        await new Promise<void>((resolve, reject) => {
          const timeout = setTimeout(() => {
            testWs.close();
            reject(new Error('Timeout'));
          }, 5000);
          
          testWs.onopen = () => {
            clearTimeout(timeout);
            testWs.close();
            resolve();
          };
          
          testWs.onerror = () => {
            clearTimeout(timeout);
            reject(new Error('Connection failed'));
          };
        });
        setItem('WebSocket URL', { status: 'pass', message: 'Connected successfully', details: WS_URL });
      } catch (e: any) {
        setItem('WebSocket URL', { status: 'fail', message: `Cannot connect: ${e?.message || 'unknown'}`, details: WS_URL });
      }

      setRunning(false);
    };

    run();
  }, [open, BASE_URL, WS_URL]);

  const summary = useMemo(() => {
    const lines = [
      `Diagnostics @ ${new Date().toISOString()}`,
      `App Host: ${window.location.origin}`,
      `API URL: ${BASE_URL}`,
      `WS URL: ${WS_URL}`,
      ...results.map(r => `- ${r.label}: ${r.status.toUpperCase()} - ${r.message}${r.details ? ` | ${r.details}` : ''}`),
      crossOriginWarning ? '* Warning: Hosted preview cannot reach localhost backend. Run locally or use a public URL.' : ''
    ].filter(Boolean);
    return lines.join('\n');
  }, [results, BASE_URL, WS_URL, crossOriginWarning]);

  const copySummary = async () => {
    try {
      await navigator.clipboard.writeText(summary);
    } catch {}
  };

  const statusBadge = (status: CheckStatus) => (
    <Badge variant={status === 'pass' ? 'default' : status === 'fail' ? 'destructive' : 'secondary'} className="capitalize">
      {status}
    </Badge>
  );

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Activity className="h-5 w-5" />
            System Diagnostics
          </DialogTitle>
          <DialogDescription>Identify why scans/buttons may not work and how to fix.</DialogDescription>
        </DialogHeader>

        {crossOriginWarning && (
          <Card className="border-orange-200 bg-orange-50 dark:bg-orange-950/20">
            <CardHeader className="py-3">
              <CardTitle className="text-sm flex items-center gap-2 text-orange-700 dark:text-orange-400">
                <ShieldAlert className="h-4 w-4" /> Cross-Origin Issue Detected
              </CardTitle>
            </CardHeader>
            <CardContent className="text-sm text-orange-600 dark:text-orange-300 space-y-2">
              <p>Backend is set to <code className="px-1 py-0.5 bg-orange-100 dark:bg-orange-900/40 rounded">localhost</code> but the app is hosted remotely. The browser blocks this connection.</p>
              <p className="font-medium">Solutions:</p>
              <ul className="list-disc list-inside space-y-1 ml-2">
                <li>Run frontend locally: <code className="px-1 py-0.5 bg-orange-100 dark:bg-orange-900/40 rounded">npm run dev</code></li>
                <li>Or deploy backend publicly and update Settings → Backend API URL</li>
              </ul>
            </CardContent>
          </Card>
        )}

        <div className="space-y-3">
          {results.map((r) => (
            <div key={r.label} className="flex items-start justify-between rounded-lg border p-3">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  {r.label.includes('Backend') ? <Server className="h-4 w-4" /> : r.label.includes('API') ? <Globe className="h-4 w-4" /> : <Link2 className="h-4 w-4" />}
                  <span className="font-medium">{r.label}</span>
                </div>
                <p className="text-sm text-muted-foreground">{r.message}</p>
                {r.details && <p className="text-xs text-muted-foreground">{r.details}</p>}
              </div>
              {statusBadge(r.status)}
            </div>
          ))}
        </div>

        <div className="flex justify-between pt-2">
          <Button variant="outline" onClick={copySummary}>
            <Copy className="h-4 w-4 mr-1" /> Copy Summary
          </Button>
          <Button disabled={running} onClick={() => onOpenChange(false)}>Close</Button>
        </div>
      </DialogContent>
    </Dialog>
  );
};

export default DiagnosticsDialog;
