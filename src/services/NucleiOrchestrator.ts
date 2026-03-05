/**
 * NucleiOrchestrator.ts — Template-Based Verification Orchestrator
 * Uses Nuclei templates to safely verify CVEs without destructive exploitation.
 * Parses JSON output to confirm if the exploit path is viable.
 */

import type { CVERecord } from './CVEIntelFetcher';
import { supabase } from '@/integrations/supabase/client';

export interface NucleiVerificationResult {
  cveId: string;
  templateId: string;
  verified: boolean;
  matcherStatus: 'confirmed' | 'not-vulnerable' | 'error' | 'template-missing';
  endpoint: string;
  matchedAt: string | null;
  extractedData: string | null;
  severity: string;
  timestamp: string;
  nucleiOutput: string | null;
}

export interface WeaponizationEntry {
  id: string;
  cveId: string;
  cvssScore: number;
  severity: string;
  technology: string;
  version: string | null;
  vulnerabilityType: string;
  verifiedEndpoint: string;
  nucleiTemplateId: string;
  description: string;
  exploitReady: boolean;
  verifiedAt: string;
  pocPayload: string | null;
}

// Known Nuclei template IDs for common CVEs
const NUCLEI_TEMPLATE_MAP: Record<string, { path: string; safe: boolean; expectedMatch: string }> = {
  'CVE-2021-41773': { path: 'cves/2021/CVE-2021-41773.yaml', safe: true, expectedMatch: 'root:' },
  'CVE-2021-42013': { path: 'cves/2021/CVE-2021-42013.yaml', safe: true, expectedMatch: 'root:' },
  'CVE-2023-25690': { path: 'cves/2023/CVE-2023-25690.yaml', safe: true, expectedMatch: 'HTTP/1.1' },
  'CVE-2024-4577':  { path: 'cves/2024/CVE-2024-4577.yaml', safe: true, expectedMatch: 'phpinfo' },
  'CVE-2019-11043': { path: 'cves/2019/CVE-2019-11043.yaml', safe: true, expectedMatch: 'PHP' },
  'CVE-2022-22965': { path: 'cves/2022/CVE-2022-22965.yaml', safe: true, expectedMatch: 'class.module' },
  'CVE-2022-22963': { path: 'cves/2022/CVE-2022-22963.yaml', safe: true, expectedMatch: 'functionRouter' },
  'CVE-2020-1938':  { path: 'cves/2020/CVE-2020-1938.yaml', safe: true, expectedMatch: 'AJP' },
  'CVE-2024-50379': { path: 'cves/2024/CVE-2024-50379.yaml', safe: true, expectedMatch: 'Tomcat' },
  'CVE-2021-31166': { path: 'cves/2021/CVE-2021-31166.yaml', safe: true, expectedMatch: 'IIS' },
  'CVE-2017-7269':  { path: 'cves/2017/CVE-2017-7269.yaml', safe: true, expectedMatch: 'PROPFIND' },
  'CVE-2023-2982':  { path: 'cves/2023/CVE-2023-2982.yaml', safe: true, expectedMatch: 'wp-login' },
  'CVE-2024-27956': { path: 'cves/2024/CVE-2024-27956.yaml', safe: true, expectedMatch: 'automatic' },
  'CVE-2021-23017': { path: 'cves/2021/CVE-2021-23017.yaml', safe: true, expectedMatch: 'nginx' },
  'CVE-2020-11023': { path: 'cves/2020/CVE-2020-11023.yaml', safe: true, expectedMatch: 'jquery' },
  'CVE-2024-29041': { path: 'cves/2024/CVE-2024-29041.yaml', safe: true, expectedMatch: 'location' },
};

/**
 * Verify a CVE against a target using Nuclei template via edge function
 */
export async function verifyCVE(
  target: string,
  cve: CVERecord
): Promise<NucleiVerificationResult> {
  const templateInfo = NUCLEI_TEMPLATE_MAP[cve.cveId];
  const templateId = cve.nucleiTemplateId || cve.cveId;

  if (!templateInfo) {
    return {
      cveId: cve.cveId,
      templateId,
      verified: false,
      matcherStatus: 'template-missing',
      endpoint: target,
      matchedAt: null,
      extractedData: null,
      severity: cve.severity,
      timestamp: new Date().toISOString(),
      nucleiOutput: `No Nuclei template mapped for ${cve.cveId}`,
    };
  }

  try {
    // Call security-scan edge function with nuclei scan type
    const { data, error } = await supabase.functions.invoke('security-scan', {
      body: {
        scanType: 'nuclei-cve',
        target,
        options: {
          templateId: templateInfo.path,
          cveId: cve.cveId,
          safeMode: templateInfo.safe,
        },
      },
    });

    if (error) {
      return {
        cveId: cve.cveId,
        templateId,
        verified: false,
        matcherStatus: 'error',
        endpoint: target,
        matchedAt: null,
        extractedData: null,
        severity: cve.severity,
        timestamp: new Date().toISOString(),
        nucleiOutput: `Edge function error: ${error.message}`,
      };
    }

    // Parse nuclei results
    const output = data?.output || '';
    const findings = data?.findings || data?.vulnerabilities || [];
    const isVulnerable = 
      findings.some((f: any) => f.severity === 'critical' || f.severity === 'high') ||
      output.toLowerCase().includes('[vulnerable]') ||
      output.toLowerCase().includes(templateInfo.expectedMatch.toLowerCase());

    return {
      cveId: cve.cveId,
      templateId,
      verified: isVulnerable,
      matcherStatus: isVulnerable ? 'confirmed' : 'not-vulnerable',
      endpoint: target,
      matchedAt: isVulnerable ? target : null,
      extractedData: findings[0]?.description || null,
      severity: cve.severity,
      timestamp: new Date().toISOString(),
      nucleiOutput: typeof output === 'string' ? output.substring(0, 1000) : JSON.stringify(output).substring(0, 1000),
    };
  } catch (err: any) {
    return {
      cveId: cve.cveId,
      templateId,
      verified: false,
      matcherStatus: 'error',
      endpoint: target,
      matchedAt: null,
      extractedData: null,
      severity: cve.severity,
      timestamp: new Date().toISOString(),
      nucleiOutput: `Verification error: ${err.message}`,
    };
  }
}

/**
 * Batch verify multiple CVEs and produce weaponization queue entries
 */
export async function batchVerifyCVEs(
  target: string,
  cves: { cve: CVERecord; technology: string; version: string | null }[]
): Promise<{ results: NucleiVerificationResult[]; weaponized: WeaponizationEntry[] }> {
  const results: NucleiVerificationResult[] = [];
  const weaponized: WeaponizationEntry[] = [];

  // Process sequentially to avoid overwhelming target
  for (const { cve, technology, version } of cves) {
    const result = await verifyCVE(target, cve);
    results.push(result);

    if (result.verified) {
      weaponized.push({
        id: crypto.randomUUID(),
        cveId: cve.cveId,
        cvssScore: cve.cvssScore,
        severity: cve.severity,
        technology,
        version,
        vulnerabilityType: cve.vulnerabilityType,
        verifiedEndpoint: result.matchedAt || target,
        nucleiTemplateId: result.templateId,
        description: cve.description,
        exploitReady: cve.exploitAvailable,
        verifiedAt: result.timestamp,
        pocPayload: result.extractedData,
      });
    }

    // Small delay between verifications
    await new Promise(r => setTimeout(r, 500));
  }

  return { results, weaponized };
}
