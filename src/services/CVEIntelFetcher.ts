/**
 * CVEIntelFetcher.ts — CVE Intelligence Correlator
 * Queries NVD API for High/Critical CVEs matching detected technologies.
 * Handles rate-limiting and timeouts gracefully.
 */

import type { TechProfile } from './TechFingerprinter';

export interface CVERecord {
  cveId: string;
  cvssScore: number;
  cvssVector: string | null;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  vulnerabilityType: string;
  description: string;
  publishedDate: string;
  affectedProduct: string;
  affectedVersions: string;
  references: string[];
  exploitAvailable: boolean;
  nucleiTemplateId: string | null; // e.g. CVE-2021-41773
}

export interface CVECorrelationResult {
  technology: TechProfile;
  cves: CVERecord[];
  totalCVEs: number;
  highestCVSS: number;
  fetchedAt: string;
  source: 'nvd-api' | 'local-cache' | 'ai-enriched';
}

// Local CVE intelligence database (fast fallback when NVD is rate-limited)
const LOCAL_CVE_INTEL: Record<string, CVERecord[]> = {
  'apache': [
    { cveId: 'CVE-2021-41773', cvssScore: 9.8, cvssVector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', severity: 'CRITICAL', vulnerabilityType: 'Path Traversal / RCE', description: 'Apache HTTP Server 2.4.49 path traversal and remote code execution', publishedDate: '2021-10-05', affectedProduct: 'Apache HTTP Server', affectedVersions: '2.4.49', references: ['https://httpd.apache.org/security/vulnerabilities_24.html'], exploitAvailable: true, nucleiTemplateId: 'CVE-2021-41773' },
    { cveId: 'CVE-2021-42013', cvssScore: 9.8, cvssVector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', severity: 'CRITICAL', vulnerabilityType: 'Path Traversal / RCE', description: 'Apache HTTP Server 2.4.50 path traversal bypass of CVE-2021-41773 fix', publishedDate: '2021-10-07', affectedProduct: 'Apache HTTP Server', affectedVersions: '2.4.49-2.4.50', references: [], exploitAvailable: true, nucleiTemplateId: 'CVE-2021-42013' },
    { cveId: 'CVE-2023-25690', cvssScore: 9.8, cvssVector: null, severity: 'CRITICAL', vulnerabilityType: 'HTTP Request Smuggling', description: 'Apache HTTP Server mod_proxy HTTP request smuggling', publishedDate: '2023-03-07', affectedProduct: 'Apache HTTP Server', affectedVersions: '<2.4.56', references: [], exploitAvailable: true, nucleiTemplateId: 'CVE-2023-25690' },
    { cveId: 'CVE-2024-38476', cvssScore: 9.8, cvssVector: null, severity: 'CRITICAL', vulnerabilityType: 'SSRF', description: 'Apache HTTP Server mod_proxy SSRF via crafted UDS path', publishedDate: '2024-07-01', affectedProduct: 'Apache HTTP Server', affectedVersions: '<2.4.60', references: [], exploitAvailable: false, nucleiTemplateId: 'CVE-2024-38476' },
  ],
  'nginx': [
    { cveId: 'CVE-2021-23017', cvssScore: 7.7, cvssVector: null, severity: 'HIGH', vulnerabilityType: 'DNS Resolver Off-by-One', description: 'Nginx DNS resolver vulnerability allowing 1-byte memory overwrite', publishedDate: '2021-05-25', affectedProduct: 'Nginx', affectedVersions: '<1.21.0', references: [], exploitAvailable: true, nucleiTemplateId: 'CVE-2021-23017' },
    { cveId: 'CVE-2024-7347', cvssScore: 7.5, cvssVector: null, severity: 'HIGH', vulnerabilityType: 'Buffer Over-read', description: 'Nginx mp4 module buffer over-read via crafted mp4 file', publishedDate: '2024-08-14', affectedProduct: 'Nginx', affectedVersions: '<1.27.1', references: [], exploitAvailable: false, nucleiTemplateId: null },
  ],
  'php': [
    { cveId: 'CVE-2024-4577', cvssScore: 9.8, cvssVector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', severity: 'CRITICAL', vulnerabilityType: 'Argument Injection / RCE', description: 'PHP CGI argument injection on Windows allowing remote code execution', publishedDate: '2024-06-09', affectedProduct: 'PHP', affectedVersions: '8.1.x <8.1.29, 8.2.x <8.2.20, 8.3.x <8.3.8', references: [], exploitAvailable: true, nucleiTemplateId: 'CVE-2024-4577' },
    { cveId: 'CVE-2019-11043', cvssScore: 9.8, cvssVector: null, severity: 'CRITICAL', vulnerabilityType: 'Remote Code Execution', description: 'PHP-FPM underflow vulnerability leading to RCE', publishedDate: '2019-10-28', affectedProduct: 'PHP', affectedVersions: '7.1.x-7.3.x', references: [], exploitAvailable: true, nucleiTemplateId: 'CVE-2019-11043' },
    { cveId: 'CVE-2024-2961', cvssScore: 8.8, cvssVector: null, severity: 'HIGH', vulnerabilityType: 'Buffer Overflow', description: 'glibc iconv() buffer overflow exploitable via PHP filters', publishedDate: '2024-04-17', affectedProduct: 'PHP', affectedVersions: 'all versions using glibc', references: [], exploitAvailable: true, nucleiTemplateId: null },
  ],
  'wordpress': [
    { cveId: 'CVE-2023-2982', cvssScore: 9.8, cvssVector: null, severity: 'CRITICAL', vulnerabilityType: 'Authentication Bypass', description: 'WordPress Social Login plugin authentication bypass', publishedDate: '2023-06-29', affectedProduct: 'WordPress', affectedVersions: 'Social Login <7.6.5', references: [], exploitAvailable: true, nucleiTemplateId: 'CVE-2023-2982' },
    { cveId: 'CVE-2024-27956', cvssScore: 9.9, cvssVector: null, severity: 'CRITICAL', vulnerabilityType: 'SQL Injection', description: 'WordPress WP-Automatic plugin SQL injection to site takeover', publishedDate: '2024-03-31', affectedProduct: 'WordPress', affectedVersions: 'WP-Automatic <3.92.1', references: [], exploitAvailable: true, nucleiTemplateId: 'CVE-2024-27956' },
    { cveId: 'CVE-2024-2876', cvssScore: 9.8, cvssVector: null, severity: 'CRITICAL', vulnerabilityType: 'SQL Injection', description: 'WordPress Icegram Express plugin SQL injection', publishedDate: '2024-04-03', affectedProduct: 'WordPress', affectedVersions: 'Icegram Express <5.7.14', references: [], exploitAvailable: true, nucleiTemplateId: null },
  ],
  'node.js': [
    { cveId: 'CVE-2023-32002', cvssScore: 9.8, cvssVector: null, severity: 'CRITICAL', vulnerabilityType: 'Permission Model Bypass', description: 'Node.js permission model bypass via Module._load', publishedDate: '2023-08-21', affectedProduct: 'Node.js', affectedVersions: '<20.5.1', references: [], exploitAvailable: true, nucleiTemplateId: null },
    { cveId: 'CVE-2024-22019', cvssScore: 7.5, cvssVector: null, severity: 'HIGH', vulnerabilityType: 'Denial of Service', description: 'Node.js HTTP server DoS via chunk extension abuse', publishedDate: '2024-02-20', affectedProduct: 'Node.js', affectedVersions: '<21.6.2', references: [], exploitAvailable: false, nucleiTemplateId: null },
  ],
  'spring': [
    { cveId: 'CVE-2022-22965', cvssScore: 9.8, cvssVector: null, severity: 'CRITICAL', vulnerabilityType: 'Remote Code Execution', description: 'Spring4Shell - Spring Framework RCE via data binding', publishedDate: '2022-03-31', affectedProduct: 'Spring Framework', affectedVersions: '5.3.0-5.3.17, 5.2.0-5.2.19', references: [], exploitAvailable: true, nucleiTemplateId: 'CVE-2022-22965' },
    { cveId: 'CVE-2022-22963', cvssScore: 9.8, cvssVector: null, severity: 'CRITICAL', vulnerabilityType: 'Remote Code Execution', description: 'Spring Cloud Function SpEL injection RCE', publishedDate: '2022-03-29', affectedProduct: 'Spring Cloud Function', affectedVersions: '<3.1.7, <3.2.3', references: [], exploitAvailable: true, nucleiTemplateId: 'CVE-2022-22963' },
  ],
  'tomcat': [
    { cveId: 'CVE-2020-1938', cvssScore: 9.8, cvssVector: null, severity: 'CRITICAL', vulnerabilityType: 'AJP File Read / RCE', description: 'Apache Tomcat AJP Ghostcat file read/inclusion', publishedDate: '2020-02-24', affectedProduct: 'Apache Tomcat', affectedVersions: '<9.0.31, <8.5.51, <7.0.100', references: [], exploitAvailable: true, nucleiTemplateId: 'CVE-2020-1938' },
    { cveId: 'CVE-2024-50379', cvssScore: 9.8, cvssVector: null, severity: 'CRITICAL', vulnerabilityType: 'Remote Code Execution', description: 'Apache Tomcat TOCTOU race condition RCE on case-insensitive FS', publishedDate: '2024-12-17', affectedProduct: 'Apache Tomcat', affectedVersions: '<11.0.2, <10.1.34, <9.0.98', references: [], exploitAvailable: true, nucleiTemplateId: 'CVE-2024-50379' },
  ],
  'iis': [
    { cveId: 'CVE-2021-31166', cvssScore: 9.8, cvssVector: null, severity: 'CRITICAL', vulnerabilityType: 'Remote Code Execution', description: 'Microsoft IIS HTTP Protocol Stack RCE (wormable)', publishedDate: '2021-05-11', affectedProduct: 'Microsoft IIS', affectedVersions: 'Windows 10 2004+', references: [], exploitAvailable: true, nucleiTemplateId: 'CVE-2021-31166' },
    { cveId: 'CVE-2017-7269', cvssScore: 9.8, cvssVector: null, severity: 'CRITICAL', vulnerabilityType: 'Buffer Overflow / RCE', description: 'IIS 6.0 WebDAV buffer overflow', publishedDate: '2017-03-27', affectedProduct: 'Microsoft IIS', affectedVersions: '6.0', references: [], exploitAvailable: true, nucleiTemplateId: 'CVE-2017-7269' },
  ],
  'express': [
    { cveId: 'CVE-2024-29041', cvssScore: 7.5, cvssVector: null, severity: 'HIGH', vulnerabilityType: 'Open Redirect', description: 'Express.js res.location open redirect via URL with host', publishedDate: '2024-03-25', affectedProduct: 'Express', affectedVersions: '<4.19.2', references: [], exploitAvailable: false, nucleiTemplateId: null },
    { cveId: 'CVE-2022-24999', cvssScore: 7.5, cvssVector: null, severity: 'HIGH', vulnerabilityType: 'Prototype Pollution', description: 'Express.js qs prototype pollution DoS', publishedDate: '2022-11-26', affectedProduct: 'Express', affectedVersions: '<4.17.3', references: [], exploitAvailable: true, nucleiTemplateId: null },
  ],
  'jquery': [
    { cveId: 'CVE-2020-11023', cvssScore: 6.1, cvssVector: null, severity: 'MEDIUM', vulnerabilityType: 'Cross-Site Scripting', description: 'jQuery XSS via untrusted HTML passed to DOM manipulation methods', publishedDate: '2020-04-29', affectedProduct: 'jQuery', affectedVersions: '<3.5.0', references: [], exploitAvailable: true, nucleiTemplateId: 'CVE-2020-11023' },
  ],
  'openssl': [
    { cveId: 'CVE-2022-3602', cvssScore: 7.5, cvssVector: null, severity: 'HIGH', vulnerabilityType: 'Buffer Overflow', description: 'OpenSSL X.509 email address buffer overflow', publishedDate: '2022-11-01', affectedProduct: 'OpenSSL', affectedVersions: '3.0.0-3.0.6', references: [], exploitAvailable: false, nucleiTemplateId: null },
  ],
};

// NVD API rate limit: 5 requests per 30 seconds (without API key)
const NVD_API_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const NVD_RATE_LIMIT_DELAY = 6500; // ms between requests
let lastNVDCall = 0;

async function rateLimitedFetch(url: string, timeout = 15000): Promise<Response> {
  const now = Date.now();
  const elapsed = now - lastNVDCall;
  if (elapsed < NVD_RATE_LIMIT_DELAY) {
    await new Promise(r => setTimeout(r, NVD_RATE_LIMIT_DELAY - elapsed));
  }
  lastNVDCall = Date.now();

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);
  try {
    const response = await fetch(url, { signal: controller.signal });
    clearTimeout(timeoutId);
    return response;
  } catch (err) {
    clearTimeout(timeoutId);
    throw err;
  }
}

/**
 * Fetch CVEs from NVD API for a specific technology
 */
async function fetchFromNVD(tech: TechProfile): Promise<CVERecord[]> {
  try {
    const keyword = `${tech.name} ${tech.version || ''}`.trim();
    const params = new URLSearchParams({
      keywordSearch: keyword,
      cvssV3Severity: 'HIGH',
      resultsPerPage: '10',
    });

    const response = await rateLimitedFetch(`${NVD_API_BASE}?${params}`);
    
    if (response.status === 403 || response.status === 429) {
      console.warn('[CVEIntelFetcher] NVD rate limited, falling back to local cache');
      return [];
    }

    if (!response.ok) {
      console.warn(`[CVEIntelFetcher] NVD returned ${response.status}`);
      return [];
    }

    const data = await response.json();
    const cves: CVERecord[] = [];

    for (const item of (data.vulnerabilities || []).slice(0, 10)) {
      const cve = item.cve;
      const metrics = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0];
      const score = metrics?.cvssData?.baseScore || 0;
      if (score < 7.0) continue; // Only High/Critical

      cves.push({
        cveId: cve.id,
        cvssScore: score,
        cvssVector: metrics?.cvssData?.vectorString || null,
        severity: score >= 9.0 ? 'CRITICAL' : 'HIGH',
        vulnerabilityType: extractVulnType(cve.descriptions?.[0]?.value || ''),
        description: cve.descriptions?.[0]?.value || '',
        publishedDate: cve.published || '',
        affectedProduct: tech.name,
        affectedVersions: tech.version || 'unknown',
        references: (cve.references || []).slice(0, 3).map((r: any) => r.url),
        exploitAvailable: cve.references?.some((r: any) => r.tags?.includes('Exploit')) || false,
        nucleiTemplateId: cve.id, // Template ID matches CVE ID in nuclei-templates
      });
    }

    return cves;
  } catch (err) {
    console.warn(`[CVEIntelFetcher] NVD fetch error for ${tech.name}:`, err);
    return [];
  }
}

function extractVulnType(description: string): string {
  const desc = description.toLowerCase();
  if (desc.includes('remote code execution') || desc.includes('rce')) return 'Remote Code Execution';
  if (desc.includes('sql injection')) return 'SQL Injection';
  if (desc.includes('cross-site scripting') || desc.includes('xss')) return 'Cross-Site Scripting';
  if (desc.includes('path traversal') || desc.includes('directory traversal')) return 'Path Traversal';
  if (desc.includes('buffer overflow')) return 'Buffer Overflow';
  if (desc.includes('denial of service') || desc.includes('dos')) return 'Denial of Service';
  if (desc.includes('authentication bypass')) return 'Authentication Bypass';
  if (desc.includes('ssrf')) return 'Server-Side Request Forgery';
  if (desc.includes('information disclosure')) return 'Information Disclosure';
  if (desc.includes('privilege escalation')) return 'Privilege Escalation';
  return 'Other';
}

/**
 * Get CVE intelligence for a technology — tries local cache first, then NVD API
 */
export async function getCVEsForTechnology(tech: TechProfile, useNVD = false): Promise<CVECorrelationResult> {
  const techKey = tech.name.toLowerCase().replace(/\s+/g, '').replace(/\.js$/i, '');
  
  // Try local cache first (instant, no rate limits)
  const localCVEs = LOCAL_CVE_INTEL[techKey] || [];
  
  let allCVEs = [...localCVEs];
  let source: CVECorrelationResult['source'] = 'local-cache';

  // Optionally try NVD API for additional/newer CVEs
  if (useNVD && tech.version) {
    try {
      const nvdCVEs = await fetchFromNVD(tech);
      if (nvdCVEs.length > 0) {
        // Merge, dedup by CVE ID
        const seen = new Set(allCVEs.map(c => c.cveId));
        for (const cve of nvdCVEs) {
          if (!seen.has(cve.cveId)) {
            allCVEs.push(cve);
          }
        }
        source = 'nvd-api';
      }
    } catch {
      // Fall through to local cache
    }
  }

  // Filter by version relevance if we have a version
  if (tech.version) {
    // Keep all for now — version filtering is complex with range matching
  }

  // Sort by CVSS score descending
  allCVEs.sort((a, b) => b.cvssScore - a.cvssScore);

  return {
    technology: tech,
    cves: allCVEs,
    totalCVEs: allCVEs.length,
    highestCVSS: allCVEs[0]?.cvssScore || 0,
    fetchedAt: new Date().toISOString(),
    source,
  };
}

/**
 * Batch-fetch CVEs for all technologies in a target asset
 */
export async function correlateAllTechnologies(
  technologies: TechProfile[],
  useNVD = false
): Promise<CVECorrelationResult[]> {
  const results: CVECorrelationResult[] = [];

  for (const tech of technologies) {
    const result = await getCVEsForTechnology(tech, useNVD);
    if (result.cves.length > 0) {
      results.push(result);
    }
  }

  return results;
}
