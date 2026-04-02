
# CyberScope Enhancement Plan

## 1. Smarter AI Scanning Pipeline (Edge Function: `advanced-recon-engine`)
- **Spider-mode scanning**: Recursive endpoint/param discovery across all subdomains
- **Retry logic with strategy rotation**: Auto-retry failed scans with rotated User-Agents, methods, and encoding
- **OWASP Top 10 mapped test suites**: Each scan maps to specific OWASP categories (A01-A10)
- **CVE correlation**: Auto-map discovered tech stacks to known CVEs via NVD data
- **AI next-action planner**: After each scan phase, AI decides the optimal next test based on findings

## 2. Live Attack Visualization Fix
- **Fix 100% failed timeline**: The `AttackVisualization.tsx` timeline shows all attempts as failed — fix status tracking so successful findings show green
- **Real-time metrics**: Working success rate, findings-per-hour, and phase progression counters
- **Phase-aware timeline**: Show scan phases (Recon → Discovery → Testing → Validation) with proper status

## 3. Validation & Reporting Enhancement
- **Enhanced PoC scaffolding**: Improve the validation-scaffolder to generate more precise, tech-stack-aware scripts
- **Professional audit report edge function**: Generate structured Markdown reports with CVSS 3.1 scoring, OWASP mapping, and remediation guidance

## 4. Reconnaissance Depth
- **Deep subdomain enumeration**: Certificate transparency, DNS brute-force, permutation scanning
- **Technology fingerprinting enhancement**: Deeper header/body/JS analysis for framework versions
- **Parameter discovery**: Automated parameter mining from JS files, archived URLs, and API schemas

## 5. OWASP Top 10 & CVE Mapping
- **OWASP test matrix**: Dedicated test cases for each OWASP Top 10 category with specific payloads
- **CVE intelligence feed**: Map discovered services/versions to high-severity CVEs
- **Attack path correlation**: Link multiple low-severity findings into high-impact chains

### Implementation Order:
1. Fix AttackVisualization timeline (quick win, high visibility)
2. Enhance the continuous-red-team-agent edge function with spider mode + retry logic
3. Add OWASP/CVE mapping to scan orchestrator
4. Improve recon depth in the scanning pipeline
5. Enhance reporting output
