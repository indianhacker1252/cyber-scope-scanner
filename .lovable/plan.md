
# CyberScope: Principal VAPT Workflow Integration

## Goal
Embed the user's 7-phase professional bug bounty workflow directly into the scanning pipeline and UI, consolidating duplicate modules.

## Phase 1: Consolidate Redundant Modules
- **Merge** Reconnaissance, ScopeDiscovery, AttackSurfaceMapping → single `ReconEngine` component
- **Merge** ExploitTesting, WebVulnerabilities, AdvancedScanning → single `VulnTestingEngine` component  
- **Remove** PentestGPT (replaced by smarter AI integrated into each phase)
- **Remove** duplicate AI modules (AIHub, AIAssistant overlap)

## Phase 2: Enhance `continuous-red-team-agent` Edge Function
Add the 7-phase PTES workflow as the core execution loop:

1. **Recon & Attack Surface Mapping**: Infrastructure profiling (tech stack versions), asset discovery (subdomain + directory brute), cloud identity detection (AWS/GCP/Azure metadata URLs)
2. **Context-Aware Differential Fuzzing**: Baseline request → breaker character injection → differential analysis (response size/time/status changes)
3. **CVE Correlation**: Auto-map detected tech+version to NVD CVEs, check for backport detection, misconfiguration scanning
4. **OWASP Deep Dives**: SQLi/NoSQLi time-based verification, IDOR parameter swapping, SSRF internal probe, business logic state analysis
5. **PoC Generation**: Auto-generate Python/curl scripts proving each finding
6. **False Positive Elimination**: 3x re-test consistency, WAF bypass verification, sanitization detection
7. **Remediation Strategy**: Short-term WAF rule + root-cause code fix for each finding

## Phase 3: New `vapt-workflow-engine` Edge Function
Dedicated edge function implementing the differential fuzzing and false-positive elimination logic that can't run in the browser.

## Phase 4: Update Dashboard UI
- New unified workflow view showing the 7 phases with progress
- Each phase shows real findings, not simulated data
- Findings display includes PoC scripts and remediation

## Implementation Order
1. Create `vapt-workflow-engine` edge function (core logic)
2. Consolidate UI modules
3. Wire consolidated UI to new edge function
4. Update Sidebar navigation
