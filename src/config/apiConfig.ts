export const API_CONFIG = {
  get BASE_URL() {
    try {
      const stored = localStorage.getItem('backend_url');
      if (stored && /^https?:\/\//i.test(stored)) return stored.replace(/\/$/, '');
    } catch {}
    return 'http://localhost:8080';
  },
  get WS_URL() {
    try {
      const stored = localStorage.getItem('ws_url');
      if (stored && /^(ws|wss):\/\//i.test(stored)) return stored.replace(/\/$/, '');
    } catch {}
    return 'ws://localhost:8080';
  },
  ENDPOINTS: {
    CHECK_KALI: '/api/check-kali',
    TOOLS_INSTALLED: '/api/tools/installed',
    SCAN_NMAP: '/api/scan/nmap',
    SCAN_NIKTO: '/api/scan/nikto',
    SCAN_SQLMAP: '/api/scan/sqlmap',
    SCAN_GOBUSTER: '/api/scan/gobuster',
    SCAN_NUCLEI: '/api/scan/nuclei',
    SCAN_WHATWEB: '/api/scan/whatweb',
    SCAN_AMASS: '/api/scan/amass',
    SCAN_SUBLIST3R: '/api/scan/sublist3r',
    SCAN_DNS: '/api/scan/dns',
    SCAN_WHOIS: '/api/scan/whois',
    SCAN_SSL: '/api/scan/ssl',
    // Advanced Tools
    SCAN_MASSCAN: '/api/scan/masscan',
    SCAN_HYDRA: '/api/scan/hydra',
    SCAN_WPSCAN: '/api/scan/wpscan',
    SCAN_ENUM4LINUX: '/api/scan/enum4linux',
    SCAN_THEHARVESTER: '/api/scan/theharvester',
    SCAN_SSLYZE: '/api/scan/sslyze',
    SCAN_WAFW00F: '/api/scan/wafw00f',
    SCAN_WAPITI: '/api/scan/wapiti',
    SCAN_COMMIX: '/api/scan/commix',
    SCAN_XSSTRIKE: '/api/scan/xsstrike',
    SCAN_DNSENUM: '/api/scan/dnsenum',
    SCAN_FIERCE: '/api/scan/fierce',
    SCAN_CRACKMAPEXEC: '/api/scan/crackmapexec',
    SCAN_METASPLOIT: '/api/scan/metasploit',
    SCAN_JOHN: '/api/scan/john',
    SCAN_HASHCAT: '/api/scan/hashcat',
    SCAN_RECONNG: '/api/scan/reconng',
    // WebHackersWeapons Tools
    SCAN_SUBFINDER: '/api/scan/subfinder',
    SCAN_HTTPX: '/api/scan/httpx',
    SCAN_KATANA: '/api/scan/katana',
    SCAN_DALFOX: '/api/scan/dalfox',
    SCAN_GAU: '/api/scan/gau',
    SCAN_FFUF: '/api/scan/ffuf',
    SCAN_ARJUN: '/api/scan/arjun',
    SCAN_PARAMSPIDER: '/api/scan/paramspider',
    SCAN_WAYBACKURLS: '/api/scan/waybackurls',
    SCAN_HAKRAWLER: '/api/scan/hakrawler',
    SCAN_ASSETFINDER: '/api/scan/assetfinder',
    SCAN_LINKFINDER: '/api/scan/linkfinder',
    SCAN_SECRETFINDER: '/api/scan/secretfinder',
    SCAN_GITLEAKS: '/api/scan/gitleaks',
    SCAN_RUSTSCAN: '/api/scan/rustscan'
  }
};
