// API Configuration for VAPT Tool Backend (runtime configurable)
export const API_CONFIG = {
  get BASE_URL() {
    try {
      const stored = localStorage.getItem('backend_url');
      if (stored && /^https?:\/\//i.test(stored)) return stored.replace(/\/$/, '');
    } catch {}
    // Default to localhost for dev setups
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
    SCAN_SUBLIST3R: '/api/scan/sublist3r'
  }
};
