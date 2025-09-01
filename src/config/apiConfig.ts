// API Configuration for VAPT Tool Backend
export const API_CONFIG = {
  BASE_URL: process.env.NODE_ENV === 'development' 
    ? 'http://localhost:8080' 
    : 'http://localhost:8080',
  WS_URL: process.env.NODE_ENV === 'development'
    ? 'ws://localhost:8080'
    : 'ws://localhost:8080',
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

// Demo mode fallback data
export const DEMO_OUTPUTS = {
  nmap: [
    'Starting Nmap 7.94 ( https://nmap.org )',
    'Nmap scan report for target',
    'Host is up (0.012s latency).',
    'PORT     STATE SERVICE VERSION',
    '22/tcp   open  ssh     OpenSSH 8.9p1',  
    '80/tcp   open  http    Apache httpd 2.4.51',
    '443/tcp  open  https   Apache httpd 2.4.51',
    'Nmap done: 1 IP address (1 host up) scanned'
  ],
  nikto: [
    '- Nikto v2.5.0',
    '+ Target Port:        80',
    '+ Server: Apache/2.4.51',
    '+ Retrieved x-powered-by header: PHP/7.4.28',
    '+ The anti-clickjacking X-Frame-Options header is not present.',
    '+ The X-XSS-Protection header is not defined.',
    '+ OSVDB-3268: /admin/: Directory indexing found.',
    '+ OSVDB-3092: /admin/: This might be interesting...'
  ],
  sqlmap: [
    'sqlmap/1.7.2 - automatic SQL injection tool',
    'testing connection to the target URL',
    'testing if the target URL content is stable',
    'target URL appears to be UNION injectable',
    'injectable parameter found!',
    'backend DBMS: MySQL >= 5.0.0',
    'current user: web_user@localhost'
  ],
  gobuster: [
    'Gobuster v3.6',
    'by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)',
    'Starting gobuster in directory enumeration mode',
    'Found: /admin              (Status: 200) [Size: 1234]',
    'Found: /backup             (Status: 301) [Size: 0]',
    'Found: /config             (Status: 403) [Size: 277]',
    'Found: /uploads            (Status: 200) [Size: 567]'
  ]
};