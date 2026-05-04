/**
 * Dork Templates - Pre-built dork queries for various vulnerability types
 * Organized by vulnerability category for bug bounty hunting
 */

export const DORK_TEMPLATES = {
  // ============================================
  // XSS (Cross-Site Scripting) Dorks
  // ============================================
  xss: [
    { query: 'inurl:"search=" OR inurl:"q=" OR inurl:"query="', desc: 'Search parameters (potential XSS)' },
    { query: 'inurl:"msg=" OR inurl:"message=" OR inurl:"comment="', desc: 'Message parameters' },
    { query: 'inurl:"name=" OR inurl:"title=" OR inurl:"desc="', desc: 'Text input parameters' },
    { query: 'inurl:"error=" OR inurl:"err=" OR inurl:"alert="', desc: 'Error display parameters' },
    { query: 'inurl:"redirect=" OR inurl:"return=" OR inurl:"callback="', desc: 'Redirect parameters' },
    { query: 'inurl:"input=" OR inurl:"text=" OR inurl:"value="', desc: 'Input value parameters' },
    { query: 'inurl:".php?id=" OR inurl:".asp?id="', desc: 'Dynamic pages with ID params' },
  ],

  // ============================================
  // SQL Injection Dorks
  // ============================================
  sqli: [
    { query: 'inurl:"id=" OR inurl:"pid=" OR inurl:"uid=" OR inurl:"nid="', desc: 'Numeric ID parameters' },
    { query: 'inurl:"cat=" OR inurl:"catid=" OR inurl:"category="', desc: 'Category parameters' },
    { query: 'inurl:"page=" OR inurl:"pageid=" OR inurl:"p="', desc: 'Page parameters' },
    { query: 'inurl:"item=" OR inurl:"product=" OR inurl:"prod="', desc: 'Product parameters' },
    { query: 'inurl:"news=" OR inurl:"article=" OR inurl:"post="', desc: 'Content parameters' },
    { query: 'inurl:"view=" OR inurl:"show=" OR inurl:"detail="', desc: 'View parameters' },
    { query: 'inurl:".php?id=" ext:php', desc: 'PHP pages with ID' },
    { query: 'inurl:".asp?id=" ext:asp', desc: 'ASP pages with ID' },
    { query: 'inurl:"index.php?id=" OR inurl:"detail.php?id="', desc: 'Common PHP pages' },
    { query: '"SQL syntax" OR "mysql_fetch" OR "You have an error"', desc: 'Existing SQL errors' },
    { query: '"Warning: mysql_" OR "Warning: pg_" OR "Warning: oci_"', desc: 'PHP database warnings' },
    { query: '"unclosed quotation mark" OR "unterminated string"', desc: 'SQL string errors' },
  ],

  // ============================================
  // LFI (Local File Inclusion) Dorks
  // ============================================
  lfi: [
    { query: 'inurl:"file=" OR inurl:"path=" OR inurl:"folder="', desc: 'File path parameters' },
    { query: 'inurl:"include=" OR inurl:"inc=" OR inurl:"require="', desc: 'Include parameters' },
    { query: 'inurl:"page=" OR inurl:"pg=" OR inurl:"template="', desc: 'Page/template parameters' },
    { query: 'inurl:"load=" OR inurl:"read=" OR inurl:"retrieve="', desc: 'File read parameters' },
    { query: 'inurl:"doc=" OR inurl:"document=" OR inurl:"pdf="', desc: 'Document parameters' },
    { query: 'inurl:"download=" OR inurl:"dl=" OR inurl:"get="', desc: 'Download parameters' },
    { query: 'inurl:"lang=" OR inurl:"language=" OR inurl:"locale="', desc: 'Language parameters' },
    { query: 'inurl:"module=" OR inurl:"mod=" OR inurl:"plugin="', desc: 'Module parameters' },
  ],

  // ============================================
  // IDOR (Insecure Direct Object Reference) Dorks
  // ============================================
  idor: [
    { query: 'inurl:"/user/" OR inurl:"/profile/" OR inurl:"/account/"', desc: 'User profile URLs' },
    { query: 'inurl:"/order/" OR inurl:"/invoice/" OR inurl:"/receipt/"', desc: 'Order/invoice URLs' },
    { query: 'inurl:"/document/" OR inurl:"/file/" OR inurl:"/attachment/"', desc: 'Document URLs' },
    { query: 'inurl:"/api/user/" OR inurl:"/api/v1/users/"', desc: 'API user endpoints' },
    { query: 'inurl:"/download?id=" OR inurl:"/export?id="', desc: 'Download with ID' },
    { query: 'inurl:"/admin/user/" OR inurl:"/manage/account/"', desc: 'Admin user management' },
    { query: 'inurl:"/ticket/" OR inurl:"/case/" OR inurl:"/report/"', desc: 'Ticket/case URLs' },
  ],

  // ============================================
  // Admin Panel / Bypass Dorks
  // ============================================
  admin_bypass: [
    { query: 'inurl:admin intitle:"login" OR intitle:"sign in"', desc: 'Admin login pages' },
    { query: 'inurl:"/admin/" -inurl:login -inurl:signin', desc: 'Admin pages without login' },
    { query: 'inurl:administrator OR inurl:adminpanel', desc: 'Administrator panels' },
    { query: 'intitle:"Dashboard" inurl:admin', desc: 'Admin dashboards' },
    { query: 'inurl:"/wp-admin/" OR inurl:"/wp-login.php"', desc: 'WordPress admin' },
    { query: 'inurl:"/administrator/" intitle:"Joomla"', desc: 'Joomla admin' },
    { query: 'inurl:"/user/login" OR inurl:"/admin/login"', desc: 'Login endpoints' },
    { query: 'intitle:"control panel" OR intitle:"management"', desc: 'Control panels' },
    { query: 'inurl:cpanel OR inurl:":2083" OR inurl:":2087"', desc: 'cPanel access' },
    { query: 'inurl:phpmyadmin OR inurl:pma', desc: 'phpMyAdmin' },
    { query: 'inurl:adminer.php OR inurl:adminer', desc: 'Adminer database tool' },
    { query: 'intitle:"Kibana" OR intitle:"Grafana" OR intitle:"Jenkins"', desc: 'DevOps dashboards' },
  ],

  // ============================================
  // Open Redirect Dorks
  // ============================================
  open_redirect: [
    { query: 'inurl:"redirect=" OR inurl:"redir=" OR inurl:"return="', desc: 'Redirect parameters' },
    { query: 'inurl:"url=" OR inurl:"uri=" OR inurl:"next="', desc: 'URL parameters' },
    { query: 'inurl:"goto=" OR inurl:"dest=" OR inurl:"destination="', desc: 'Destination parameters' },
    { query: 'inurl:"returnUrl=" OR inurl:"return_url=" OR inurl:"returnTo="', desc: 'Return URL parameters' },
    { query: 'inurl:"continue=" OR inurl:"forward=" OR inurl:"target="', desc: 'Forward parameters' },
    { query: 'inurl:"out=" OR inurl:"link=" OR inurl:"ref="', desc: 'Outbound link parameters' },
  ],

  // ============================================
  // SSRF (Server-Side Request Forgery) Dorks
  // ============================================
  ssrf: [
    { query: 'inurl:"url=" OR inurl:"uri=" OR inurl:"src="', desc: 'URL fetch parameters' },
    { query: 'inurl:"proxy=" OR inurl:"fetch=" OR inurl:"request="', desc: 'Proxy/fetch parameters' },
    { query: 'inurl:"callback=" OR inurl:"webhook=" OR inurl:"ping="', desc: 'Callback parameters' },
    { query: 'inurl:"image=" OR inurl:"img=" OR inurl:"load="', desc: 'Image load parameters' },
    { query: 'inurl:"feed=" OR inurl:"rss=" OR inurl:"xml="', desc: 'Feed/RSS parameters' },
    { query: 'inurl:"preview=" OR inurl:"render=" OR inurl:"screenshot="', desc: 'Preview/render parameters' },
  ],

  // ============================================
  // File Upload Dorks
  // ============================================
  file_upload: [
    { query: 'inurl:upload OR inurl:file-upload', desc: 'Upload endpoints' },
    { query: 'inurl:"upload.php" OR inurl:"uploader.php"', desc: 'PHP upload scripts' },
    { query: 'intitle:"upload" "choose file" OR "select file"', desc: 'Upload forms' },
    { query: 'inurl:"/uploads/" OR inurl:"/uploaded/"', desc: 'Upload directories' },
    { query: 'inurl:import OR inurl:attach', desc: 'Import/attach endpoints' },
    { query: 'inurl:"avatar" OR inurl:"profile-picture" "upload"', desc: 'Avatar upload' },
  ],

  // ============================================
  // Sensitive Information Dorks
  // ============================================
  sensitive_info: [
    { query: '"BEGIN RSA PRIVATE KEY" OR "BEGIN DSA PRIVATE KEY"', desc: 'Private keys exposed' },
    { query: '"password" ext:txt OR ext:log OR ext:cfg', desc: 'Passwords in text files' },
    { query: '"api_key" OR "apikey" OR "api_secret" ext:json OR ext:yml', desc: 'API keys in config' },
    { query: '"AKIA" ext:txt OR ext:env OR ext:cfg', desc: 'AWS access keys' },
    { query: '"mongodb://" OR "postgres://" OR "mysql://"', desc: 'Database connection strings' },
    { query: '"smtp" "password" ext:yml OR ext:yaml OR ext:env', desc: 'SMTP credentials' },
    { query: 'intitle:"index of" ".env"', desc: '.env files in directory listing' },
    { query: 'intitle:"index of" "id_rsa" OR "id_dsa"', desc: 'SSH keys in directory listing' },
    { query: '"token" OR "secret" ext:js inurl:config', desc: 'Secrets in JS config' },
    { query: '"Authorization: Bearer" ext:txt OR ext:log', desc: 'Bearer tokens in logs' },
  ],

  // ============================================
  // Technology-Specific Dorks
  // ============================================
  wordpress: [
    { query: 'inurl:"/wp-content/debug.log"', desc: 'WordPress debug log' },
    { query: 'inurl:"/wp-config.php.bak" OR inurl:"/wp-config.php.old"', desc: 'WP config backup' },
    { query: 'inurl:"/wp-content/uploads/" ext:sql OR ext:zip', desc: 'WP uploads with backups' },
    { query: 'inurl:"/wp-json/wp/v2/users"', desc: 'WP user enumeration' },
    { query: 'inurl:"/xmlrpc.php" "XML-RPC server accepts POST requests only"', desc: 'WP XML-RPC enabled' },
    { query: 'inurl:"/wp-content/plugins/" "index of"', desc: 'WP plugins directory listing' },
  ],

  laravel: [
    { query: 'inurl:"/_ignition/execute-solution"', desc: 'Laravel Ignition RCE' },
    { query: '"APP_KEY" "base64:" ext:env', desc: 'Laravel .env with APP_KEY' },
    { query: 'intitle:"Whoops!" "Laravel"', desc: 'Laravel debug mode' },
    { query: 'inurl:"/telescope" intitle:"Telescope"', desc: 'Laravel Telescope exposed' },
    { query: 'inurl:"/horizon" intitle:"Horizon"', desc: 'Laravel Horizon exposed' },
  ],

  git_exposed: [
    { query: 'inurl:"/.git/config" "repositoryformatversion"', desc: '.git/config exposed' },
    { query: 'inurl:"/.git/HEAD" "ref:"', desc: '.git/HEAD exposed' },
    { query: 'intitle:"index of" "/.git"', desc: '.git directory listing' },
    { query: 'inurl:"/.gitignore"', desc: '.gitignore exposed' },
  ],
};

/**
 * Build dork query with site filter
 */
export function buildDork(template, siteFilter) {
  return `site:${siteFilter} ${template.query}`;
}

/**
 * Get all dorks for a specific vulnerability type
 */
export function getDorksByType(type) {
  return DORK_TEMPLATES[type] || [];
}

/**
 * Get all vulnerability types available
 */
export function getAvailableTypes() {
  return Object.keys(DORK_TEMPLATES);
}

/**
 * Generate combined dorks for full scan
 */
export function generateFullDorkList(target) {
  const allDorks = [];
  for (const [category, dorks] of Object.entries(DORK_TEMPLATES)) {
    for (const dork of dorks) {
      allDorks.push({
        category,
        query: `site:${target} ${dork.query}`,
        description: dork.desc,
      });
    }
  }
  return allDorks;
}

export default DORK_TEMPLATES;
