import { httpGet, httpPost, httpRequest } from '../../../utils/http-client.js';
import { generateId, sleep } from '../../../utils/helpers.js';
import logger from '../../../utils/logger.js';

/**
 * Infrastructure Exposure Scanner
 * Covers: Admin panels, Exposed services, Sensitive files, Debug endpoints,
 * API documentation, Backup files, Source code exposure, Directory listing,
 * Version disclosure, Default credentials
 */
export class InfraScanner {
  constructor(options = {}) {
    this.timeout = options.timeout || 8000;
    this.concurrency = options.concurrency || 10;
    this.delay = options.delay || 100;
    this.findings = [];
  }

  /**
   * Run all infrastructure exposure checks
   */
  async scan(url, options = {}) {
    const baseUrl = this._getBaseUrl(url);

    const scanModules = [
      { name: 'Admin Panels', fn: () => this.scanAdminPanels(baseUrl, options) },
      { name: 'Exposed Services', fn: () => this.scanExposedServices(baseUrl, options) },
      { name: 'Sensitive Files', fn: () => this.scanSensitiveFiles(baseUrl, options) },
      { name: 'Debug Endpoints', fn: () => this.scanDebugEndpoints(baseUrl, options) },
      { name: 'API Documentation', fn: () => this.scanAPIDocumentation(baseUrl, options) },
      { name: 'Backup Files', fn: () => this.scanBackupFiles(baseUrl, options) },
      { name: 'Source Code Exposure', fn: () => this.scanSourceCodeExposure(baseUrl, options) },
      { name: 'Directory Listing', fn: () => this.scanDirectoryListing(baseUrl, options) },
      { name: 'Version Disclosure', fn: () => this.scanVersionDisclosure(baseUrl, options) },
      { name: 'Default Credentials', fn: () => this.scanDefaultCredentials(baseUrl, options) },
    ];

    for (const mod of scanModules) {
      try {
        logger.info(`  [${mod.name}] Scanning...`);
        const results = await mod.fn();
        if (results && results.length > 0) {
          this.findings.push(...results);
          results.forEach(r => logger.vuln?.(r.severity, `    FOUND: ${r.title}`) || logger.info(`    FOUND [${r.severity}]: ${r.title}`));
        }
      } catch (e) {
        logger.debug?.(`  [${mod.name}] Error: ${e.message}`) || logger.info(`  [${mod.name}] Error: ${e.message}`);
      }
    }

    return this.findings;
  }

  // ═══════════════════════════════════════════════════════════
  // ADMIN PANELS
  // ═══════════════════════════════════════════════════════════
  async scanAdminPanels(url, options = {}) {
    const findings = [];

    const adminPaths = [
      '/admin', '/admin/', '/administrator', '/administrator/', '/admin/login',
      '/admin/index.php', '/admin/dashboard', '/admin/panel', '/adminpanel',
      '/admin.php', '/admin.html', '/admin/admin', '/admin/cp',
      '/wp-admin', '/wp-admin/', '/wp-login.php', '/wp-admin/admin-ajax.php',
      '/administrator/index.php', '/joomla/administrator',
      '/drupal/admin', '/user/login',
      '/cpanel', '/cpanel/', '/whm', '/webmail',
      '/django-admin', '/django-admin/', '/admin/django',
      '/rails/info', '/rails/mailers',
      '/laravel-admin', '/nova', '/nova/login',
      '/filament', '/filament/login',
      '/manager', '/manager/', '/magento/admin',
      '/shop/admin', '/store/admin', '/commerce/admin',
      '/backend', '/backend/', '/backoffice', '/back-office',
      '/control', '/controlpanel', '/control-panel',
      '/dashboard', '/dashboard/', '/dash',
      '/manage', '/management', '/manager/html',
      '/portal', '/portal/admin', '/system', '/sys-admin',
      '/superadmin', '/super-admin', '/root',
      '/console', '/console/', '/webadmin',
      '/siteadmin', '/site-admin', '/moderator',
      '/staff', '/internal', '/private',
    ];

    const adminIndicators = [
      'login', 'sign in', 'log in', 'username', 'password',
      'admin', 'dashboard', 'control panel', 'authentication',
      'management', 'administrator', 'backend',
    ];

    for (const path of adminPaths) {
      const testUrl = `${url}${path}`;
      const resp = await httpGet(testUrl, { timeout: this.timeout });
      const body = typeof resp.data === 'string' ? resp.data.toLowerCase() : '';

      if (resp.status === 200 || resp.status === 401 || resp.status === 403) {
        const hasIndicator = adminIndicators.some(ind => body.includes(ind));
        const hasLoginForm = body.includes('<form') && (body.includes('password') || body.includes('passwd'));

        if (hasIndicator || hasLoginForm || resp.status === 401) {
          const severity = resp.status === 200 && hasLoginForm ? 'high' : 'medium';
          findings.push(this._createFinding({
            type: 'admin-panel-exposed', title: `Admin Panel Found: ${path}`,
            severity, url: testUrl, parameter: 'Path',
            payload: path,
            evidence: `Admin panel accessible at ${path} (HTTP ${resp.status})${hasLoginForm ? ' - Login form present' : ''}`,
            request: `GET ${testUrl}`,
            response: `HTTP ${resp.status} - ${hasLoginForm ? 'Login form detected' : 'Admin indicators found'}`,
            remediation: 'Restrict admin panel access by IP. Use VPN. Implement MFA. Change default admin paths.',
            cwe: 'CWE-200', owasp: 'A05:2021 Security Misconfiguration',
          }));
        }
      }

      await sleep(this.delay);
    }

    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // EXPOSED SERVICES
  // ═══════════════════════════════════════════════════════════
  async scanExposedServices(url, options = {}) {
    const findings = [];

    const services = [
      { path: '/phpmyadmin', indicator: 'phpMyAdmin', name: 'phpMyAdmin', severity: 'critical' },
      { path: '/phpmyadmin/', indicator: 'phpMyAdmin', name: 'phpMyAdmin', severity: 'critical' },
      { path: '/pma', indicator: 'phpMyAdmin', name: 'phpMyAdmin (alias)', severity: 'critical' },
      { path: '/adminer', indicator: 'adminer', name: 'Adminer', severity: 'critical' },
      { path: '/adminer.php', indicator: 'adminer', name: 'Adminer', severity: 'critical' },
      { path: '/pgadmin', indicator: 'pgAdmin', name: 'pgAdmin', severity: 'critical' },
      { path: '/jenkins', indicator: 'Jenkins', name: 'Jenkins', severity: 'critical' },
      { path: '/jenkins/', indicator: 'Dashboard', name: 'Jenkins', severity: 'critical' },
      { path: '/hudson', indicator: 'Hudson', name: 'Hudson CI', severity: 'high' },
      { path: '/bamboo', indicator: 'Bamboo', name: 'Atlassian Bamboo', severity: 'high' },
      { path: '/teamcity', indicator: 'TeamCity', name: 'TeamCity', severity: 'high' },
      { path: '/gitlab', indicator: 'GitLab', name: 'GitLab', severity: 'high' },
      { path: '/gitea', indicator: 'Gitea', name: 'Gitea', severity: 'high' },
      { path: '/gogs', indicator: 'Gogs', name: 'Gogs', severity: 'high' },
      { path: '/grafana', indicator: 'Grafana', name: 'Grafana', severity: 'high' },
      { path: '/grafana/', indicator: 'grafana', name: 'Grafana', severity: 'high' },
      { path: '/kibana', indicator: 'kibana', name: 'Kibana', severity: 'high' },
      { path: '/kibana/', indicator: 'kibana', name: 'Kibana', severity: 'high' },
      { path: '/prometheus', indicator: 'Prometheus', name: 'Prometheus', severity: 'high' },
      { path: '/prometheus/graph', indicator: 'Prometheus', name: 'Prometheus', severity: 'high' },
      { path: '/nagios', indicator: 'Nagios', name: 'Nagios', severity: 'high' },
      { path: '/zabbix', indicator: 'Zabbix', name: 'Zabbix', severity: 'high' },
      { path: '/netdata', indicator: 'netdata', name: 'Netdata', severity: 'medium' },
      { path: '/_search', indicator: 'hits', name: 'Elasticsearch', severity: 'critical' },
      { path: '/_cat/indices', indicator: 'index', name: 'Elasticsearch Indices', severity: 'critical' },
      { path: '/_cluster/health', indicator: 'cluster_name', name: 'Elasticsearch Cluster', severity: 'critical' },
      { path: '/rabbitmq', indicator: 'RabbitMQ', name: 'RabbitMQ', severity: 'high' },
      { path: '/portainer', indicator: 'Portainer', name: 'Portainer', severity: 'critical' },
      { path: '/kubernetes-dashboard', indicator: 'Kubernetes', name: 'Kubernetes Dashboard', severity: 'critical' },
      { path: '/rancher', indicator: 'Rancher', name: 'Rancher', severity: 'critical' },
      { path: '/roundcube', indicator: 'Roundcube', name: 'Roundcube Webmail', severity: 'medium' },
      { path: '/webmail', indicator: 'mail', name: 'Webmail', severity: 'medium' },
      { path: '/solr', indicator: 'Solr', name: 'Apache Solr', severity: 'high' },
      { path: '/minio', indicator: 'MinIO', name: 'MinIO', severity: 'high' },
      { path: '/vault', indicator: 'Vault', name: 'HashiCorp Vault', severity: 'critical' },
      { path: '/consul', indicator: 'Consul', name: 'HashiCorp Consul', severity: 'high' },
      { path: '/sonarqube', indicator: 'SonarQube', name: 'SonarQube', severity: 'high' },
      { path: '/nexus', indicator: 'Nexus', name: 'Sonatype Nexus', severity: 'high' },
      { path: '/artifactory', indicator: 'Artifactory', name: 'JFrog Artifactory', severity: 'high' },
      { path: '/traefik', indicator: 'traefik', name: 'Traefik Dashboard', severity: 'high' },
      { path: '/flower', indicator: 'Flower', name: 'Celery Flower', severity: 'medium' },
      { path: '/mailhog', indicator: 'MailHog', name: 'MailHog', severity: 'medium' },
      { path: '/redis-commander', indicator: 'Redis Commander', name: 'Redis Commander', severity: 'critical' },
      { path: '/mongo-express', indicator: 'Mongo Express', name: 'Mongo Express', severity: 'critical' },
    ];

    for (const svc of services) {
      const testUrl = `${url}${svc.path}`;
      const resp = await httpGet(testUrl, { timeout: this.timeout });
      const body = typeof resp.data === 'string' ? resp.data : '';

      if (resp.status === 200 && body.toLowerCase().includes(svc.indicator.toLowerCase())) {
        findings.push(this._createFinding({
          type: 'exposed-service', title: `Exposed Service: ${svc.name} at ${svc.path}`,
          severity: svc.severity, url: testUrl, parameter: 'Service Path',
          payload: svc.path,
          evidence: `${svc.name} service accessible at ${svc.path} - indicator "${svc.indicator}" found`,
          request: `GET ${testUrl}`,
          response: `HTTP ${resp.status} - ${svc.name} interface detected`,
          remediation: `Restrict access to ${svc.name}. Use authentication, IP allowlisting, or VPN.`,
          cwe: 'CWE-200', owasp: 'A05:2021 Security Misconfiguration',
        }));
      }

      await sleep(this.delay);
    }

    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // SENSITIVE FILES
  // ═══════════════════════════════════════════════════════════
  async scanSensitiveFiles(url, options = {}) {
    const findings = [];

    const sensitiveFiles = [
      { path: '/.env', indicator: ['DB_', 'APP_KEY', 'SECRET', 'PASSWORD', 'API_KEY'], severity: 'critical', desc: 'Environment variables' },
      { path: '/.env.local', indicator: ['DB_', 'SECRET'], severity: 'critical', desc: 'Local environment' },
      { path: '/.env.production', indicator: ['DB_', 'SECRET'], severity: 'critical', desc: 'Production environment' },
      { path: '/.env.backup', indicator: ['DB_', 'SECRET'], severity: 'critical', desc: 'Environment backup' },
      { path: '/wp-config.php', indicator: ['DB_NAME', 'DB_PASSWORD'], severity: 'critical', desc: 'WordPress config' },
      { path: '/wp-config.php.bak', indicator: ['DB_NAME', 'DB_PASSWORD'], severity: 'critical', desc: 'WordPress config backup' },
      { path: '/wp-config.php.old', indicator: ['DB_NAME', 'DB_PASSWORD'], severity: 'critical', desc: 'WordPress config old' },
      { path: '/configuration.php', indicator: ['password', 'secret'], severity: 'critical', desc: 'Joomla config' },
      { path: '/config/database.yml', indicator: ['password', 'adapter'], severity: 'critical', desc: 'Rails DB config' },
      { path: '/config/secrets.yml', indicator: ['secret_key_base'], severity: 'critical', desc: 'Rails secrets' },
      { path: '/appsettings.json', indicator: ['ConnectionStrings', 'Password'], severity: 'critical', desc: '.NET config' },
      { path: '/application.properties', indicator: ['spring.datasource', 'password'], severity: 'critical', desc: 'Spring config' },
      { path: '/application.yml', indicator: ['datasource', 'password'], severity: 'critical', desc: 'Spring YAML config' },
      { path: '/.git/config', indicator: ['[core]', '[remote'], severity: 'critical', desc: 'Git config' },
      { path: '/.git/HEAD', indicator: ['ref:'], severity: 'critical', desc: 'Git HEAD' },
      { path: '/.git/logs/HEAD', indicator: ['commit'], severity: 'critical', desc: 'Git logs' },
      { path: '/.htaccess', indicator: ['RewriteRule', 'Deny', 'Allow'], severity: 'medium', desc: 'Apache htaccess' },
      { path: '/.htpasswd', indicator: ['$apr1$', ':'], severity: 'critical', desc: 'Apache password file' },
      { path: '/web.config', indicator: ['configuration', 'system.web'], severity: 'high', desc: 'IIS config' },
      { path: '/nginx.conf', indicator: ['server', 'location'], severity: 'high', desc: 'Nginx config' },
      { path: '/package.json', indicator: ['dependencies', 'scripts'], severity: 'low', desc: 'Node.js package' },
      { path: '/package-lock.json', indicator: ['lockfileVersion'], severity: 'low', desc: 'Node.js lockfile' },
      { path: '/composer.json', indicator: ['require', 'autoload'], severity: 'low', desc: 'PHP Composer' },
      { path: '/Gemfile', indicator: ['source', 'gem'], severity: 'low', desc: 'Ruby Gemfile' },
      { path: '/requirements.txt', indicator: ['=='], severity: 'low', desc: 'Python requirements' },
      { path: '/go.mod', indicator: ['module', 'require'], severity: 'low', desc: 'Go modules' },
      { path: '/Dockerfile', indicator: ['FROM', 'RUN', 'EXPOSE'], severity: 'medium', desc: 'Dockerfile' },
      { path: '/docker-compose.yml', indicator: ['services', 'image'], severity: 'medium', desc: 'Docker Compose' },
      { path: '/docker-compose.yaml', indicator: ['services', 'image'], severity: 'medium', desc: 'Docker Compose' },
      { path: '/.gitlab-ci.yml', indicator: ['stages', 'script'], severity: 'low', desc: 'GitLab CI' },
      { path: '/Jenkinsfile', indicator: ['pipeline', 'stage'], severity: 'medium', desc: 'Jenkinsfile' },
      { path: '/id_rsa', indicator: ['PRIVATE KEY'], severity: 'critical', desc: 'SSH private key' },
      { path: '/server.key', indicator: ['PRIVATE KEY'], severity: 'critical', desc: 'SSL private key' },
      { path: '/credentials.json', indicator: ['client_id', 'client_secret'], severity: 'critical', desc: 'Credentials file' },
      { path: '/serviceAccountKey.json', indicator: ['private_key', 'client_email'], severity: 'critical', desc: 'GCP service account' },
      { path: '/.aws/credentials', indicator: ['aws_access_key_id'], severity: 'critical', desc: 'AWS credentials' },
      { path: '/error.log', indicator: ['error', 'warning', 'fatal'], severity: 'medium', desc: 'Error log' },
      { path: '/access.log', indicator: ['GET', 'POST', 'HTTP'], severity: 'medium', desc: 'Access log' },
      { path: '/debug.log', indicator: ['debug', 'trace'], severity: 'medium', desc: 'Debug log' },
      { path: '/firebase.json', indicator: ['apiKey', 'projectId'], severity: 'high', desc: 'Firebase config' },
      { path: '/crossdomain.xml', indicator: ['cross-domain-policy'], severity: 'low', desc: 'Flash crossdomain' },
      { path: '/.DS_Store', indicator: null, severity: 'low', desc: 'macOS DS_Store' },
    ];

    for (const file of sensitiveFiles) {
      const testUrl = `${url}${file.path}`;
      const resp = await httpGet(testUrl, { timeout: this.timeout });
      const body = typeof resp.data === 'string' ? resp.data : '';

      if (resp.status === 200 && body.length > 0) {
        let hasIndicator = false;
        if (file.indicator === null) {
          hasIndicator = true;
        } else if (Array.isArray(file.indicator)) {
          hasIndicator = file.indicator.some(ind => body.includes(ind));
        } else {
          hasIndicator = body.includes(file.indicator);
        }

        if (hasIndicator) {
          findings.push(this._createFinding({
            type: 'sensitive-file', title: `Sensitive File Exposed: ${file.path} (${file.desc})`,
            severity: file.severity, url: testUrl, parameter: 'File Path',
            payload: file.path,
            evidence: `${file.desc} accessible at ${file.path} (${body.length} bytes)`,
            request: `GET ${testUrl}`,
            response: `HTTP 200 - ${file.desc} content returned (${body.length} bytes)`,
            remediation: `Block access to ${file.path}. Add deny rules in web server config. Remove from web root.`,
            cwe: 'CWE-538', owasp: 'A05:2021 Security Misconfiguration',
          }));
        }
      }

      await sleep(this.delay);
    }

    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // DEBUG ENDPOINTS
  // ═══════════════════════════════════════════════════════════
  async scanDebugEndpoints(url, options = {}) {
    const findings = [];

    const debugEndpoints = [
      { path: '/debug', indicator: ['debug', 'trace', 'stack'], severity: 'high', desc: 'Debug endpoint' },
      { path: '/trace', indicator: ['trace', 'span'], severity: 'high', desc: 'Trace endpoint' },
      { path: '/_debug', indicator: ['debug'], severity: 'high', desc: 'Debug endpoint' },
      { path: '/actuator', indicator: ['_links', 'self'], severity: 'high', desc: 'Spring Actuator' },
      { path: '/actuator/health', indicator: ['status', 'UP'], severity: 'medium', desc: 'Actuator Health' },
      { path: '/actuator/env', indicator: ['propertySources', 'activeProfiles'], severity: 'critical', desc: 'Actuator Environment' },
      { path: '/actuator/configprops', indicator: ['contexts', 'beans'], severity: 'critical', desc: 'Actuator Config' },
      { path: '/actuator/mappings', indicator: ['contexts', 'dispatcherServlets'], severity: 'high', desc: 'Actuator Mappings' },
      { path: '/actuator/beans', indicator: ['contexts', 'beans'], severity: 'high', desc: 'Actuator Beans' },
      { path: '/actuator/heapdump', indicator: null, severity: 'critical', desc: 'Actuator Heap Dump' },
      { path: '/actuator/threaddump', indicator: ['threads', 'threadName'], severity: 'high', desc: 'Actuator Thread Dump' },
      { path: '/actuator/loggers', indicator: ['levels', 'loggers'], severity: 'medium', desc: 'Actuator Loggers' },
      { path: '/actuator/metrics', indicator: ['names'], severity: 'medium', desc: 'Actuator Metrics' },
      { path: '/actuator/shutdown', indicator: null, severity: 'critical', desc: 'Actuator Shutdown' },
      { path: '/server-status', indicator: ['Apache Server Status', 'Total accesses'], severity: 'high', desc: 'Apache Server Status' },
      { path: '/server-info', indicator: ['Apache Server Information', 'Module'], severity: 'high', desc: 'Apache Server Info' },
      { path: '/phpinfo.php', indicator: ['PHP Version', 'phpinfo()'], severity: 'high', desc: 'PHP Info' },
      { path: '/info.php', indicator: ['PHP Version', 'phpinfo()'], severity: 'high', desc: 'PHP Info' },
      { path: '/test.php', indicator: ['PHP Version', 'phpinfo'], severity: 'high', desc: 'PHP Test' },
      { path: '/_profiler', indicator: ['profiler', 'Symfony'], severity: 'high', desc: 'Symfony Profiler' },
      { path: '/_profiler/latest', indicator: ['profiler'], severity: 'high', desc: 'Symfony Profiler Latest' },
      { path: '/_wdt', indicator: ['profiler', 'sf-toolbar'], severity: 'medium', desc: 'Symfony Web Debug Toolbar' },
      { path: '/telescope', indicator: ['Laravel Telescope'], severity: 'high', desc: 'Laravel Telescope' },
      { path: '/horizon', indicator: ['Laravel Horizon'], severity: 'high', desc: 'Laravel Horizon' },
      { path: '/clockwork', indicator: ['clockwork'], severity: 'medium', desc: 'Clockwork Debugger' },
      { path: '/elmah.axd', indicator: ['Error Log', 'ELMAH'], severity: 'high', desc: 'ELMAH Error Log' },
      { path: '/trace.axd', indicator: ['Application Trace', 'Request Details'], severity: 'high', desc: '.NET Trace' },
      { path: '/glimpse.axd', indicator: ['Glimpse'], severity: 'medium', desc: 'Glimpse Debugger' },
      { path: '/debug/vars', indicator: ['cmdline', 'memstats'], severity: 'high', desc: 'Go Debug Vars' },
      { path: '/debug/pprof', indicator: ['Profile', 'goroutine'], severity: 'high', desc: 'Go pprof' },
      { path: '/__inspect', indicator: ['inspect'], severity: 'medium', desc: 'Node Inspector' },
      { path: '/metrics', indicator: ['process_', 'http_'], severity: 'medium', desc: 'Prometheus Metrics' },
      { path: '/stats', indicator: ['uptime', 'requests'], severity: 'medium', desc: 'Statistics' },
      { path: '/heapdump', indicator: null, severity: 'critical', desc: 'Heap Dump' },
      { path: '/dump', indicator: null, severity: 'high', desc: 'Memory/Data Dump' },
      { path: '/health', indicator: ['status', 'healthy', 'ok'], severity: 'info', desc: 'Health Check' },
      { path: '/healthcheck', indicator: ['status', 'healthy'], severity: 'info', desc: 'Health Check' },
    ];

    for (const ep of debugEndpoints) {
      const testUrl = `${url}${ep.path}`;
      const resp = await httpGet(testUrl, { timeout: this.timeout });
      const body = typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data || '');

      if (resp.status === 200 && body.length > 10) {
        let hasIndicator = false;
        if (ep.indicator === null) {
          hasIndicator = body.length > 100;
        } else if (Array.isArray(ep.indicator)) {
          hasIndicator = ep.indicator.some(ind => body.toLowerCase().includes(ind.toLowerCase()));
        } else {
          hasIndicator = body.toLowerCase().includes(ep.indicator.toLowerCase());
        }

        if (hasIndicator) {
          findings.push(this._createFinding({
            type: 'debug-endpoint', title: `Debug Endpoint Exposed: ${ep.path} (${ep.desc})`,
            severity: ep.severity, url: testUrl, parameter: 'Path',
            payload: ep.path,
            evidence: `${ep.desc} accessible at ${ep.path} - sensitive debug information exposed`,
            request: `GET ${testUrl}`,
            response: `HTTP 200 - ${ep.desc} content (${body.length} bytes)`,
            remediation: `Disable ${ep.desc} in production. Restrict access via authentication or IP allowlist.`,
            cwe: 'CWE-215', owasp: 'A05:2021 Security Misconfiguration',
          }));
        }
      }

      await sleep(this.delay);
    }

    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // API DOCUMENTATION
  // ═══════════════════════════════════════════════════════════
  async scanAPIDocumentation(url, options = {}) {
    const findings = [];

    const apiDocPaths = [
      { path: '/swagger', indicator: 'swagger', name: 'Swagger UI' },
      { path: '/swagger/', indicator: 'swagger', name: 'Swagger UI' },
      { path: '/swagger-ui', indicator: 'swagger', name: 'Swagger UI' },
      { path: '/swagger-ui/', indicator: 'swagger', name: 'Swagger UI' },
      { path: '/swagger-ui.html', indicator: 'swagger', name: 'Swagger UI' },
      { path: '/swagger/index.html', indicator: 'swagger', name: 'Swagger UI' },
      { path: '/swagger.json', indicator: 'swagger', name: 'Swagger JSON' },
      { path: '/swagger.yaml', indicator: 'swagger', name: 'Swagger YAML' },
      { path: '/api-docs', indicator: 'swagger', name: 'API Docs' },
      { path: '/api-docs/', indicator: 'swagger', name: 'API Docs' },
      { path: '/v1/api-docs', indicator: 'swagger', name: 'API Docs v1' },
      { path: '/v2/api-docs', indicator: 'swagger', name: 'API Docs v2' },
      { path: '/v3/api-docs', indicator: 'openapi', name: 'API Docs v3' },
      { path: '/openapi.json', indicator: 'openapi', name: 'OpenAPI JSON' },
      { path: '/openapi.yaml', indicator: 'openapi', name: 'OpenAPI YAML' },
      { path: '/openapi', indicator: 'openapi', name: 'OpenAPI' },
      { path: '/docs', indicator: ['api', 'endpoint', 'swagger'], name: 'API Documentation' },
      { path: '/redoc', indicator: 'redoc', name: 'ReDoc' },
      { path: '/api/docs', indicator: ['api', 'swagger'], name: 'API Docs' },
      { path: '/graphiql', indicator: 'graphiql', name: 'GraphiQL IDE' },
      { path: '/graphql/playground', indicator: 'playground', name: 'GraphQL Playground' },
      { path: '/playground', indicator: 'graphql', name: 'GraphQL Playground' },
      { path: '/altair', indicator: 'altair', name: 'Altair GraphQL' },
      { path: '/voyager', indicator: 'voyager', name: 'GraphQL Voyager' },
      { path: '/_catalog', indicator: 'repositories', name: 'Docker Registry Catalog' },
    ];

    for (const doc of apiDocPaths) {
      const testUrl = `${url}${doc.path}`;
      const resp = await httpGet(testUrl, { timeout: this.timeout });
      const body = typeof resp.data === 'string' ? resp.data.toLowerCase() : JSON.stringify(resp.data || '').toLowerCase();

      if (resp.status === 200) {
        let hasIndicator = false;
        if (Array.isArray(doc.indicator)) {
          hasIndicator = doc.indicator.some(ind => body.includes(ind.toLowerCase()));
        } else {
          hasIndicator = body.includes(doc.indicator.toLowerCase());
        }

        if (hasIndicator) {
          findings.push(this._createFinding({
            type: 'api-documentation', title: `API Documentation Exposed: ${doc.name} at ${doc.path}`,
            severity: 'medium', url: testUrl, parameter: 'Path',
            payload: doc.path,
            evidence: `${doc.name} accessible at ${doc.path} - API structure and endpoints disclosed`,
            request: `GET ${testUrl}`,
            response: `HTTP 200 - ${doc.name} interface/content detected`,
            remediation: 'Restrict API documentation access in production. Require authentication.',
            cwe: 'CWE-200', owasp: 'A05:2021 Security Misconfiguration',
          }));
        }
      }

      await sleep(this.delay);
    }

    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // BACKUP FILES
  // ═══════════════════════════════════════════════════════════
  async scanBackupFiles(url, options = {}) {
    const findings = [];
    const parsedUrl = new URL(url);
    const domain = parsedUrl.hostname.replace(/\./g, '_');
    const domainShort = parsedUrl.hostname.split('.')[0];

    const backupPaths = [
      '/backup.zip', '/backup.tar.gz', '/backup.tar', '/backup.sql',
      '/backup.sql.gz', '/backup.rar', '/backup.7z',
      '/site.zip', '/site.tar.gz', '/website.zip',
      '/db.sql', '/db.sql.gz', '/database.sql', '/database.sql.gz',
      '/dump.sql', '/dump.sql.gz', '/data.sql',
      '/mysql.sql', '/mysql_dump.sql',
      `/${domain}.zip`, `/${domain}.tar.gz`, `/${domain}.sql`,
      `/${domainShort}.zip`, `/${domainShort}.tar.gz`, `/${domainShort}.sql`,
      `/${domainShort}_backup.zip`, `/${domainShort}_db.sql`,
      '/backup_2024.zip', '/backup_2023.zip',
      '/db_backup_latest.sql', '/latest_backup.zip',
      '/wp-content/backup', '/wp-content/backups',
      '/index.php.bak', '/index.php.old',
      '/config.php.bak', '/config.php.old',
      '/web.config.bak', '/web.config.old',
      '/.env.bak', '/.env.old', '/.env.save',
      '/archive.zip', '/archive.tar.gz',
      '/old.zip', '/temp.zip',
      '/export.sql', '/export.csv',
      '/users.sql', '/users.csv',
      '/data.json', '/export.json',
    ];

    for (const path of backupPaths) {
      const testUrl = `${url}${path}`;
      const resp = await httpGet(testUrl, { timeout: this.timeout });

      if (resp.status === 200) {
        const contentType = resp.headers?.['content-type'] || '';
        const contentLength = resp.headers?.['content-length'] || '0';
        const body = typeof resp.data === 'string' ? resp.data : '';

        const isArchive = contentType.includes('zip') || contentType.includes('gzip') ||
                         contentType.includes('tar') || contentType.includes('octet-stream') ||
                         contentType.includes('x-rar');
        const isSql = body.includes('CREATE TABLE') || body.includes('INSERT INTO') ||
                     body.includes('DROP TABLE') || body.includes('mysqldump');
        const isConfig = body.includes('DB_') || body.includes('password') ||
                        body.includes('<?php') || body.includes('secret');
        const isLargeFile = parseInt(contentLength) > 1000;

        if (isArchive || isSql || isConfig || isLargeFile) {
          const fileType = isArchive ? 'Archive' : isSql ? 'SQL Dump' : isConfig ? 'Config Backup' : 'Large File';
          findings.push(this._createFinding({
            type: 'backup-file', title: `Backup File Exposed: ${path} (${fileType})`,
            severity: isSql || isConfig ? 'critical' : 'high',
            url: testUrl, parameter: 'File Path',
            payload: path,
            evidence: `${fileType} accessible at ${path} (Content-Type: ${contentType}, Size: ${contentLength} bytes)`,
            request: `GET ${testUrl}`,
            response: `HTTP 200 - ${fileType} detected (${contentLength} bytes)`,
            remediation: 'Remove backup files from web root. Block access to backup extensions in web server config.',
            cwe: 'CWE-530', owasp: 'A05:2021 Security Misconfiguration',
          }));
        }
      }

      await sleep(this.delay);
    }

    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // SOURCE CODE EXPOSURE
  // ═══════════════════════════════════════════════════════════
  async scanSourceCodeExposure(url, options = {}) {
    const findings = [];

    // Git directory reconstruction
    const gitPaths = [
      { path: '/.git/config', indicator: '[core]', desc: 'Git configuration' },
      { path: '/.git/HEAD', indicator: 'ref:', desc: 'Git HEAD reference' },
      { path: '/.git/index', indicator: null, desc: 'Git index (binary)' },
      { path: '/.git/logs/HEAD', indicator: 'commit', desc: 'Git commit log' },
      { path: '/.git/packed-refs', indicator: 'refs/', desc: 'Git packed references' },
      { path: '/.git/objects/info/packs', indicator: 'pack-', desc: 'Git pack info' },
      { path: '/.git/COMMIT_EDITMSG', indicator: null, desc: 'Last commit message' },
    ];

    let gitExposed = false;
    for (const gp of gitPaths) {
      const testUrl = `${url}${gp.path}`;
      const resp = await httpGet(testUrl, { timeout: this.timeout });
      const body = typeof resp.data === 'string' ? resp.data : '';

      if (resp.status === 200) {
        const hasIndicator = gp.indicator === null ? body.length > 0 : body.includes(gp.indicator);
        if (hasIndicator && !gitExposed) {
          findings.push(this._createFinding({
            type: 'git-exposed', title: '.git Directory Exposed - Full Source Code Reconstruction Possible',
            severity: 'critical', url: `${url}/.git/`, parameter: '.git directory',
            payload: '/.git/',
            evidence: `Git repository data accessible. File found: ${gp.path}. Full source code can be reconstructed.`,
            request: `GET ${testUrl}`,
            response: `HTTP 200 - Git ${gp.desc} accessible`,
            remediation: 'Block access to .git directory. Add deny rules in web server configuration.',
            cwe: 'CWE-527', owasp: 'A05:2021 Security Misconfiguration',
          }));
          gitExposed = true;
        }
      }
    }

    // SVN exposure
    const svnResp = await httpGet(`${url}/.svn/entries`, { timeout: this.timeout });
    const svnBody = typeof svnResp.data === 'string' ? svnResp.data : '';
    if (svnResp.status === 200 && (svnBody.includes('dir') || svnBody.length > 0)) {
      findings.push(this._createFinding({
        type: 'svn-exposed', title: '.svn Directory Exposed',
        severity: 'critical', url: `${url}/.svn/`, parameter: '.svn directory',
        payload: '/.svn/entries',
        evidence: 'SVN repository data accessible. Source code may be reconstructable.',
        request: `GET ${url}/.svn/entries`,
        response: `HTTP 200 - SVN entries accessible`,
        remediation: 'Block access to .svn directory. Remove version control data from production.',
        cwe: 'CWE-527', owasp: 'A05:2021 Security Misconfiguration',
      }));
    }

    // Mercurial exposure
    const hgResp = await httpGet(`${url}/.hg/store/00manifest.i`, { timeout: this.timeout });
    if (hgResp.status === 200) {
      findings.push(this._createFinding({
        type: 'hg-exposed', title: '.hg Directory Exposed (Mercurial)',
        severity: 'critical', url: `${url}/.hg/`, parameter: '.hg directory',
        payload: '/.hg/store/00manifest.i',
        evidence: 'Mercurial repository data accessible. Source code can be reconstructed.',
        request: `GET ${url}/.hg/store/00manifest.i`,
        response: 'HTTP 200 - Mercurial manifest accessible',
        remediation: 'Block access to .hg directory. Remove version control data from production.',
        cwe: 'CWE-527', owasp: 'A05:2021 Security Misconfiguration',
      }));
    }

    // Source map files
    const sourceMapPaths = ['/main.js.map', '/app.js.map', '/bundle.js.map', '/vendor.js.map', '/chunk.js.map'];
    for (const smp of sourceMapPaths) {
      const testUrl = `${url}${smp}`;
      const resp = await httpGet(testUrl, { timeout: this.timeout });
      const body = typeof resp.data === 'string' ? resp.data : '';

      if (resp.status === 200 && (body.includes('"sources"') || body.includes('"mappings"'))) {
        findings.push(this._createFinding({
          type: 'sourcemap-exposed', title: `Source Map Exposed: ${smp}`,
          severity: 'medium', url: testUrl, parameter: 'Source Map',
          payload: smp,
          evidence: 'JavaScript source map accessible - original source code can be reconstructed',
          request: `GET ${testUrl}`,
          response: 'HTTP 200 - Source map with original sources',
          remediation: 'Remove source maps from production. Configure build tools to exclude .map files.',
          cwe: 'CWE-540', owasp: 'A05:2021 Security Misconfiguration',
        }));
      }
    }

    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // DIRECTORY LISTING
  // ═══════════════════════════════════════════════════════════
  async scanDirectoryListing(url, options = {}) {
    const findings = [];
    const indicators = ['Index of', 'Directory listing', 'Parent Directory', '[To Parent Directory]', '<title>Index of'];

    const paths = [
      '/', '/images/', '/uploads/', '/backup/', '/admin/', '/api/',
      '/assets/', '/static/', '/media/', '/files/', '/data/',
      '/tmp/', '/temp/', '/logs/', '/config/', '/includes/',
      '/lib/', '/vendor/', '/node_modules/', '/wp-content/uploads/',
    ];

    for (const path of paths) {
      const testUrl = `${url}${path}`;
      const resp = await httpGet(testUrl, { timeout: this.timeout });
      const body = typeof resp.data === 'string' ? resp.data : '';

      if (resp.status === 200 && indicators.some(i => body.includes(i))) {
        findings.push(this._createFinding({
          type: 'directory-listing', title: `Directory Listing Enabled: ${path}`,
          severity: 'medium', url: testUrl, parameter: 'Path',
          payload: path,
          evidence: `Directory listing found at ${path} - file structure exposed`,
          request: `GET ${testUrl}`,
          response: `HTTP 200 - "Index of" or directory listing indicators in response`,
          remediation: 'Disable directory listing in web server configuration (Options -Indexes for Apache).',
          cwe: 'CWE-548', owasp: 'A05:2021 Security Misconfiguration',
        }));
      }

      await sleep(this.delay);
    }

    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // VERSION DISCLOSURE
  // ═══════════════════════════════════════════════════════════
  async scanVersionDisclosure(url, options = {}) {
    const findings = [];
    const resp = await httpGet(url, { timeout: this.timeout });
    const headers = resp.headers || {};
    const body = typeof resp.data === 'string' ? resp.data : '';

    // Server header version
    if (headers['server']) {
      const serverHeader = headers['server'];
      const versionMatch = serverHeader.match(/[\d]+\.[\d]+/);
      if (versionMatch) {
        findings.push(this._createFinding({
          type: 'version-disclosure', title: `Server Version Disclosed: ${serverHeader}`,
          severity: 'low', url, parameter: 'Server header',
          payload: serverHeader,
          evidence: `Server header reveals version: ${serverHeader}`,
          request: `GET ${url}`,
          response: `Server: ${serverHeader}`,
          remediation: 'Remove or obfuscate the Server header. Hide version information.',
          cwe: 'CWE-200', owasp: 'A05:2021 Security Misconfiguration',
        }));
      }
    }

    // X-Powered-By header
    if (headers['x-powered-by']) {
      findings.push(this._createFinding({
        type: 'version-disclosure', title: `Technology Disclosed: X-Powered-By: ${headers['x-powered-by']}`,
        severity: 'low', url, parameter: 'X-Powered-By header',
        payload: headers['x-powered-by'],
        evidence: `X-Powered-By header reveals technology: ${headers['x-powered-by']}`,
        request: `GET ${url}`,
        response: `X-Powered-By: ${headers['x-powered-by']}`,
        remediation: 'Remove X-Powered-By header from responses.',
        cwe: 'CWE-200', owasp: 'A05:2021 Security Misconfiguration',
      }));
    }

    // X-AspNet-Version
    if (headers['x-aspnet-version']) {
      findings.push(this._createFinding({
        type: 'version-disclosure', title: `ASP.NET Version Disclosed: ${headers['x-aspnet-version']}`,
        severity: 'low', url, parameter: 'X-AspNet-Version header',
        payload: headers['x-aspnet-version'],
        evidence: `ASP.NET version exposed: ${headers['x-aspnet-version']}`,
        request: `GET ${url}`,
        response: `X-AspNet-Version: ${headers['x-aspnet-version']}`,
        remediation: 'Remove X-AspNet-Version header. Set enableVersionHeader="false" in web.config.',
        cwe: 'CWE-200', owasp: 'A05:2021 Security Misconfiguration',
      }));
    }

    // WordPress version in meta/links
    const wpVersion = body.match(/content="WordPress ([\d.]+)"/i) || body.match(/ver=([\d.]+)/);
    if (wpVersion) {
      findings.push(this._createFinding({
        type: 'version-disclosure', title: `WordPress Version Disclosed: ${wpVersion[1]}`,
        severity: 'low', url, parameter: 'HTML meta/link',
        payload: wpVersion[1],
        evidence: `WordPress version ${wpVersion[1]} found in page source`,
        request: `GET ${url}`,
        response: `WordPress ${wpVersion[1]} detected in HTML`,
        remediation: 'Remove WordPress version from HTML output. Use security plugins to hide version.',
        cwe: 'CWE-200', owasp: 'A05:2021 Security Misconfiguration',
      }));
    }

    // Generator meta tag
    const generator = body.match(/<meta[^>]*name=["']generator["'][^>]*content=["']([^"']+)["']/i);
    if (generator && !generator[1].toLowerCase().includes('wordpress')) {
      findings.push(this._createFinding({
        type: 'version-disclosure', title: `Generator Disclosed: ${generator[1]}`,
        severity: 'low', url, parameter: 'meta generator',
        payload: generator[1],
        evidence: `Generator meta tag reveals: ${generator[1]}`,
        request: `GET ${url}`,
        response: `<meta name="generator" content="${generator[1]}">`,
        remediation: 'Remove generator meta tag from HTML output.',
        cwe: 'CWE-200', owasp: 'A05:2021 Security Misconfiguration',
      }));
    }

    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // DEFAULT CREDENTIALS
  // ═══════════════════════════════════════════════════════════
  async scanDefaultCredentials(url, options = {}) {
    const findings = [];

    const loginEndpoints = [
      { path: '/admin/login', type: 'Admin Panel' },
      { path: '/admin', type: 'Admin Panel' },
      { path: '/login', type: 'Login Page' },
      { path: '/wp-login.php', type: 'WordPress' },
      { path: '/administrator', type: 'Joomla' },
      { path: '/user/login', type: 'Drupal' },
    ];

    const defaultCreds = [
      { username: 'admin', password: 'admin' },
      { username: 'admin', password: 'password' },
      { username: 'admin', password: '123456' },
      { username: 'admin', password: 'admin123' },
      { username: 'administrator', password: 'administrator' },
      { username: 'root', password: 'root' },
      { username: 'root', password: 'toor' },
      { username: 'root', password: 'password' },
      { username: 'test', password: 'test' },
      { username: 'user', password: 'user' },
      { username: 'guest', password: 'guest' },
      { username: 'demo', password: 'demo' },
      { username: 'admin', password: 'changeme' },
      { username: 'admin', password: 'default' },
      { username: 'admin', password: '' },
    ];

    for (const endpoint of loginEndpoints) {
      const loginUrl = `${url}${endpoint.path}`;
      const pageResp = await httpGet(loginUrl, { timeout: this.timeout });
      const pageBody = typeof pageResp.data === 'string' ? pageResp.data.toLowerCase() : '';

      // Only test if it looks like a login page
      if (pageResp.status !== 200 || !pageBody.includes('password')) continue;

      // Detect form action and field names
      const formAction = pageBody.match(/action=["']([^"']+)["']/)?.[1] || endpoint.path;
      const usernameField = pageBody.match(/name=["'](user|username|email|login|usr|uname)["']/i)?.[1] || 'username';
      const passwordField = pageBody.match(/name=["'](pass|password|passwd|pwd)["']/i)?.[1] || 'password';

      for (const cred of defaultCreds) {
        const postData = `${usernameField}=${encodeURIComponent(cred.username)}&${passwordField}=${encodeURIComponent(cred.password)}`;
        const actionUrl = formAction.startsWith('http') ? formAction : `${url}${formAction}`;

        const loginResp = await httpPost(actionUrl, postData, {
          timeout: this.timeout,
          contentType: 'application/x-www-form-urlencoded',
          headers: { 'Referer': loginUrl },
        });

        const loginBody = typeof loginResp.data === 'string' ? loginResp.data.toLowerCase() : '';
        const loginHeaders = loginResp.headers || {};

        // Detect successful login indicators
        const hasRedirectToDashboard = loginHeaders['location'] && (
          loginHeaders['location'].includes('dashboard') ||
          loginHeaders['location'].includes('admin') ||
          loginHeaders['location'].includes('home') ||
          loginHeaders['location'].includes('panel')
        );
        const hasSessionCookie = loginHeaders['set-cookie'] && /sess|auth|token/i.test(loginHeaders['set-cookie'].toString());
        const noErrorMessage = !loginBody.includes('invalid') && !loginBody.includes('incorrect') &&
                              !loginBody.includes('failed') && !loginBody.includes('error');
        const hasWelcome = loginBody.includes('welcome') || loginBody.includes('dashboard') || loginBody.includes('logout');

        if (hasRedirectToDashboard || (hasSessionCookie && noErrorMessage) || hasWelcome) {
          findings.push(this._createFinding({
            type: 'default-credentials', title: `Default Credentials Work: ${cred.username}:${cred.password} at ${endpoint.path}`,
            severity: 'critical', url: loginUrl, parameter: `${usernameField}/${passwordField}`,
            payload: `${cred.username}:${cred.password}`,
            evidence: `Login successful with ${cred.username}:${cred.password} on ${endpoint.type}`,
            request: `POST ${actionUrl}\n${usernameField}=${cred.username}&${passwordField}=***`,
            response: `HTTP ${loginResp.status}${hasRedirectToDashboard ? ' -> ' + loginHeaders['location'] : ''} - Login accepted`,
            remediation: 'Change default credentials immediately. Enforce strong password policy. Implement account lockout.',
            cwe: 'CWE-798', owasp: 'A07:2021 Identification and Authentication Failures',
          }));
          break; // Found working creds for this endpoint, move on
        }

        await sleep(this.delay);
      }
    }

    return findings;
  }

  // ═══════════════════════════════════════════════════════════
  // HELPER METHODS
  // ═══════════════════════════════════════════════════════════
  _getBaseUrl(url) {
    try {
      const parsed = new URL(url);
      return `${parsed.protocol}//${parsed.host}`;
    } catch {
      return url.replace(/\/[^/]*$/, '');
    }
  }

  _createFinding(data) {
    return {
      id: generateId(data.type.toUpperCase().replace(/[^A-Z]/g, '').slice(0, 5)),
      type: data.type,
      title: data.title,
      severity: data.severity,
      url: data.url,
      parameter: data.parameter,
      payload: data.payload,
      evidence: data.evidence,
      request: data.request,
      response: data.response,
      remediation: data.remediation,
      cwe: data.cwe,
      owasp: data.owasp,
      timestamp: new Date().toISOString(),
    };
  }
}

export default InfraScanner;
