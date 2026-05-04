// Parameter Discovery Wordlist - Bug Bounty Toolkit
// Comprehensive parameter lists for web application testing
// Used for parameter brute-forcing, hidden parameter discovery, and injection testing

/**
 * COMMON_PARAMS - 500+ most common web parameters found in the wild
 * Gathered from public bug bounty reports, web crawls, and application testing
 */
export const COMMON_PARAMS = [
  // Identification & Pagination
  'id', 'Id', 'ID', 'uid', 'pid', 'sid', 'oid', 'tid', 'cid', 'rid',
  'page', 'p', 'pg', 'pagenum', 'page_num', 'pageNumber', 'paging',
  'limit', 'offset', 'start', 'end', 'count', 'size', 'per_page', 'perPage',
  'num', 'number', 'max', 'min', 'from', 'to', 'skip', 'take',
  
  // Search & Query
  'search', 'q', 'query', 'keyword', 'keywords', 'term', 'terms', 'find',
  'lookup', 'filter', 'filters', 's', 'w', 'text', 'input', 'phrase',
  'searchQuery', 'search_query', 'searchTerm', 'search_term',
  
  // Sorting & Ordering
  'sort', 'sortby', 'sort_by', 'sortBy', 'order', 'orderby', 'order_by',
  'orderBy', 'dir', 'direction', 'asc', 'desc', 'sort_order', 'sortOrder',
  'sort_field', 'sortField', 'sort_dir', 'sortDir',
  
  // URLs & Redirects
  'url', 'uri', 'link', 'href', 'src', 'source', 'dest', 'destination',
  'redirect', 'redirect_url', 'redirect_uri', 'return', 'returnUrl',
  'return_url', 'returnTo', 'return_to', 'next', 'goto', 'go', 'target',
  'rurl', 'redir', 'forward', 'forward_url', 'continue', 'continueTo',
  
  // File & Path
  'file', 'filename', 'filepath', 'path', 'folder', 'dir', 'directory',
  'doc', 'document', 'pdf', 'img', 'image', 'pic', 'photo', 'media',
  'attachment', 'upload', 'download', 'load', 'read', 'include', 'require',
  'template', 'tpl', 'view', 'layout', 'theme', 'style', 'stylesheet',
  
  // User & Account
  'user', 'username', 'login', 'email', 'mail', 'name', 'firstname',
  'lastname', 'first_name', 'last_name', 'fullname', 'full_name',
  'account', 'profile', 'member', 'customer', 'client', 'contact',
  'phone', 'mobile', 'tel', 'address', 'city', 'state', 'country', 'zip',
  
  // Authentication
  'password', 'pass', 'passwd', 'pwd', 'token', 'auth', 'key', 'apikey',
  'api_key', 'secret', 'session', 'sessionid', 'session_id', 'cookie',
  'csrf', 'csrf_token', 'csrfToken', '_token', 'nonce', 'hash',
  
  // Content & Data
  'content', 'body', 'data', 'payload', 'message', 'msg', 'comment',
  'description', 'desc', 'title', 'subject', 'heading', 'label',
  'value', 'val', 'param', 'parameter', 'field', 'attribute', 'attr',
  'property', 'prop', 'item', 'element', 'entry', 'record', 'row',
  
  // Actions & Operations
  'action', 'act', 'do', 'cmd', 'command', 'exec', 'execute', 'run',
  'op', 'operation', 'func', 'function', 'method', 'mode', 'type',
  'task', 'job', 'process', 'step', 'stage', 'phase', 'event',
  'trigger', 'handler', 'callback', 'hook', 'signal',
  
  // Format & Display
  'format', 'fmt', 'output', 'render', 'display', 'show', 'hide',
  'visible', 'hidden', 'view', 'layout', 'template', 'theme', 'skin',
  'lang', 'language', 'locale', 'i18n', 'l10n', 'translate', 'charset',
  'encoding', 'content_type', 'contentType', 'mime', 'accept',
  
  // Category & Classification
  'category', 'cat', 'categories', 'tag', 'tags', 'label', 'labels',
  'group', 'groups', 'class', 'classes', 'type', 'types', 'kind',
  'section', 'sector', 'segment', 'division', 'department', 'dept',
  
  // Date & Time
  'date', 'time', 'datetime', 'timestamp', 'ts', 'year', 'month', 'day',
  'hour', 'minute', 'second', 'week', 'period', 'duration', 'interval',
  'start_date', 'end_date', 'startDate', 'endDate', 'from_date', 'to_date',
  'created', 'updated', 'modified', 'deleted', 'expires', 'expiry',
  
  // Status & State
  'status', 'state', 'condition', 'active', 'enabled', 'disabled',
  'published', 'draft', 'pending', 'approved', 'rejected', 'archived',
  'deleted', 'removed', 'blocked', 'banned', 'suspended', 'locked',
  'verified', 'confirmed', 'completed', 'finished', 'done',
  
  // Numeric & Quantity
  'amount', 'total', 'sum', 'price', 'cost', 'fee', 'rate', 'tax',
  'discount', 'quantity', 'qty', 'weight', 'height', 'width', 'length',
  'depth', 'volume', 'area', 'distance', 'speed', 'score', 'rating',
  
  // Boolean & Flags
  'flag', 'bool', 'boolean', 'true', 'false', 'yes', 'no', 'on', 'off',
  'enable', 'disable', 'allow', 'deny', 'permit', 'block', 'grant',
  'is_admin', 'isAdmin', 'is_active', 'isActive', 'is_verified',
  
  // API & Integration
  'api', 'version', 'v', 'ver', 'api_version', 'apiVersion',
  'client', 'client_id', 'clientId', 'app', 'app_id', 'appId',
  'platform', 'device', 'os', 'browser', 'agent', 'user_agent',
  'channel', 'source', 'medium', 'campaign', 'ref', 'referrer',
  
  // Database & Technical
  'table', 'column', 'col', 'field', 'index', 'key', 'pk', 'fk',
  'db', 'database', 'schema', 'collection', 'model', 'entity',
  'join', 'where', 'having', 'group_by', 'order_by', 'limit',
  'select', 'insert', 'update', 'delete', 'create', 'drop',
  
  // Network & Server
  'host', 'hostname', 'domain', 'subdomain', 'port', 'protocol',
  'ip', 'ipaddress', 'ip_address', 'server', 'proxy', 'gateway',
  'endpoint', 'route', 'path', 'base', 'root', 'prefix', 'suffix',
  
  // Media & Content
  'width', 'height', 'w', 'h', 'quality', 'resolution', 'dpi',
  'crop', 'resize', 'scale', 'rotate', 'flip', 'mirror', 'blur',
  'brightness', 'contrast', 'saturation', 'opacity', 'alpha',
  'thumbnail', 'thumb', 'preview', 'poster', 'cover', 'banner',
  
  // E-commerce
  'product', 'product_id', 'productId', 'item', 'item_id', 'itemId',
  'sku', 'upc', 'barcode', 'cart', 'cart_id', 'cartId', 'basket',
  'order', 'order_id', 'orderId', 'invoice', 'invoice_id', 'invoiceId',
  'payment', 'payment_id', 'paymentId', 'transaction', 'transaction_id',
  'shipping', 'delivery', 'tracking', 'coupon', 'promo', 'voucher',
  
  // Social & Communication
  'post', 'post_id', 'postId', 'thread', 'thread_id', 'threadId',
  'reply', 'reply_id', 'replyId', 'share', 'like', 'follow',
  'friend', 'connection', 'notification', 'alert', 'inbox', 'outbox',
  'chat', 'conversation', 'channel', 'room', 'group',
  
  // Miscellaneous Common
  'ref', 'reference', 'code', 'pin', 'otp', 'captcha', 'recaptcha',
  'g-recaptcha-response', 'h-captcha-response', 'turnstile',
  'consent', 'agree', 'terms', 'privacy', 'gdpr', 'cookie_consent',
  'newsletter', 'subscribe', 'unsubscribe', 'opt_in', 'opt_out',
  'debug', 'test', 'demo', 'sample', 'example', 'mock', 'fake',
  'preview', 'draft', 'staging', 'production', 'environment', 'env',
  'config', 'settings', 'preferences', 'options', 'params', 'args',
  'module', 'plugin', 'extension', 'addon', 'widget', 'component',
  'scope', 'context', 'namespace', 'prefix', 'suffix', 'delimiter',
  'separator', 'wrapper', 'container', 'parent', 'child', 'sibling',
  'depth', 'level', 'tier', 'rank', 'priority', 'weight', 'position',
  'index', 'cursor', 'pointer', 'marker', 'anchor', 'bookmark',
  'tab', 'panel', 'pane', 'window', 'frame', 'iframe', 'popup',
  'modal', 'dialog', 'overlay', 'tooltip', 'dropdown', 'menu',
  'nav', 'navigation', 'breadcrumb', 'sidebar', 'header', 'footer',
  'banner', 'hero', 'carousel', 'slider', 'gallery', 'grid', 'list',
  'map', 'chart', 'graph', 'table', 'form', 'wizard', 'stepper',
  'tab_id', 'panel_id', 'section_id', 'block_id', 'widget_id',
  'returnurl', 'backurl', 'back_url', 'success_url', 'error_url',
  'cancel_url', 'failure_url', 'confirm_url', 'verify_url',
];

/**
 * HIDDEN_PARAMS - 300+ hidden/debug parameters
 * Parameters often left in production that reveal debug info or unlock hidden features
 */
export const HIDDEN_PARAMS = [
  // Debug & Testing
  'debug', 'Debug', 'DEBUG', '_debug', 'dbg', 'debugging', 'debug_mode',
  'debugMode', 'debug_level', 'debugLevel', 'debug_output', 'debugOutput',
  'test', 'Test', 'TEST', '_test', 'testing', 'test_mode', 'testMode',
  'tester', 'qa', 'QA', 'quality', 'check', 'validate', 'verify',
  
  // Admin & Internal
  'admin', 'Admin', 'ADMIN', '_admin', 'administrator', 'superadmin',
  'super_admin', 'superAdmin', 'root', 'sudo', 'su', 'elevated',
  'internal', 'Internal', '_internal', 'private', 'restricted',
  'hidden', 'secret', 'confidential', 'classified', 'sensitive',
  'staff', 'employee', 'operator', 'moderator', 'mod', 'manager',
  
  // Verbose & Logging
  'verbose', 'Verbose', 'VERBOSE', 'v', 'vv', 'vvv', 'verbosity',
  'trace', 'Trace', 'TRACE', 'tracing', 'trace_id', 'traceId',
  'log', 'Log', 'LOG', 'logging', 'log_level', 'logLevel', 'loglevel',
  'logger', 'audit', 'monitor', 'monitoring', 'observe', 'watch',
  
  // Source & Code
  'source', 'src', 'sourcecode', 'source_code', 'sourceCode',
  'code', 'raw', 'plain', 'plaintext', 'text', 'markup', 'markdown',
  'show_source', 'showSource', 'view_source', 'viewSource',
  'disclose', 'reveal', 'expose', 'dump', 'export',
  
  // Configuration
  'config', 'Config', 'CONFIG', '_config', 'configuration', 'conf',
  'settings', 'Settings', 'SETTINGS', '_settings', 'prefs', 'preferences',
  'setup', 'init', 'initialize', 'bootstrap', 'startup', 'boot',
  'env', 'environment', 'ENV', 'ENVIRONMENT', 'enviroment',
  
  // Feature Flags
  'feature', 'features', 'feature_flag', 'featureFlag', 'ff',
  'flag', 'flags', 'toggle', 'toggles', 'switch', 'switches',
  'experiment', 'experiments', 'variant', 'variants', 'ab', 'abtest',
  'ab_test', 'abTest', 'split', 'bucket', 'cohort', 'segment',
  'beta', 'alpha', 'canary', 'preview', 'early_access', 'earlyAccess',
  'lab', 'labs', 'experimental', 'unstable', 'nightly', 'dev',
  
  // Bypass & Override
  'bypass', 'skip', 'ignore', 'override', 'overwrite', 'force',
  'disable', 'nocheck', 'no_check', 'novalidate', 'no_validate',
  'nocache', 'no_cache', 'noCache', 'cache_bust', 'cacheBust',
  'nolimit', 'no_limit', 'noLimit', 'unlimited', 'unrestricted',
  'noauth', 'no_auth', 'noAuth', 'skip_auth', 'skipAuth',
  'nofilter', 'no_filter', 'noFilter', 'unfiltered', 'raw',
  'nosecurity', 'no_security', 'noSecurity', 'insecure', 'unsafe',
  'nowaf', 'no_waf', 'noWaf', 'bypass_waf', 'bypassWaf',
  
  // Profiling & Performance
  'profile', 'profiling', 'profiler', 'perf', 'performance',
  'benchmark', 'bench', 'timing', 'timer', 'elapsed', 'duration',
  'metrics', 'stats', 'statistics', 'analytics', 'telemetry',
  'measure', 'instrument', 'instrumentation', 'apm', 'newrelic',
  'datadog', 'sentry', 'bugsnag', 'rollbar', 'airbrake',
  
  // Error & Exception
  'error', 'errors', 'exception', 'exceptions', 'throw', 'catch',
  'stacktrace', 'stack_trace', 'stackTrace', 'backtrace', 'traceback',
  'show_errors', 'showErrors', 'display_errors', 'displayErrors',
  'error_reporting', 'errorReporting', 'error_level', 'errorLevel',
  'fail', 'failure', 'fault', 'panic', 'crash', 'abort',
  
  // Database & Backend
  'sql', 'SQL', 'mysql', 'postgres', 'mongodb', 'redis', 'elastic',
  'query_log', 'queryLog', 'slow_query', 'slowQuery', 'explain',
  'db_debug', 'dbDebug', 'orm_debug', 'ormDebug', 'migration',
  'seed', 'fixture', 'factory', 'mock', 'stub', 'fake', 'dummy',
  
  // Framework-specific
  'XDEBUG_SESSION', 'XDEBUG_SESSION_START', 'XDEBUG_PROFILE',
  'XDEBUG_TRACE', 'PHPSTORM', 'VSCODE', 'phpinfo', 'php_info',
  'laravel_debug', 'symfony_debug', 'django_debug', 'rails_debug',
  'spring_debug', 'express_debug', 'flask_debug', 'fastapi_debug',
  'wp_debug', 'WP_DEBUG', 'WORDPRESS_DEBUG', 'joomla_debug',
  'drupal_debug', 'magento_debug', 'shopify_debug',
  
  // API & Documentation
  'swagger', 'openapi', 'graphql', 'graphiql', 'playground',
  'explorer', 'sandbox', 'console', 'terminal', 'shell', 'repl',
  'docs', 'documentation', 'api_docs', 'apiDocs', 'spec', 'schema',
  'introspection', 'reflection', 'metadata', 'meta', 'info',
  
  // Security & Auth Debug
  'jwt_debug', 'jwtDebug', 'token_debug', 'tokenDebug',
  'auth_debug', 'authDebug', 'session_debug', 'sessionDebug',
  'permission_debug', 'permissionDebug', 'role_debug', 'roleDebug',
  'acl_debug', 'aclDebug', 'rbac_debug', 'rbacDebug',
  'cors_debug', 'corsDebug', 'csp_debug', 'cspDebug',
  
  // Rendering & Template
  'render_debug', 'renderDebug', 'template_debug', 'templateDebug',
  'view_debug', 'viewDebug', 'layout_debug', 'layoutDebug',
  'cache_debug', 'cacheDebug', 'asset_debug', 'assetDebug',
  'minify', 'compress', 'optimize', 'bundle', 'webpack',
  'sourcemap', 'source_map', 'sourceMap', 'map',
  
  // Network & Request
  'request_debug', 'requestDebug', 'response_debug', 'responseDebug',
  'http_debug', 'httpDebug', 'curl_debug', 'curlDebug',
  'proxy_debug', 'proxyDebug', 'ssl_debug', 'sslDebug',
  'dns_debug', 'dnsDebug', 'network_debug', 'networkDebug',
  
  // Misc Hidden
  'backdoor', 'master', 'master_key', 'masterKey', 'skeleton',
  'skeleton_key', 'skeletonKey', 'god', 'god_mode', 'godMode',
  'cheat', 'hack', 'exploit', 'pwn', 'own', 'takeover',
  'impersonate', 'masquerade', 'spoof', 'forge', 'fabricate',
  'simulate', 'emulate', 'mimic', 'clone', 'copy', 'duplicate',
  'replay', 'playback', 'record', 'capture', 'intercept', 'sniff',
  'inject', 'payload', 'gadget', 'chain', 'pipeline', 'workflow',
  '_', '__', '___', '_x', '_y', '_z', '_a', '_b', '_c',
  'x', 'y', 'z', 'a', 'b', 'c', 'foo', 'bar', 'baz', 'qux',
  'tmp', 'temp', 'temporary', 'scratch', 'workspace', 'sandbox',
  'dev_mode', 'devMode', 'developer', 'development', 'staging',
  'preprod', 'pre_prod', 'preProd', 'uat', 'sit', 'local',
];

/**
 * AUTH_PARAMS - 100+ authentication-related parameters
 */
export const AUTH_PARAMS = [
  // Username & Identity
  'username', 'user', 'login', 'email', 'mail', 'account', 'name',
  'user_name', 'userName', 'user_login', 'userLogin', 'login_name',
  'loginName', 'account_name', 'accountName', 'identity', 'ident',
  'principal', 'subject', 'sub', 'uid', 'user_id', 'userId',
  
  // Password & Credentials
  'password', 'pass', 'passwd', 'pwd', 'passw', 'passwrd',
  'password1', 'password2', 'old_password', 'oldPassword',
  'new_password', 'newPassword', 'confirm_password', 'confirmPassword',
  'current_password', 'currentPassword', 'pass_confirm', 'passConfirm',
  'secret', 'credential', 'credentials', 'cred', 'creds',
  'pin', 'PIN', 'passcode', 'passphrase', 'pass_phrase',
  
  // Tokens
  'token', 'auth_token', 'authToken', 'access_token', 'accessToken',
  'refresh_token', 'refreshToken', 'id_token', 'idToken',
  'session_token', 'sessionToken', 'csrf_token', 'csrfToken',
  'xsrf_token', 'xsrfToken', 'verification_token', 'verificationToken',
  'reset_token', 'resetToken', 'invite_token', 'inviteToken',
  'confirmation_token', 'confirmationToken', 'activation_token',
  'jwt', 'JWT', 'bearer', 'Bearer', 'oauth_token', 'oauthToken',
  
  // API Keys
  'api_key', 'apiKey', 'apikey', 'API_KEY', 'APIKEY',
  'api_secret', 'apiSecret', 'app_key', 'appKey', 'app_secret',
  'appSecret', 'client_secret', 'clientSecret', 'consumer_key',
  'consumerKey', 'consumer_secret', 'consumerSecret',
  'private_key', 'privateKey', 'public_key', 'publicKey',
  'signing_key', 'signingKey', 'encryption_key', 'encryptionKey',
  'master_key', 'masterKey', 'service_key', 'serviceKey',
  
  // Session
  'session', 'sessionid', 'session_id', 'sessionId', 'sess',
  'sid', 'SID', 'PHPSESSID', 'JSESSIONID', 'ASP.NET_SessionId',
  'connect.sid', 'express.sid', 'laravel_session', 'ci_session',
  
  // Cookie & Auth Headers
  'cookie', 'cookies', 'auth', 'authorization', 'Authorization',
  'auth_type', 'authType', 'auth_method', 'authMethod',
  'x-auth-token', 'x-api-key', 'x-access-token', 'x-session-token',
  
  // OAuth
  'client_id', 'clientId', 'client_secret', 'clientSecret',
  'grant_type', 'grantType', 'response_type', 'responseType',
  'redirect_uri', 'redirectUri', 'scope', 'state', 'nonce',
  'code', 'authorization_code', 'authorizationCode',
  'code_verifier', 'codeVerifier', 'code_challenge', 'codeChallenge',
  
  // MFA & OTP
  'otp', 'OTP', 'totp', 'TOTP', 'hotp', 'HOTP', 'mfa', 'MFA',
  '2fa', 'twofa', 'two_factor', 'twoFactor', 'verification_code',
  'verificationCode', 'sms_code', 'smsCode', 'backup_code', 'backupCode',
  'recovery_code', 'recoveryCode', 'authenticator', 'security_code',
  
  // Remember & Persistence
  'remember', 'remember_me', 'rememberMe', 'keep_logged_in',
  'keepLoggedIn', 'stay_signed_in', 'staySignedIn', 'persistent',
  'auto_login', 'autoLogin', 'trust_device', 'trustDevice',
];

/**
 * FILE_PARAMS - 100+ file-related parameters
 * Parameters commonly vulnerable to LFI/RFI/Path Traversal
 */
export const FILE_PARAMS = [
  // Direct File References
  'file', 'File', 'FILE', 'filename', 'fileName', 'file_name',
  'filepath', 'filePath', 'file_path', 'fileurl', 'fileUrl', 'file_url',
  'files', 'fileList', 'file_list', 'filetype', 'fileType', 'file_type',
  
  // Path & Directory
  'path', 'Path', 'PATH', 'pathname', 'pathName', 'path_name',
  'dir', 'directory', 'folder', 'location', 'loc', 'root',
  'base', 'basepath', 'basePath', 'base_path', 'basedir', 'baseDir',
  'workdir', 'workDir', 'work_dir', 'homedir', 'homeDir', 'home_dir',
  
  // Include & Require
  'include', 'Include', 'INCLUDE', 'inc', 'includes', 'include_path',
  'require', 'Require', 'REQUIRE', 'req', 'requires', 'require_path',
  'import', 'Import', 'IMPORT', 'imports', 'import_path',
  'load', 'Load', 'LOAD', 'loader', 'autoload', 'preload',
  
  // Read & Write
  'read', 'Read', 'READ', 'readfile', 'readFile', 'read_file',
  'write', 'Write', 'WRITE', 'writefile', 'writeFile', 'write_file',
  'open', 'Open', 'OPEN', 'openfile', 'openFile', 'open_file',
  'save', 'Save', 'SAVE', 'savefile', 'saveFile', 'save_file',
  
  // Template & View
  'template', 'tpl', 'tmpl', 'templateName', 'template_name',
  'view', 'viewName', 'view_name', 'viewFile', 'view_file',
  'layout', 'layoutName', 'layout_name', 'partial', 'partialName',
  'page', 'pageName', 'page_name', 'pageFile', 'page_file',
  'theme', 'themeName', 'theme_name', 'skin', 'skinName', 'skin_name',
  
  // Document Types
  'doc', 'document', 'pdf', 'csv', 'xml', 'json', 'yaml', 'yml',
  'txt', 'text', 'log', 'conf', 'config', 'cfg', 'ini', 'env',
  'html', 'htm', 'php', 'asp', 'aspx', 'jsp', 'py', 'rb', 'js',
  
  // Media Files
  'img', 'image', 'photo', 'pic', 'picture', 'avatar', 'icon',
  'logo', 'banner', 'thumbnail', 'thumb', 'poster', 'cover',
  'video', 'audio', 'music', 'sound', 'clip', 'media', 'asset',
  
  // Upload & Download
  'upload', 'uploadFile', 'upload_file', 'uploaded', 'uploadPath',
  'download', 'downloadFile', 'download_file', 'downloadPath',
  'attachment', 'attachments', 'attach', 'attached', 'attachFile',
  'export', 'exportFile', 'export_file', 'exportPath', 'exportFormat',
  'import', 'importFile', 'import_file', 'importPath', 'importFormat',
  
  // Source & Resource
  'src', 'source', 'resource', 'res', 'assets', 'static',
  'public', 'private', 'shared', 'common', 'lib', 'library',
  'module', 'package', 'bundle', 'chunk', 'vendor', 'node_modules',
  'content', 'data', 'store', 'storage', 'bucket', 'blob',
  'stream', 'pipe', 'buffer', 'reader', 'writer', 'handler',
];

/**
 * REDIRECT_PARAMS - 80+ redirect-related parameters
 * Parameters commonly vulnerable to Open Redirect
 */
export const REDIRECT_PARAMS = [
  // Standard Redirect
  'redirect', 'redirect_url', 'redirect_uri', 'redirectUrl', 'redirectUri',
  'redirect_to', 'redirectTo', 'redirect_path', 'redirectPath',
  'redir', 'redirUrl', 'redir_url', 'redirection', 'redirectionUrl',
  
  // URL & URI
  'url', 'uri', 'URL', 'URI', 'link', 'href', 'hyperlink',
  'target', 'targetUrl', 'target_url', 'targetUri', 'target_uri',
  'dest', 'destination', 'destUrl', 'dest_url', 'destinationUrl',
  
  // Return & Back
  'return', 'returnUrl', 'return_url', 'returnUri', 'return_uri',
  'returnTo', 'return_to', 'returnPath', 'return_path',
  'back', 'backUrl', 'back_url', 'backUri', 'back_uri',
  'backTo', 'back_to', 'backPath', 'back_path',
  
  // Next & Continue
  'next', 'nextUrl', 'next_url', 'nextUri', 'next_uri',
  'nextPage', 'next_page', 'nextStep', 'next_step',
  'continue', 'continueUrl', 'continue_url', 'continueTo', 'continue_to',
  'proceed', 'proceedUrl', 'proceed_url', 'proceedTo', 'proceed_to',
  
  // Go & Forward
  'goto', 'go', 'goTo', 'go_to', 'goUrl', 'go_url',
  'forward', 'forwardUrl', 'forward_url', 'forwardTo', 'forward_to',
  'fwd', 'fwdUrl', 'fwd_url', 'fwdTo', 'fwd_to',
  
  // Callback & Hook
  'callback', 'callbackUrl', 'callback_url', 'callbackUri', 'callback_uri',
  'webhook', 'webhookUrl', 'webhook_url', 'hook', 'hookUrl', 'hook_url',
  'notify', 'notifyUrl', 'notify_url', 'notification_url',
  
  // Success & Error
  'success', 'successUrl', 'success_url', 'success_redirect',
  'error', 'errorUrl', 'error_url', 'error_redirect',
  'cancel', 'cancelUrl', 'cancel_url', 'cancel_redirect',
  'failure', 'failureUrl', 'failure_url', 'fail_url',
  'confirm', 'confirmUrl', 'confirm_url', 'confirmation_url',
  
  // Login & Logout
  'login_url', 'loginUrl', 'login_redirect', 'loginRedirect',
  'logout_url', 'logoutUrl', 'logout_redirect', 'logoutRedirect',
  'after_login', 'afterLogin', 'after_logout', 'afterLogout',
  'post_login', 'postLogin', 'post_logout', 'postLogout',
  
  // Misc Redirect
  'out', 'outUrl', 'out_url', 'external', 'externalUrl', 'external_url',
  'jump', 'jumpUrl', 'jump_url', 'jumpTo', 'jump_to',
  'transfer', 'transferUrl', 'transfer_url', 'transferTo', 'transfer_to',
  'navigate', 'navigateTo', 'navigate_to', 'navigateUrl', 'navigate_url',
  'location', 'locationUrl', 'location_url', 'loc', 'site', 'siteUrl',
  'ref', 'referer', 'referrer', 'origin', 'from', 'fromUrl', 'from_url',
  'path', 'pathInfo', 'path_info', 'route', 'routeTo', 'route_to',
  'view', 'window', 'open', 'launch', 'load', 'fetch', 'request',
];

/**
 * INJECTION_PARAMS - 100+ commonly injectable parameters
 * Parameters frequently vulnerable to SQLi, XSS, Command Injection, etc.
 */
export const INJECTION_PARAMS = [
  // ID Parameters (SQLi prone)
  'id', 'Id', 'ID', 'uid', 'pid', 'sid', 'cid', 'tid', 'rid', 'oid',
  'nid', 'bid', 'fid', 'gid', 'hid', 'kid', 'lid', 'mid', 'vid', 'wid',
  'user_id', 'userId', 'account_id', 'accountId', 'product_id', 'productId',
  'item_id', 'itemId', 'order_id', 'orderId', 'post_id', 'postId',
  'comment_id', 'commentId', 'category_id', 'categoryId', 'group_id',
  
  // Search & Query (XSS/SQLi prone)
  'search', 'q', 'query', 'keyword', 'keywords', 'term', 'find',
  'lookup', 'text', 'input', 'phrase', 'string', 'pattern', 'regex',
  'expression', 'criteria', 'condition', 'clause', 'predicate',
  
  // Sort & Filter (SQLi prone)
  'sort', 'sortby', 'sort_by', 'sortBy', 'order', 'orderby', 'order_by',
  'orderBy', 'column', 'col', 'field', 'table', 'group', 'groupby',
  'group_by', 'groupBy', 'having', 'where', 'filter', 'filterBy',
  
  // Page & Display (XSS prone)
  'page', 'title', 'name', 'content', 'body', 'message', 'msg',
  'comment', 'description', 'desc', 'subject', 'heading', 'label',
  'value', 'data', 'info', 'details', 'summary', 'note', 'notes',
  
  // URL & Path (SSRF/Redirect prone)
  'url', 'uri', 'link', 'href', 'src', 'source', 'target', 'dest',
  'destination', 'redirect', 'return', 'next', 'goto', 'forward',
  'callback', 'webhook', 'endpoint', 'host', 'domain', 'site',
  
  // File & Path (LFI/RFI prone)
  'file', 'filename', 'filepath', 'path', 'dir', 'directory',
  'include', 'require', 'load', 'read', 'template', 'view', 'page',
  'doc', 'document', 'folder', 'root', 'base', 'module', 'plugin',
  
  // Command (RCE prone)
  'cmd', 'command', 'exec', 'execute', 'run', 'system', 'shell',
  'bash', 'powershell', 'ping', 'ip', 'host', 'hostname', 'port',
  'process', 'proc', 'daemon', 'service', 'program', 'script',
  
  // Email & Communication (Header Injection prone)
  'email', 'mail', 'to', 'from', 'cc', 'bcc', 'subject', 'body',
  'message', 'header', 'headers', 'recipient', 'sender', 'reply_to',
  
  // Numeric (Integer Overflow/Logic prone)
  'amount', 'price', 'cost', 'total', 'quantity', 'qty', 'count',
  'num', 'number', 'size', 'length', 'width', 'height', 'weight',
  'rate', 'ratio', 'percentage', 'percent', 'discount', 'tax',
  
  // Format & Type (Type Confusion prone)
  'type', 'format', 'mode', 'method', 'action', 'operation', 'op',
  'func', 'function', 'class', 'object', 'entity', 'model', 'schema',
  'encoding', 'charset', 'content_type', 'mime', 'accept', 'language',
  'locale', 'timezone', 'tz', 'currency', 'unit', 'measure',
  
  // Serialization (Deserialization prone)
  'data', 'payload', 'object', 'serialized', 'json', 'xml', 'yaml',
  'pickle', 'marshal', 'base64', 'encoded', 'compressed', 'encrypted',
  'signed', 'token', 'jwt', 'cookie', 'session', 'state', 'viewstate',
];

/**
 * API_PARAMS - 100+ API-related parameters
 */
export const API_PARAMS = [
  // Authentication & Authorization
  'api_key', 'apiKey', 'apikey', 'API_KEY', 'APIKEY',
  'access_token', 'accessToken', 'access_key', 'accessKey',
  'secret_key', 'secretKey', 'secret_token', 'secretToken',
  'client_id', 'clientId', 'client_key', 'clientKey',
  'client_secret', 'clientSecret', 'app_id', 'appId',
  'app_key', 'appKey', 'app_secret', 'appSecret',
  'consumer_key', 'consumerKey', 'consumer_secret', 'consumerSecret',
  'bearer', 'Bearer', 'token', 'auth', 'authorization',
  
  // OAuth 2.0
  'grant_type', 'grantType', 'response_type', 'responseType',
  'scope', 'scopes', 'state', 'nonce', 'audience', 'aud',
  'redirect_uri', 'redirectUri', 'callback_url', 'callbackUrl',
  'code', 'authorization_code', 'authorizationCode',
  'code_verifier', 'codeVerifier', 'code_challenge', 'codeChallenge',
  'code_challenge_method', 'codeChallengeMethod',
  'refresh_token', 'refreshToken', 'id_token', 'idToken',
  
  // Versioning & Format
  'version', 'v', 'ver', 'api_version', 'apiVersion',
  'format', 'fmt', 'output', 'response_format', 'responseFormat',
  'accept', 'content_type', 'contentType', 'media_type', 'mediaType',
  'encoding', 'charset', 'locale', 'language', 'lang',
  
  // Pagination & Filtering
  'page', 'per_page', 'perPage', 'page_size', 'pageSize',
  'limit', 'offset', 'cursor', 'after', 'before', 'since', 'until',
  'start', 'end', 'from', 'to', 'skip', 'take', 'first', 'last',
  'sort', 'sort_by', 'sortBy', 'order', 'order_by', 'orderBy',
  'direction', 'dir', 'asc', 'desc', 'filter', 'filters',
  'fields', 'select', 'include', 'exclude', 'expand', 'embed',
  'populate', 'relations', 'associations', 'joins', 'with',
  
  // Search & Query
  'q', 'query', 'search', 'keyword', 'term', 'text', 'fulltext',
  'match', 'contains', 'starts_with', 'ends_with', 'regex', 'pattern',
  'where', 'condition', 'criteria', 'predicate', 'expression',
  
  // Rate Limiting & Throttling
  'rate_limit', 'rateLimit', 'throttle', 'burst', 'quota',
  'requests_per_second', 'rps', 'requests_per_minute', 'rpm',
  'retry_after', 'retryAfter', 'backoff', 'delay', 'timeout',
  
  // Webhook & Callback
  'webhook_url', 'webhookUrl', 'callback_url', 'callbackUrl',
  'notify_url', 'notifyUrl', 'postback_url', 'postbackUrl',
  'event', 'events', 'trigger', 'triggers', 'subscription',
  'topic', 'channel', 'queue', 'exchange', 'routing_key',
  
  // Metadata & Headers
  'request_id', 'requestId', 'correlation_id', 'correlationId',
  'trace_id', 'traceId', 'span_id', 'spanId', 'parent_id', 'parentId',
  'idempotency_key', 'idempotencyKey', 'if_match', 'if_none_match',
  'etag', 'last_modified', 'lastModified', 'cache_control', 'cacheControl',
  
  // Batch & Bulk
  'batch', 'bulk', 'ids', 'items', 'records', 'entries',
  'batch_size', 'batchSize', 'chunk_size', 'chunkSize',
  'parallel', 'concurrent', 'async', 'sync', 'blocking',
  
  // GraphQL
  'query', 'mutation', 'subscription', 'variables', 'operationName',
  'operation_name', 'extensions', 'fragments', 'directives',
  'introspectionQuery', 'schema', 'types', 'fields',
];

/**
 * IDOR_PARAMS - 80+ IDOR-prone parameters
 * Parameters commonly vulnerable to Insecure Direct Object Reference
 */
export const IDOR_PARAMS = [
  // User & Account IDs
  'user_id', 'userId', 'uid', 'user', 'username', 'user_name',
  'account_id', 'accountId', 'account', 'account_number', 'accountNumber',
  'profile_id', 'profileId', 'profile', 'member_id', 'memberId',
  'customer_id', 'customerId', 'customer', 'customer_number',
  'client_id', 'clientId', 'client', 'client_number', 'clientNumber',
  'employee_id', 'employeeId', 'employee', 'staff_id', 'staffId',
  'author_id', 'authorId', 'author', 'owner_id', 'ownerId', 'owner',
  
  // Content & Resource IDs
  'post_id', 'postId', 'article_id', 'articleId', 'blog_id', 'blogId',
  'comment_id', 'commentId', 'reply_id', 'replyId', 'review_id', 'reviewId',
  'message_id', 'messageId', 'thread_id', 'threadId', 'chat_id', 'chatId',
  'conversation_id', 'conversationId', 'notification_id', 'notificationId',
  'media_id', 'mediaId', 'image_id', 'imageId', 'video_id', 'videoId',
  'file_id', 'fileId', 'document_id', 'documentId', 'doc_id', 'docId',
  'attachment_id', 'attachmentId', 'upload_id', 'uploadId',
  
  // E-commerce IDs
  'order_id', 'orderId', 'order_number', 'orderNumber', 'order_ref',
  'invoice_id', 'invoiceId', 'invoice_number', 'invoiceNumber',
  'transaction_id', 'transactionId', 'transaction_ref', 'transactionRef',
  'payment_id', 'paymentId', 'payment_ref', 'paymentRef',
  'product_id', 'productId', 'item_id', 'itemId', 'sku', 'SKU',
  'cart_id', 'cartId', 'basket_id', 'basketId', 'wishlist_id', 'wishlistId',
  'coupon_id', 'couponId', 'voucher_id', 'voucherId', 'promo_id', 'promoId',
  'subscription_id', 'subscriptionId', 'plan_id', 'planId',
  'shipping_id', 'shippingId', 'tracking_id', 'trackingId',
  
  // Organization IDs
  'org_id', 'orgId', 'organization_id', 'organizationId',
  'company_id', 'companyId', 'team_id', 'teamId', 'group_id', 'groupId',
  'department_id', 'departmentId', 'division_id', 'divisionId',
  'project_id', 'projectId', 'workspace_id', 'workspaceId',
  'tenant_id', 'tenantId', 'site_id', 'siteId', 'store_id', 'storeId',
  'branch_id', 'branchId', 'location_id', 'locationId',
  
  // Technical IDs
  'session_id', 'sessionId', 'token_id', 'tokenId', 'key_id', 'keyId',
  'api_id', 'apiId', 'app_id', 'appId', 'webhook_id', 'webhookId',
  'event_id', 'eventId', 'job_id', 'jobId', 'task_id', 'taskId',
  'report_id', 'reportId', 'log_id', 'logId', 'audit_id', 'auditId',
  'ticket_id', 'ticketId', 'issue_id', 'issueId', 'bug_id', 'bugId',
  'request_id', 'requestId', 'case_id', 'caseId', 'incident_id',
  
  // Generic Numeric IDs
  'id', 'Id', 'ID', 'no', 'num', 'number', 'ref', 'reference',
  'code', 'key', 'index', 'idx', 'seq', 'sequence', 'serial',
  'record', 'entry', 'row', 'pk', 'uuid', 'guid', 'hash', 'slug',
];

/**
 * Helper function to get all params combined (deduplicated)
 */
export function getAllParams() {
  const all = new Set([
    ...COMMON_PARAMS,
    ...HIDDEN_PARAMS,
    ...AUTH_PARAMS,
    ...FILE_PARAMS,
    ...REDIRECT_PARAMS,
    ...INJECTION_PARAMS,
    ...API_PARAMS,
    ...IDOR_PARAMS,
  ]);
  return [...all];
}

/**
 * Get params by risk category
 */
export function getParamsByRisk(risk = 'all') {
  const riskMap = {
    critical: [...INJECTION_PARAMS, ...FILE_PARAMS, ...REDIRECT_PARAMS],
    high: [...AUTH_PARAMS, ...IDOR_PARAMS],
    medium: [...API_PARAMS, ...HIDDEN_PARAMS],
    low: [...COMMON_PARAMS],
    all: getAllParams(),
  };
  return riskMap[risk] || riskMap.all;
}

/**
 * Get params formatted for different tools
 */
export function formatForTool(params, tool = 'raw') {
  switch (tool) {
    case 'ffuf':
      return params.join('\n');
    case 'arjun':
      return JSON.stringify(params);
    case 'paramspider':
      return params.map(p => `FUZZ=${p}`).join('\n');
    case 'burp':
      return params.map(p => `${p}=FUZZ`).join('&');
    case 'raw':
    default:
      return params;
  }
}

export default {
  COMMON_PARAMS,
  HIDDEN_PARAMS,
  AUTH_PARAMS,
  FILE_PARAMS,
  REDIRECT_PARAMS,
  INJECTION_PARAMS,
  API_PARAMS,
  IDOR_PARAMS,
  getAllParams,
  getParamsByRisk,
  formatForTool,
};
