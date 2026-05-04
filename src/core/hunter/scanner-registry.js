/**
 * Scanner Registry - Master registry of ALL vulnerability scanners
 * Contains 500+ vulnerability checks organized by category
 * Each scanner can be invoked individually or as part of a full scan
 */

export const VULNERABILITY_CATEGORIES = {
  // ═══════════════════════════════════════════════════════════════
  // WEB / APPLICATION
  // ═══════════════════════════════════════════════════════════════
  web: {
    name: 'Web / Application',
    scanners: [
      'xss', 'sqli', 'nosqli', 'cmdi', 'ldap-injection', 'xpath-injection',
      'ssti', 'html-injection', 'css-injection', 'http-header-injection',
      'crlf-injection', 'xxe', 'ssrf', 'csrf', 'cors-misconfig',
      'open-redirect', 'clickjacking', 'host-header-injection',
      'cache-poisoning', 'http-request-smuggling', 'http-param-pollution',
      'parameter-tampering', 'cookie-tampering', 'jwt-tampering',
      'session-fixation', 'session-hijacking', 'broken-auth',
      'weak-password-policy', 'brute-force-weakness', 'mfa-bypass',
      'password-reset-abuse', 'account-enumeration', 'user-enumeration',
      'idor', 'bola', 'bfla', 'privilege-escalation', 'admin-bypass',
      'forced-browsing', 'directory-traversal', 'lfi', 'rfi',
      'arbitrary-file-upload', 'insecure-file-download', 'insecure-direct-file-access',
      'business-logic-abuse', 'race-condition', 'rate-limit-bypass',
      'mass-assignment', 'insecure-deserialization', 'prototype-pollution',
      'websocket-security', 'graphql-introspection', 'graphql-authz',
      'api-key-exposure', 'secret-leakage', 'sensitive-data-exposure',
      'debug-mode-exposure', 'stack-trace-exposure', 'verbose-error',
      'security-misconfiguration', 'missing-security-headers',
      'weak-tls-ssl', 'mixed-content', 'subdomain-takeover',
      'dependency-vulnerability', 'supply-chain-risk',
    ],
  },

  // ═══════════════════════════════════════════════════════════════
  // WEB ADVANCED
  // ═══════════════════════════════════════════════════════════════
  web_advanced: {
    name: 'Web Advanced',
    scanners: [
      'dom-clobbering', 'client-prototype-pollution', 'reflected-file-download',
      'web-cache-deception', 'cache-key-confusion', 'client-path-traversal',
      'client-request-forgery', 'dangling-markup', 'mime-sniffing',
      'content-type-confusion', 'csp-bypass', 'csp-misconfiguration',
      'sri-missing', 'insecure-postmessage', 'postmessage-origin-validation',
      'web-worker-abuse', 'service-worker-hijacking', 'localstorage-token-exposure',
      'sessionstorage-token-exposure', 'browser-autofill-exposure',
      'insecure-cross-origin', 'webrtc-ip-leakage', 'websocket-hijacking',
      'samesite-cookie-misconfig', 'cookie-prefix-misconfig', 'cookie-scope-misconfig',
      'insecure-redirect-after-login', 'oauth-redirect-uri-misconfig',
      'oauth-scope-abuse', 'oauth-consent-phishing', 'saml-signature-wrapping',
      'saml-assertion-replay', 'sso-account-linking-abuse', 'magic-link-abuse',
      'invite-link-abuse', 'email-verification-bypass', 'phone-verification-bypass',
      'captcha-bypass', 'anti-automation-weakness', 'bot-protection-weakness',
    ],
  },

  // ═══════════════════════════════════════════════════════════════
  // API SECURITY
  // ═══════════════════════════════════════════════════════════════
  api: {
    name: 'API Security',
    scanners: [
      'api-bola', 'api-broken-auth', 'api-broken-object-property',
      'api-unrestricted-resource', 'api-bfla', 'api-unrestricted-business-flow',
      'api-ssrf', 'api-security-misconfig', 'api-improper-inventory',
      'api-unsafe-consumption', 'api-rate-limit', 'api-token-leakage',
      'api-replay-risk', 'api-version-exposure', 'api-excessive-data',
      'api-improper-input-validation', 'api-mass-assignment',
      'api-graphql-query-abuse', 'api-graphql-depth-abuse',
      // API Advanced
      'api-excessive-object-exposure', 'api-improper-pagination',
      'api-improper-filtering', 'api-sorting-abuse', 'api-field-selection-abuse',
      'api-method-override', 'api-verb-tampering', 'api-hidden-endpoint',
      'api-deprecated-endpoint', 'api-shadow-api', 'api-zombie-api',
      'api-inconsistent-authz', 'api-batch-abuse', 'api-bulk-abuse',
      'api-import-abuse', 'api-export-abuse', 'api-webhook-spoofing',
      'api-webhook-replay', 'api-webhook-signature-weakness',
      'api-callback-abuse', 'api-idempotency-abuse', 'api-key-no-scope',
      'api-key-no-expiry', 'api-key-in-url', 'api-token-audience-misconfig',
      'api-token-issuer-misconfig', 'api-token-scope-escalation',
      'api-refresh-token-rotation', 'graphql-resolver-authz',
      'graphql-alias-abuse', 'graphql-batch-query', 'graphql-fragment-abuse',
      'graphql-error-disclosure', 'graphql-subscription-abuse',
    ],
  },

  // ═══════════════════════════════════════════════════════════════
  // FILE & UPLOAD/DOWNLOAD
  // ═══════════════════════════════════════════════════════════════
  file: {
    name: 'File & Upload/Download',
    scanners: [
      'file-extension-bypass', 'mime-type-validation-weakness',
      'magic-byte-validation-weakness', 'double-extension',
      'polyglot-file', 'image-metadata-leakage', 'exif-data-exposure',
      'svg-script-injection', 'pdf-script-risk', 'zip-slip',
      'archive-bomb', 'decompression-bomb', 'path-normalization',
      'filename-injection', 'null-byte-injection', 'unsafe-temp-file',
      'public-upload-directory', 'predictable-file-url', 'insecure-signed-url',
      'signed-url-expiry-weakness', 'file-overwrite', 'file-permission-misconfig',
      'malware-scanning-missing',
    ],
  },

  // ═══════════════════════════════════════════════════════════════
  // AUTHENTICATION & AUTHORIZATION
  // ═══════════════════════════════════════════════════════════════
  auth: {
    name: 'Authentication & Authorization',
    scanners: [
      'login-bypass', 'admin-bypass', 'role-bypass', 'permission-bypass',
      'mfa-bypass-risk', 'otp-abuse', 'password-reset-bypass',
      'account-takeover', 'session-replay', 'token-replay',
      'jwt-none-algorithm', 'jwt-weak-secret', 'refresh-token-abuse',
      'oauth-misconfiguration', 'sso-misconfiguration', 'saml-misconfiguration',
      'access-token-leakage', 'insecure-remember-me', 'missing-logout-invalidation',
    ],
  },

  // ═══════════════════════════════════════════════════════════════
  // IDENTITY & ACCESS ADVANCED
  // ═══════════════════════════════════════════════════════════════
  identity: {
    name: 'Identity & Access Advanced',
    scanners: [
      'broken-tenant-isolation', 'cross-tenant-data-access',
      'organization-switching-abuse', 'workspace-role-confusion',
      'group-membership-abuse', 'invite-permission-escalation',
      'shared-link-permission-weakness', 'public-link-exposure',
      'orphaned-account', 'dormant-account', 'privileged-account-sprawl',
      'service-account-overprivilege', 'api-token-overprivilege',
      'missing-reauthentication', 'weak-step-up-auth',
      'insecure-account-recovery', 'backup-code-abuse',
      'device-trust-bypass', 'session-confusion', 'concurrent-session-weakness',
      'login-csrf', 'logout-csrf', 'account-lockout-abuse',
      'username-squatting', 'email-change-abuse', 'phone-number-reuse-abuse',
    ],
  },

  // ═══════════════════════════════════════════════════════════════
  // BUSINESS LOGIC
  // ═══════════════════════════════════════════════════════════════
  logic: {
    name: 'Data & Logic Abuse',
    scanners: [
      'price-manipulation', 'quantity-manipulation', 'coupon-abuse',
      'payment-flow-abuse', 'order-status-tampering', 'wallet-balance-tampering',
      'point-reward-manipulation', 'referral-abuse', 'race-condition-abuse',
      'workflow-bypass', 'validation-bypass', 'negative-value-abuse',
      'currency-manipulation', 'inventory-manipulation', 'duplicate-transaction',
      'replay-transaction', 'business-rule-bypass',
      // Business Logic Advanced
      'multi-step-flow-bypass', 'step-skipping', 'state-machine-abuse',
      'approval-flow-bypass', 'maker-checker-bypass', 'kyc-bypass',
      'age-verification-bypass', 'region-restriction-bypass',
      'subscription-plan-bypass', 'trial-abuse', 'refund-abuse',
      'chargeback-abuse', 'invoice-manipulation', 'tax-calculation-manipulation',
      'shipping-fee-manipulation', 'loyalty-program-abuse', 'gift-card-abuse',
      'promo-stacking-abuse', 'limit-per-user-bypass', 'duplicate-account-abuse',
      'self-referral-abuse', 'auction-bidding-abuse', 'booking-slot-abuse',
      'queue-jumping', 'rate-race-condition', 'toctou',
      'concurrent-request-abuse',
    ],
  },

  // ═══════════════════════════════════════════════════════════════
  // SYSTEM / SERVER
  // ═══════════════════════════════════════════════════════════════
  system: {
    name: 'System / Server',
    scanners: [
      'service-enumeration', 'open-port-exposure', 'version-disclosure',
      'vulnerable-service', 'weak-ssh-config', 'weak-rdp-config',
      'default-credential', 'weak-password-policy-server', 'excessive-user-privileges',
      'sudo-misconfiguration', 'suid-sgid-misconfig', 'path-hijacking',
      'cron-job-misconfig', 'writable-sensitive-files', 'insecure-file-permissions',
      'kernel-vulnerability', 'package-vulnerability', 'patch-mismanagement',
      'privilege-escalation-server', 'lateral-movement', 'insecure-backup-exposure',
      'log-exposure', 'secret-exposure-server', 'env-variable-leakage',
      'misconfigured-firewall', 'unnecessary-services', 'insecure-network-share',
      'nfs-misconfiguration', 'smb-misconfiguration', 'ftp-misconfiguration',
      'mail-server-misconfig', 'dns-misconfiguration',
    ],
  },

  // ═══════════════════════════════════════════════════════════════
  // NETWORK
  // ═══════════════════════════════════════════════════════════════
  network: {
    name: 'Network',
    scanners: [
      'network-recon', 'host-discovery', 'port-scanning',
      'service-fingerprinting', 'banner-grabbing', 'network-segmentation-weakness',
      'firewall-rule-weakness', 'vlan-misconfiguration', 'dns-zone-transfer',
      'dns-spoofing-risk', 'arp-spoofing-risk', 'mitm-risk',
      'ssl-stripping-risk', 'insecure-protocol-usage', 'snmp-misconfiguration',
      'exposed-management-interface', 'vpn-misconfiguration', 'wireless-security-weakness',
    ],
  },

  // ═══════════════════════════════════════════════════════════════
  // CLOUD
  // ═══════════════════════════════════════════════════════════════
  cloud: {
    name: 'Cloud',
    scanners: [
      'public-bucket-exposure', 'insecure-object-storage-permission',
      'iam-misconfiguration', 'overprivileged-role', 'exposed-access-key',
      'weak-key-rotation', 'public-snapshot-exposure', 'public-database-exposure',
      'security-group-misconfig', 'open-admin-port', 'metadata-service-abuse',
      'serverless-misconfiguration', 'container-registry-exposure',
      'logging-disabled', 'insecure-secret-storage', 'cross-account-access-risk',
      // Cloud Advanced
      'public-cdn-origin-exposure', 'origin-bypass', 'waf-bypass',
      'weak-cloudtrail-logging', 'missing-guardduty', 'public-ami-exposure',
      'public-ebs-snapshot', 'public-rds-snapshot', 'overbroad-trust-policy',
      'cross-account-role-abuse', 'weak-assumerole-policy', 'missing-mfa-admin',
      'long-lived-access-key', 'unused-access-key', 'insecure-kms-policy',
      'public-queue-topic-exposure', 'lambda-env-secret-exposure',
      'serverless-overprivilege', 'api-gateway-misconfig', 'cloud-metadata-exposure',
      'storage-object-acl-misconfig', 'cdn-cache-misconfig', 'dns-takeover-risk',
    ],
  },

  // ═══════════════════════════════════════════════════════════════
  // CONTAINER / KUBERNETES
  // ═══════════════════════════════════════════════════════════════
  container: {
    name: 'Container / Kubernetes',
    scanners: [
      'vulnerable-container-image', 'running-as-root', 'privileged-container',
      'dangerous-linux-capabilities', 'host-path-mount', 'docker-socket-exposure',
      'insecure-image-registry', 'secret-in-image', 'k8s-rbac-misconfig',
      'overprivileged-service-account', 'exposed-k8s-dashboard',
      'insecure-admission-controller', 'missing-network-policy',
      'pod-escape-risk', 'namespace-isolation-weakness',
      'insecure-configmap-secret', 'api-server-exposure', 'etcd-exposure',
    ],
  },

  // ═══════════════════════════════════════════════════════════════
  // INFRASTRUCTURE
  // ═══════════════════════════════════════════════════════════════
  infrastructure: {
    name: 'Infrastructure',
    scanners: [
      'exposed-admin-panel', 'exposed-monitoring-dashboard',
      'exposed-metrics-endpoint', 'exposed-debug-endpoint',
      'exposed-actuator-endpoint', 'exposed-swagger-openapi',
      'exposed-graphiql-playground', 'exposed-phpmyadmin-adminer',
      'exposed-jenkins-gitlab-ci', 'exposed-elasticsearch',
      'exposed-redis', 'exposed-mongodb', 'exposed-postgresql-mysql',
      'exposed-rabbitmq-kafka', 'exposed-prometheus-grafana',
      'exposed-jaeger-tracing', 'exposed-minio-s3-console',
      'directory-listing', 'backup-file-exposure', 'source-code-exposure',
      'git-directory-exposure', 'svn-directory-exposure', 'env-file-exposure',
      'config-file-exposure', 'log-file-exposure', 'database-dump-exposure',
      'core-dump-exposure', 'temporary-file-exposure', 'build-artifact-exposure',
    ],
  },

  // ═══════════════════════════════════════════════════════════════
  // CI/CD & DevSecOps
  // ═══════════════════════════════════════════════════════════════
  cicd: {
    name: 'CI/CD & DevSecOps',
    scanners: [
      'secret-in-repository', 'secret-in-ci-logs', 'secret-in-build-artifact',
      'overprivileged-ci-runner', 'public-ci-artifact', 'insecure-pipeline-variable',
      'missing-branch-protection', 'missing-code-owner-review',
      'unsigned-commit-risk', 'dependency-confusion', 'typosquatting-dependency',
      'malicious-package-risk', 'insecure-build-script', 'artifact-tampering',
      'missing-sbom', 'missing-sast', 'missing-dependency-scan',
      'missing-container-scan', 'missing-iac-scan', 'insecure-terraform-state',
      'public-terraform-state', 'weak-deployment-approval',
      'production-deploy-without-review',
    ],
  },

  // ═══════════════════════════════════════════════════════════════
  // MOBILE / CLIENT-SIDE
  // ═══════════════════════════════════════════════════════════════
  mobile: {
    name: 'Mobile / Client-Side',
    scanners: [
      'insecure-local-storage', 'hardcoded-secret-mobile',
      'weak-certificate-pinning', 'insecure-deep-link',
      'webview-misconfiguration', 'insecure-api-communication',
      'token-leakage-mobile', 'reverse-engineering-risk',
      'debug-build-exposure', 'root-jailbreak-detection-weakness',
    ],
  },

  // ═══════════════════════════════════════════════════════════════
  // AI / LLM APPLICATION SECURITY
  // ═══════════════════════════════════════════════════════════════
  ai: {
    name: 'AI / LLM Application Security',
    scanners: [
      'prompt-injection', 'indirect-prompt-injection', 'jailbreak-risk',
      'system-prompt-leakage', 'tool-abuse-risk', 'excessive-agency',
      'insecure-plugin-invocation', 'data-exfiltration-via-prompt',
      'retrieval-poisoning', 'rag-data-leakage', 'vector-database-exposure',
      'embedding-inversion-risk', 'model-output-injection',
      'sensitive-data-in-prompt', 'training-data-leakage',
      'insecure-llm-function-calling', 'unsafe-code-execution-agent',
      'prompt-template-injection', 'model-denial-of-service',
      'hallucination-security-risk',
    ],
  },

  // ═══════════════════════════════════════════════════════════════
  // LINUX / RED HAT SPECIFIC
  // ═══════════════════════════════════════════════════════════════
  linux: {
    name: 'Linux / Red Hat Specific',
    scanners: [
      'selinux-disabled', 'selinux-permissive', 'incorrect-selinux-context',
      'auditd-disabled', 'firewalld-disabled', 'weak-sshd-config',
      'password-auth-enabled', 'root-login-enabled', 'empty-password-allowed',
      'weak-pam-policy', 'weak-sudoers-rule', 'world-writable-directory',
      'world-writable-script', 'writable-systemd-unit', 'insecure-systemd-service',
      'dangerous-capabilities', 'unowned-file', 'orphaned-package',
      'outdated-rpm-package', 'untrusted-repository', 'gpg-check-disabled',
      'yum-dnf-repo-misconfig', 'weak-kernel-parameter', 'ipv6-misconfiguration',
      'insecure-ntp-config', 'insecure-syslog-config', 'weak-cron-permission',
      'weak-logrotate-permission',
    ],
  },

  // ═══════════════════════════════════════════════════════════════
  // ACTIVE DIRECTORY / ENTERPRISE
  // ═══════════════════════════════════════════════════════════════
  ad: {
    name: 'Active Directory / Enterprise',
    scanners: [
      'kerberoasting-risk', 'asrep-roasting-risk', 'weak-spn-management',
      'unconstrained-delegation', 'constrained-delegation-misconfig',
      'rbcd-risk', 'privileged-group-misuse', 'nested-group-privilege',
      'stale-computer-account', 'stale-user-account', 'weak-gpo-permission',
      'gpo-abuse-risk', 'sysvol-secret-exposure', 'ldap-signing-disabled',
      'smb-signing-disabled', 'ntlm-usage-risk', 'llmnr-nbns-poisoning',
      'password-spraying-risk', 'local-admin-reuse', 'domain-admin-overexposure',
      'adcs-misconfiguration', 'certificate-template-abuse',
    ],
  },

  // ═══════════════════════════════════════════════════════════════
  // IoT / OT
  // ═══════════════════════════════════════════════════════════════
  iot: {
    name: 'IoT / OT',
    scanners: [
      'default-device-credential', 'insecure-firmware', 'firmware-secret-exposure',
      'insecure-ota-update', 'missing-firmware-signature', 'debug-port-exposure-iot',
      'uart-jtag-exposure', 'insecure-mqtt', 'insecure-modbus',
      'insecure-bacnet', 'weak-device-identity', 'insecure-pairing',
      'hardcoded-credential-iot', 'weak-physical-tamper-protection',
      'unsafe-remote-management',
    ],
  },

  // ═══════════════════════════════════════════════════════════════
  // REPORTING TAGS (MITRE ATT&CK aligned)
  // ═══════════════════════════════════════════════════════════════
  reporting: {
    name: 'Reporting Tags',
    tags: [
      'reconnaissance', 'initial-access', 'execution-risk',
      'persistence-risk', 'privilege-escalation', 'defense-evasion',
      'credential-access', 'discovery', 'lateral-movement',
      'collection-risk', 'exfiltration-risk', 'impact-risk',
      'misconfiguration', 'vulnerability', 'business-logic',
      'compliance', 'detection-gap', 'logging-gap', 'hardening-gap',
    ],
  },
};

/**
 * Get total scanner count
 */
export function getTotalScannerCount() {
  let count = 0;
  for (const category of Object.values(VULNERABILITY_CATEGORIES)) {
    count += (category.scanners || category.tags || []).length;
  }
  return count;
}

/**
 * Get all scanner IDs flat
 */
export function getAllScannerIds() {
  const ids = [];
  for (const category of Object.values(VULNERABILITY_CATEGORIES)) {
    ids.push(...(category.scanners || category.tags || []));
  }
  return ids;
}

/**
 * Get scanners by category
 */
export function getScannersByCategory(categoryKey) {
  return VULNERABILITY_CATEGORIES[categoryKey]?.scanners || [];
}

/**
 * Find category for a scanner
 */
export function findCategoryForScanner(scannerId) {
  for (const [key, category] of Object.entries(VULNERABILITY_CATEGORIES)) {
    if ((category.scanners || []).includes(scannerId)) {
      return { key, name: category.name };
    }
  }
  return null;
}

export default VULNERABILITY_CATEGORIES;
