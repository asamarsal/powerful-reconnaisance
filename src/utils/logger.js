import chalk from 'chalk';

const LEVELS = { debug: 0, info: 1, warn: 2, error: 3, success: 4, vuln: 5 };
let currentLevel = LEVELS.info;

function timestamp() {
  return new Date().toISOString().replace('T', ' ').substring(0, 19);
}

const logger = {
  setLevel(level) {
    currentLevel = LEVELS[level] || LEVELS.info;
  },

  debug(...args) {
    if (currentLevel <= LEVELS.debug) {
      console.log(chalk.gray(`[${timestamp()}] [DEBUG]`), ...args);
    }
  },

  info(...args) {
    if (currentLevel <= LEVELS.info) {
      console.log(chalk.blue(`[${timestamp()}] [INFO]`), ...args);
    }
  },

  warn(...args) {
    if (currentLevel <= LEVELS.warn) {
      console.log(chalk.yellow(`[${timestamp()}] [WARN]`), ...args);
    }
  },

  error(...args) {
    if (currentLevel <= LEVELS.error) {
      console.log(chalk.red(`[${timestamp()}] [ERROR]`), ...args);
    }
  },

  success(...args) {
    console.log(chalk.green(`[${timestamp()}] [+]`), ...args);
  },

  vuln(severity, ...args) {
    const colors = {
      critical: chalk.bgRed.white.bold,
      high: chalk.red.bold,
      medium: chalk.yellow.bold,
      low: chalk.cyan,
      info: chalk.gray,
    };
    const colorFn = colors[severity] || colors.info;
    console.log(colorFn(`[${timestamp()}] [VULN:${severity.toUpperCase()}]`), ...args);
  },

  banner() {
    console.log(chalk.cyan.bold(`
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║   ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗           ║
║   ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║           ║
║   ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║           ║
║   ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║           ║
║   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║           ║
║   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝           ║
║                                                          ║
║   Bug Bounty Toolkit v1.0.0                              ║
║   Live CVE | Recon | Hunt | PoC Generator                ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
`));
  },

  table(data, columns) {
    if (!data || data.length === 0) return;
    console.table(data, columns);
  },

  divider() {
    console.log(chalk.gray('─'.repeat(60)));
  },

  progress(current, total, label = '') {
    const pct = Math.round((current / total) * 100);
    const filled = Math.round(pct / 2);
    const bar = '█'.repeat(filled) + '░'.repeat(50 - filled);
    process.stdout.write(`\r${chalk.cyan(`[${bar}]`)} ${pct}% ${label}`);
    if (current >= total) process.stdout.write('\n');
  },
};

export default logger;
