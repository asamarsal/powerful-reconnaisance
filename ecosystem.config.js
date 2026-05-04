/**
 * PM2 Ecosystem Configuration
 * Manages all ReconTool services
 */

export default {
  apps: [
    {
      name: 'recontool-daemon',
      script: './src/daemon/daemon.js',
      interpreter: 'node',
      interpreter_args: '--experimental-modules',
      cwd: './',
      watch: false,
      autorestart: true,
      max_restarts: 10,
      restart_delay: 5000,
      env: {
        NODE_ENV: 'production'
      },
      error_file: './logs/daemon-error.log',
      out_file: './logs/daemon-out.log',
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
      merge_logs: true
    },
    {
      name: 'recontool-dashboard',
      script: './src/dashboard/server.js',
      interpreter: 'node',
      interpreter_args: '--experimental-modules',
      cwd: './',
      watch: ['./src/dashboard/'],
      watch_delay: 1000,
      ignore_watch: ['node_modules', 'data', 'logs'],
      autorestart: true,
      max_restarts: 10,
      restart_delay: 3000,
      env: {
        NODE_ENV: 'production',
        PORT: 4500
      },
      error_file: './logs/dashboard-error.log',
      out_file: './logs/dashboard-out.log',
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
      merge_logs: true
    },
    {
      name: 'recontool-python-bridge',
      script: './python/bridge_server.py',
      interpreter: 'python3',
      cwd: './',
      watch: false,
      autorestart: true,
      max_restarts: 5,
      restart_delay: 10000,
      env: {
        PYTHONUNBUFFERED: '1',
        BRIDGE_PORT: 5100
      },
      error_file: './logs/python-bridge-error.log',
      out_file: './logs/python-bridge-out.log',
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
      merge_logs: true
    }
  ]
};
