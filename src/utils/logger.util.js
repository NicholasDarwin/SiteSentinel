/**
 * Application Logger
 */

const LOG_LEVELS = {
  ERROR: 'ERROR',
  WARN: 'WARN',
  INFO: 'INFO',
  DEBUG: 'DEBUG'
};

function log(level, message, data = null) {
  const timestamp = new Date().toISOString();
  const logEntry = `[${timestamp}] [${level}] ${message}`;
  
  if (data) {
    console.log(logEntry, data);
  } else {
    console.log(logEntry);
  }
}

module.exports = {
  error: (msg, data) => log(LOG_LEVELS.ERROR, msg, data),
  warn: (msg, data) => log(LOG_LEVELS.WARN, msg, data),
  info: (msg, data) => log(LOG_LEVELS.INFO, msg, data),
  debug: (msg, data) => log(LOG_LEVELS.DEBUG, msg, data)
};
