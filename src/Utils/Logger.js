const winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');
const path = require('path');
const fs = require('fs');
const configs = require('../configs.json');

class Logger {
  constructor() {
    this.logDir = path.resolve(configs.logging.directory);
    
    // Ensure log directory exists
    if (!fs.existsSync(this.logDir)) {
      fs.mkdirSync(this.logDir, { recursive: true });
    }
    
    this.logger = this.createLogger();
  }

  createLogger() {
    const logFormat = winston.format.combine(
      winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
      winston.format.errors({ stack: true }),
      winston.format.splat(),
      winston.format.json()
    );

    const consoleFormat = winston.format.combine(
      winston.format.colorize(),
      winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
      winston.format.printf(({ timestamp, level, message, ...meta }) => {
        let msg = `${timestamp} [${level}]: ${message}`;
        if (Object.keys(meta).length > 0) {
          msg += ` ${JSON.stringify(meta)}`;
        }
        return msg;
      })
    );

    const transports = [
      // Console transport
      new winston.transports.Console({
        format: consoleFormat,
        level: configs.logging.level
      }),

      // Error logs
      new DailyRotateFile({
        filename: path.join(this.logDir, 'error-%DATE%.log'),
        datePattern: 'YYYY-MM-DD',
        level: 'error',
        maxFiles: configs.logging.maxFiles,
        maxSize: configs.logging.maxSize,
        format: logFormat
      }),

      // Combined logs
      new DailyRotateFile({
        filename: path.join(this.logDir, 'combined-%DATE%.log'),
        datePattern: 'YYYY-MM-DD',
        maxFiles: configs.logging.maxFiles,
        maxSize: configs.logging.maxSize,
        format: logFormat
      }),

      // Access logs
      new DailyRotateFile({
        filename: path.join(this.logDir, 'access-%DATE%.log'),
        datePattern: 'YYYY-MM-DD',
        level: 'info',
        maxFiles: configs.logging.maxFiles,
        maxSize: configs.logging.maxSize,
        format: logFormat
      })
    ];

    return winston.createLogger({
      level: configs.logging.level,
      format: logFormat,
      transports,
      exceptionHandlers: [
        new DailyRotateFile({
          filename: path.join(this.logDir, 'exceptions-%DATE%.log'),
          datePattern: 'YYYY-MM-DD',
          maxFiles: configs.logging.maxFiles,
          maxSize: configs.logging.maxSize
        })
      ],
      rejectionHandlers: [
        new DailyRotateFile({
          filename: path.join(this.logDir, 'rejections-%DATE%.log'),
          datePattern: 'YYYY-MM-DD',
          maxFiles: configs.logging.maxFiles,
          maxSize: configs.logging.maxSize
        })
      ]
    });
  }

  logRequest(req, res, responseTime) {
    const logData = {
      method: req.method,
      url: req.originalUrl || req.url,
      host: req.headers.host,
      ip: this.getClientIP(req),
      statusCode: res.statusCode,
      responseTime: `${responseTime}ms`,
      userAgent: req.headers['user-agent']
    };

    if (res.statusCode >= 500) {
      this.logger.error('Request error', logData);
    } else if (res.statusCode >= 400) {
      this.logger.warn('Client error', logData);
    } else {
      this.logger.info('Request', logData);
    }
  }

  getClientIP(req) {
    return req.headers['x-forwarded-for']?.split(',')[0].trim() ||
           req.headers['x-real-ip'] ||
           req.connection?.remoteAddress ||
           req.socket?.remoteAddress;
  }

  info(message, meta = {}) {
    this.logger.info(message, meta);
  }

  warn(message, meta = {}) {
    this.logger.warn(message, meta);
  }

  error(message, meta = {}) {
    this.logger.error(message, meta);
  }

  debug(message, meta = {}) {
    this.logger.debug(message, meta);
  }
}

// Singleton instance
let loggerInstance = null;

function getLogger() {
  if (!loggerInstance) {
    loggerInstance = new Logger();
  }
  return loggerInstance;
}

module.exports = { Logger, getLogger };

