const fs = require('fs');
const path = require('path');
const configs = require('../configs.json');

/**
 * Firewall Class
 * 
 * Provides basic firewall functionality including:
 * - Rate limiting (requests per time window)
 * - IP banning (persistent and temporary)
 * - Suspicious pattern detection
 * - Body/file size validation
 * - Request tracking and statistics
 * 
 * Works in conjunction with AdvancedSecurity for comprehensive protection.
 * 
 * @class Firewall
 */
class Firewall {
  /**
   * Initialize the firewall system
   * Loads banned IPs and starts cleanup intervals
   */
  constructor() {
    this.options = configs.firewall;
    this.ipRequests = new Map();       // IP -> request count tracking
    this.bannedIPs = new Set();        // Set of banned IP addresses
    this.suspiciousAttempts = new Map(); // IP -> suspicious attempt count
    
    // Convert string patterns to RegExp objects for efficient matching
    this.suspiciousRegexPatterns = this.options.suspiciousPatterns.map(pattern => {
      try {
        return new RegExp(pattern, 'i');
      } catch (err) {
        console.error(`Invalid regex pattern: ${pattern}`);
        return null;
      }
    }).filter(Boolean);

    this.loadBannedIPs();
    this.startCleanupInterval();
  }

  loadBannedIPs() {
    try {
      const bannedIPsPath = path.resolve(this.options.bannedIPsPath);
      if (fs.existsSync(bannedIPsPath)) {
        const data = fs.readFileSync(bannedIPsPath, 'utf8');
        const ips = JSON.parse(data);
        this.bannedIPs = new Set(ips);
      }
    } catch (err) {
      console.error(`Failed to load banned IPs: ${err.message}`);
    }
  }

  saveBannedIPs() {
    try {
      const bannedIPsPath = path.resolve(this.options.bannedIPsPath);
      const ips = Array.from(this.bannedIPs);
      
      // Ensure directory exists
      const dir = path.dirname(bannedIPsPath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      
      fs.writeFileSync(bannedIPsPath, JSON.stringify(ips, null, 2));
    } catch (err) {
      console.error(`Failed to save banned IPs: ${err.message}`);
    }
  }

  getClientIP(req) {
    return req.headers['x-forwarded-for']?.split(',')[0].trim() ||
           req.headers['x-real-ip'] ||
           req.connection.remoteAddress ||
           req.socket.remoteAddress;
  }

  isIPBanned(ip) {
    return this.bannedIPs.has(ip);
  }

  banIP(ip, reason = 'Manual ban') {
    this.bannedIPs.add(ip);
    this.saveBannedIPs();
    console.error(`IP banned: ${ip} - ${reason}`);
  }

  unbanIP(ip) {
    this.bannedIPs.delete(ip);
    this.saveBannedIPs();
  }

  /**
   * Rate Limiting Check
   * 
   * Implements sliding window rate limiting. Tracks request count per IP
   * within a configured time window. Automatically bans IPs that exceed
   * the limit multiple times (configurable threshold).
   * 
   * @param {string} ip - Client IP address
   * @returns {boolean} True if request is allowed, false if rate limit exceeded
   */
  checkRateLimit(ip) {
    const now = Date.now();
    const record = this.ipRequests.get(ip);

    // First request from this IP
    if (!record) {
      this.ipRequests.set(ip, { count: 1, lastReset: now });
      return true;
    }

    // Reset counter if window has passed
    if (now - record.lastReset > this.options.rateLimitWindow) {
      record.count = 1;
      record.lastReset = now;
      return true;
    }

    // Increment request count
    record.count++;

    // Check if limit exceeded
    if (record.count > this.options.rateLimit) {
      const attempts = (this.suspiciousAttempts.get(ip) || 0) + 1;
      this.suspiciousAttempts.set(ip, attempts);

      if (attempts >= 3) {
        this.banIP(ip, 'Rate limit exceeded multiple times');
      }
      
      return false;
    }

    return true;
  }

  checkSuspiciousContent(url, headers, body) {
    const content = `${url} ${JSON.stringify(headers)} ${body || ''}`;

    for (const pattern of this.suspiciousRegexPatterns) {
      if (pattern.test(content)) {
        return { suspicious: true, pattern: pattern.toString() };
      }
    }

    return { suspicious: false };
  }

  isFileUpload(req) {
    const contentType = req.headers['content-type'] || '';
    return contentType.includes('multipart/form-data') || 
           contentType.includes('application/octet-stream');
  }

  checkBodySize(req) {
    const contentLength = parseInt(req.headers['content-length'] || '0', 10);
    
    if (contentLength > this.options.maxBodySize) {
      return { valid: false, reason: 'Body size too large' };
    }

    if (this.isFileUpload(req) && contentLength > this.options.maxFileSize) {
      return { valid: false, reason: 'File size too large' };
    }

    return { valid: true };
  }

  /**
   * Comprehensive Request Inspection
   * 
   * Performs multi-layer security checks on incoming requests:
   * 1. IP ban status check
   * 2. Rate limiting
   * 3. File upload restrictions
   * 4. Body size validation
   * 5. Suspicious content detection
   * 
   * @param {Object} req - HTTP request object
   * @returns {Object} Inspection result with allowed status and details
   */
  async inspect(req) {
    const ip = this.getClientIP(req);

    // Check if IP is banned
    if (this.isIPBanned(ip)) {
      return {
        allowed: false,
        statusCode: 403,
        message: 'IP banned',
        ip
      };
    }

    // Rate limit check
    if (!this.checkRateLimit(ip)) {
      return {
        allowed: false,
        statusCode: 429,
        message: 'Rate limit exceeded',
        ip
      };
    }

    // File upload restriction check
    if (this.options.blockFileUploads && this.isFileUpload(req)) {
      const attempts = (this.suspiciousAttempts.get(ip) || 0) + 1;
      this.suspiciousAttempts.set(ip, attempts);

      if (attempts >= 5) {
        this.banIP(ip, 'Multiple file upload attempts');
      }

      return {
        allowed: false,
        statusCode: 403,
        message: 'File uploads not allowed',
        ip
      };
    }

    // Body size validation
    const bodySizeCheck = this.checkBodySize(req);
    if (!bodySizeCheck.valid) {
      return {
        allowed: false,
        statusCode: 413,
        message: bodySizeCheck.reason,
        ip
      };
    }

    // Suspicious content detection
    const suspiciousCheck = this.checkSuspiciousContent(
      req.url,
      req.headers,
      null // Body cannot be checked here as it arrives as a stream
    );

    if (suspiciousCheck.suspicious) {
      const attempts = (this.suspiciousAttempts.get(ip) || 0) + 1;
      this.suspiciousAttempts.set(ip, attempts);

      if (attempts >= 5) {
        this.banIP(ip, `Suspicious pattern detected: ${suspiciousCheck.pattern}`);
      }

      console.error(`Suspicious request from ${ip}: ${suspiciousCheck.pattern}`);
      
      return {
        allowed: false,
        statusCode: 403,
        message: 'Suspicious request detected',
        ip
      };
    }

    return {
      allowed: true,
      ip
    };
  }

  middleware() {
    return async (req, res, next) => {
      const result = await this.inspect(req);

      if (!result.allowed) {
        res.writeHead(result.statusCode, { 'Content-Type': 'text/plain' });
        res.end(result.message);
        return;
      }

      next();
    };
  }

  /**
   * Background Cleanup Process
   * 
   * Periodically removes stale data to prevent memory leaks:
   * - Expired rate limit records
   * - Low-severity suspicious attempts
   * 
   * Runs every 5 minutes to maintain optimal performance.
   * @private
   */
  startCleanupInterval() {
    setInterval(() => {
      const now = Date.now();
      
      // Remove expired rate limit records
      for (const [ip, record] of this.ipRequests.entries()) {
        if (now - record.lastReset > this.options.rateLimitWindow * 2) {
          this.ipRequests.delete(ip);
        }
      }

      // Remove low-severity suspicious attempts
      for (const [ip, attempts] of this.suspiciousAttempts.entries()) {
        if (attempts < 3) {
          this.suspiciousAttempts.delete(ip);
        }
      }
    }, 300000); // Cleanup every 5 minutes
  }

  getStats() {
    return {
      bannedIPs: this.bannedIPs.size,
      activeIPs: this.ipRequests.size,
      suspiciousIPs: this.suspiciousAttempts.size
    };
  }
}

module.exports = { Firewall };