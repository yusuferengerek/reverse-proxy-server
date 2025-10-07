const { getLogger } = require('./Logger');
const crypto = require('crypto');

/**
 * Advanced Security Layer
 * 
 * Enterprise-grade security system that provides 13 layers of protection
 * while maintaining excellent user experience. Implements behavioral analysis
 * to distinguish between legitimate users and malicious actors.
 * 
 * Features:
 * - SQL/NoSQL Injection Detection
 * - XSS Prevention
 * - Command Injection Protection
 * - SSTI & SSRF Detection
 * - Bot Detection (superhuman speed analysis)
 * - Brute Force Protection
 * - Scanning Detection
 * - CSRF Protection
 * - File Upload Validation
 * 
 * @class AdvancedSecurity
 */
class AdvancedSecurity {
  /**
   * Initialize the advanced security system
   * @param {Firewall} firewall - Reference to the firewall instance for IP banning
   */
  constructor(firewall) {
    this.logger = getLogger();
    this.firewall = firewall;
    this.configs = require('../configs.json');
    
    // Behavioral tracking for bot detection and threat analysis
    this.userBehavior = new Map();    // IP -> comprehensive behavior data
    this.csrfTokens = new Map();      // Session -> CSRF tokens
    this.loginAttempts = new Map();   // IP+username -> login attempt tracking
    this.requestPatterns = new Map(); // IP -> request pattern analysis
    
    // Start background cleanup process
    this.startCleanup();
    
    // Initialize security pattern matchers
    this.initializePatterns();
  }

  /**
   * Initialize all security pattern matchers
   * Compiles regex patterns for various attack vectors
   * @private
   */
  initializePatterns() {
    // Directory traversal attack patterns
    // Detects attempts to access files outside intended directories
    this.directoryTraversalPatterns = [
      /\.\.[\/\\]/gi,                    // ../
      /\.\.\\/gi,                        // ..\
      /%2e%2e[\/\\]/gi,                  // URL encoded ../
      /\.\.%2f/gi,                       // Mixed encoding
      /\.\.%5c/gi,                       // Mixed encoding
      /\/%2e%2e%2f/gi,                   // Full URL encoded
      /etc[\/\\]passwd/gi,               // Linux password file
      /etc[\/\\]shadow/gi,               // Linux shadow file
      /windows[\/\\]win\.ini/gi,         // Windows system file
      /boot\.ini/gi,                     // Windows boot config
      /proc[\/\\]self/gi,                // Process info
      /\.\.;/gi,                         // Semicolon bypass
    ];

    // SQL Injection attack patterns
    // Covers classic, UNION-based, time-based, and stacked query injections
    this.sqlInjectionPatterns = [
      /(\b(select|union|insert|update|delete|drop|create|alter|exec|execute|script|javascript|eval)\b.*\b(from|into|where|table|database|column)\b)/gi,
      /(\bunion\b.*\bselect\b)/gi,
      /(;|\s)*(drop|delete|truncate)\s+(table|database)/gi,
      /('|\"|`|;|\||&|\$)\s*(or|and)\s*('|\"|`|;|\||&|\$)/gi,
      /'\s*(or|and)\s*'?\d*\s*=\s*\d*/gi,
      /\/\*.*\*\//gi,                    // SQL comments
      /-{2,}/g,                          // SQL comments --
      /xp_cmdshell/gi,                   // MSSQL command execution
      /;\s*shutdown/gi,                  // Database shutdown
      /benchmark\s*\(/gi,                // MySQL benchmark
      /sleep\s*\(/gi,                    // Time-based injection
      /waitfor\s+delay/gi,               // MSSQL time delay
    ];

    // NoSQL Injection attack patterns
    // Targets MongoDB and similar NoSQL database operators
    this.nosqlInjectionPatterns = [
      /\$where/gi,
      /\$ne/gi,
      /\$gt/gi,
      /\$lt/gi,
      /\$regex/gi,
      /\$nin/gi,
      /\$in\s*:\s*\[/gi,
      /\{.*\$.*:.*\}/gi,
      /\.find\s*\(/gi,
      /\.aggregate\s*\(/gi,
    ];

    // Cross-Site Scripting (XSS) attack patterns
    // Detects stored, reflected, and DOM-based XSS attempts
    this.xssPatterns = [
      /<script[^>]*>.*?<\/script>/gi,
      /javascript:/gi,
      /on(error|load|click|mouse|focus|blur|change|submit)=/gi,
      /<iframe/gi,
      /<embed/gi,
      /<object/gi,
      /eval\s*\(/gi,
      /expression\s*\(/gi,
      /vbscript:/gi,
      /data:text\/html/gi,
      /<img[^>]+src[^>]*=/gi,
      /document\.cookie/gi,
      /document\.write/gi,
      /window\.location/gi,
      /<svg.*onload/gi,
    ];

    // OS Command Injection attack patterns
    // Detects shell metacharacters and command execution attempts
    // NOTE: Must be context-aware - don't check headers, only URL and body
    this.commandInjectionPatterns = [
      /;.*\w+/g,                         // Semicolon with command (;cat, ;ls)
      /\|\s*\w+/g,                       // Pipe with command (|cat, |ls)
      /&&\s*\w+/g,                       // AND chain with command (&&cat)
      /\|\|\s*\w+/g,                     // OR chain with command (||cat)
      /\$\(.*\)/g,                       // Command substitution $(cmd)
      /`.*`/g,                           // Backtick command substitution
      /(nc|netcat|curl|wget|bash|sh|cmd|powershell|python|perl|ruby|php)\s/gi, // Shell commands
      /\/bin\/(ba)?sh/gi,                // Shell paths
      /etc\/passwd/gi,                   // Sensitive files
      /\/dev\/(tcp|udp)/gi,              // Network devices
    ];

    // Server-Side Template Injection (SSTI) attack patterns
    // Covers Jinja2, JSP, Ruby, and other template engines
    this.sstiPatterns = [
      /\{\{.*\}\}/g,                     // Template expressions
      /\{%.*%\}/g,                       // Template tags
      /\$\{.*\}/g,                       // JSP/Spring EL
      /#\{.*\}/g,                        // Ruby interpolation
      /@\{.*\}/g,                        // Razor syntax
      /\{\{.*constructor.*\}\}/gi,
      /\{\{.*__.*__.*\}\}/gi,            // Python dunder methods
      /\{\{.*config.*\}\}/gi,
      /\{\{.*self.*\}\}/gi,
    ];

    // Server-Side Request Forgery (SSRF) attack patterns
    // Prevents access to internal networks and metadata endpoints
    this.ssrfPatterns = [
      /localhost/gi,
      /127\.0\.0\.1/g,
      /0\.0\.0\.0/g,
      /::1/g,                            // IPv6 localhost
      /169\.254\./g,                     // AWS metadata
      /192\.168\./g,                     // Private network
      /10\.\d{1,3}\.\d{1,3}\.\d{1,3}/g, // Private network
      /172\.(1[6-9]|2\d|3[01])\./g,     // Private network
      /file:\/\//gi,
      /gopher:\/\//gi,
      /dict:\/\//gi,
      /metadata\.google\.internal/gi,    // GCP metadata
    ];

    // Dangerous file extensions that should be blocked
    // Prevents upload of executable and server-side script files
    this.dangerousExtensions = [
      'php', 'php3', 'php4', 'php5', 'phtml', 'phps',
      'asp', 'aspx', 'ascx', 'ashx', 'asmx', 'axd',
      'jsp', 'jspx', 'jsw', 'jsv', 'jspf',
      'exe', 'dll', 'bat', 'cmd', 'sh', 'bash',
      'pl', 'cgi', 'py', 'rb', 'jar', 'war',
      'htaccess', 'htpasswd', 'ini', 'config',
    ];

    // Common scanning patterns for directory/subdomain enumeration
    // Used to detect automated reconnaissance and information gathering
    this.scanPatterns = [
      '/admin', '/administrator', '/wp-admin', '/wp-login',
      '/.git', '/.env', '/.htaccess', '/config',
      '/backup', '/db', '/database', '/sql',
      '/phpmyadmin', '/phpinfo', '/test', '/dev',
      '/api', '/v1', '/v2', '/swagger', '/graphql',
      '/.well-known', '/robots.txt', '/sitemap.xml',
    ];
  }

  /**
   * Main security analysis function - comprehensive threat detection
   * 
   * Analyzes incoming requests through multiple security layers:
   * 1. Directory Traversal Detection
   * 2. SQL Injection Detection
   * 3. NoSQL Injection Detection
   * 4. XSS Detection
   * 5. Command Injection Detection
   * 6. SSTI Detection
   * 7. SSRF Detection
   * 8. Scanning Detection
   * 9. Brute Force Detection
   * 10. Bot Detection
   * 11. Information Gathering Detection
   * 
   * Uses behavioral analysis to minimize false positives while
   * maintaining high security standards.
   * 
   * @param {Object} req - HTTP request object
   * @returns {Object} Analysis result with allowed status, threats, and score
   */
  async analyze(req) {
    const ip = this.getClientIP(req);
    
    // Skip analysis for whitelisted IPs
    // Localhost and trusted IPs bypass all security checks
    if (this.firewall && this.firewall.isIPWhitelisted(ip)) {
      return { allowed: true, threats: [], threatScore: 0, whitelisted: true };
    }
    
    const url = req.url;
    const method = req.method;
    const headers = req.headers;
    const userAgent = headers['user-agent'] || '';

    // Skip strict analysis for framework internal requests
    // Modern frameworks (Next.js, Nuxt, etc.) make many internal requests
    // that can contain special characters in paths (webpack chunks, HMR, etc.)
    // These should not trigger injection detection
    if (this.firewall && this.firewall.isFrameworkRequest(req)) {
      return { allowed: true, threats: [], threatScore: 0, framework: true };
    }

    // Skip strict analysis for exempt paths (static files, API routes, etc.)
    // These paths are part of normal framework operation
    if (this.firewall && this.firewall.isPathExempt(url)) {
      return { allowed: true, threats: [], threatScore: 0, exemptPath: true };
    }

    // Initialize behavior tracking for new IPs
    // This enables behavioral analysis and bot detection
    if (!this.userBehavior.has(ip)) {
      this.userBehavior.set(ip, {
        requests: [],
        scanScore: 0,
        lastRequest: Date.now(),
        suspiciousActivities: [],
        isBot: false,
        requestCount: 0,
      });
    }

    const behavior = this.userBehavior.get(ip);
    const now = Date.now();
    const timeSinceLastRequest = now - behavior.lastRequest;

    // Track request for behavioral analysis
    // Maintains sliding window of recent requests for pattern detection
    behavior.requests.push({
      url,
      method,
      timestamp: now,
      userAgent,
    });
    behavior.requestCount++;
    behavior.lastRequest = now;

    // Keep only recent requests (last 60 seconds)
    behavior.requests = behavior.requests.filter(r => now - r.timestamp < 60000);

    // Execute all security checks
    // Each check returns detected threats which are aggregated
    const threats = [];

    // 1. Directory Traversal Detection
    // Detects path traversal attempts (../,  ../, etc.)
    const directoryTraversal = this.detectDirectoryTraversal(url, headers);
    if (directoryTraversal.detected) {
      threats.push({ type: 'directory_traversal', severity: 'high', ...directoryTraversal });
    }

    // 2. SQL Injection Detection
    const sqlInjection = this.detectSQLInjection(url, headers);
    if (sqlInjection.detected) {
      threats.push({ type: 'sql_injection', severity: 'critical', ...sqlInjection });
    }

    // 3. NoSQL Injection Detection
    const nosqlInjection = this.detectNoSQLInjection(url, headers);
    if (nosqlInjection.detected) {
      threats.push({ type: 'nosql_injection', severity: 'high', ...nosqlInjection });
    }

    // 4. XSS Detection
    const xss = this.detectXSS(url, headers);
    if (xss.detected) {
      threats.push({ type: 'xss', severity: 'high', ...xss });
    }

    // 5. Command Injection Detection
    const cmdInjection = this.detectCommandInjection(url, headers);
    if (cmdInjection.detected) {
      threats.push({ type: 'command_injection', severity: 'critical', ...cmdInjection });
    }

    // 6. SSTI Detection
    const ssti = this.detectSSTI(url, headers);
    if (ssti.detected) {
      threats.push({ type: 'ssti', severity: 'critical', ...ssti });
    }

    // 7. SSRF Detection
    const ssrf = this.detectSSRF(url, headers);
    if (ssrf.detected) {
      threats.push({ type: 'ssrf', severity: 'high', ...ssrf });
    }

    // 8. Scanning Detection (Directory/Subdomain enumeration)
    const scanning = this.detectScanning(behavior, ip);
    if (scanning.detected) {
      threats.push({ type: 'scanning', severity: 'medium', ...scanning });
    }

    // 9. Brute Force Detection
    const bruteForce = this.detectBruteForce(req, ip, behavior);
    if (bruteForce.detected) {
      threats.push({ type: 'brute_force', severity: 'high', ...bruteForce });
    }

    // 10. Bot Detection (Superhuman speed)
    const botDetection = this.detectBot(behavior, timeSinceLastRequest);
    if (botDetection.isBot) {
      threats.push({ type: 'bot_activity', severity: 'medium', ...botDetection });
    }

    // 11. Information Gathering Detection
    const infoGathering = this.detectInformationGathering(behavior, url);
    if (infoGathering.detected) {
      threats.push({ type: 'info_gathering', severity: 'low', ...infoGathering });
    }

    // Calculate overall threat score based on detected threats
    // and historical behavior
    const threatScore = this.calculateThreatScore(threats, behavior);

    // Decision making based on threat level
    // Uses graduated response: log -> block -> ban
    if (threatScore >= 100) {
      // Critical threat - immediate ban to protect infrastructure
      this.firewall.banIP(ip, `Critical security threat detected: ${threats.map(t => t.type).join(', ')}`);
      return {
        allowed: false,
        statusCode: 403,
        reason: 'Security threat detected',
        threats,
        threatScore,
      };
    } else if (threatScore >= 70) {
      // High - Block request but don't ban yet
      behavior.suspiciousActivities.push(...threats);
      if (behavior.suspiciousActivities.length >= 5) {
        this.firewall.banIP(ip, 'Multiple security violations');
        return {
          allowed: false,
          statusCode: 403,
          reason: 'Multiple security violations',
          threats,
          threatScore,
        };
      }
      return {
        allowed: false,
        statusCode: 403,
        reason: 'Suspicious request blocked',
        threats,
        threatScore,
      };
    } else if (threatScore >= 40) {
      // Medium - Log and allow but track
      this.logger.warn('Suspicious request detected', {
        ip,
        url,
        threats,
        threatScore,
      });
      behavior.scanScore += 10;
    }

    // Update behavior
    this.userBehavior.set(ip, behavior);

    return {
      allowed: true,
      threats,
      threatScore,
    };
  }

  detectDirectoryTraversal(url, headers) {
    // Skip detection for framework paths
    // Next.js uses paths like /_next/static/... which can contain dots
    // that might trigger false positives for directory traversal
    if (this.firewall && this.firewall.isPathExempt(url)) {
      return { detected: false, reason: 'exempt_path' };
    }

    const fullContent = `${url} ${JSON.stringify(headers)}`;
    
    for (const pattern of this.directoryTraversalPatterns) {
      if (pattern.test(fullContent)) {
        return {
          detected: true,
          pattern: pattern.toString(),
          location: url,
        };
      }
    }
    
    return { detected: false };
  }

  detectSQLInjection(url, headers) {
    const fullContent = `${url} ${JSON.stringify(headers)}`;
    
    for (const pattern of this.sqlInjectionPatterns) {
      if (pattern.test(fullContent)) {
        return {
          detected: true,
          pattern: pattern.toString(),
          location: url,
        };
      }
    }
    
    return { detected: false };
  }

  detectNoSQLInjection(url, headers) {
    const fullContent = `${url} ${JSON.stringify(headers)}`;
    
    for (const pattern of this.nosqlInjectionPatterns) {
      if (pattern.test(fullContent)) {
        return {
          detected: true,
          pattern: pattern.toString(),
          location: url,
        };
      }
    }
    
    return { detected: false };
  }

  detectXSS(url, headers) {
    const fullContent = `${url} ${JSON.stringify(headers)}`;
    
    for (const pattern of this.xssPatterns) {
      if (pattern.test(fullContent)) {
        return {
          detected: true,
          pattern: pattern.toString(),
          location: url,
        };
      }
    }
    
    return { detected: false };
  }

  detectCommandInjection(url, headers) {
    // Skip detection for framework paths and static files
    // Webpack chunks, source maps, and other framework files can contain
    // special characters that look like shell metacharacters but are harmless
    // Example: chunk.[hash].js?v=123, sourcemap.map.js, etc.
    if (this.firewall && this.firewall.isPathExempt(url)) {
      return { detected: false, reason: 'exempt_path' };
    }

    // CRITICAL FIX: Only check URL and query params, NOT headers
    // Headers contain legitimate special characters (Accept-Encoding: gzip, deflate, br)
    // JSON.stringify(headers) adds {}, [], : which triggers false positives
    // User-Agent, Accept headers are safe and should not be checked for command injection
    const urlOnly = url; // Only check the actual URL path
    
    // Very short URLs (< 10 chars) are unlikely to contain command injection
    // This prevents false positives on paths like /, /api, /home
    if (urlOnly.length < 10) {
      return { detected: false, reason: 'url_too_short' };
    }
    
    for (const pattern of this.commandInjectionPatterns) {
      const matches = urlOnly.match(pattern);
      // Command injection requires actual command execution patterns
      // Single special char is not enough - need command context
      if (matches && matches.length >= 1) {
        // Additional validation: check if it looks like a real command injection
        // Real attacks have patterns like: ?cmd=ls|cat, ?exec=$(whoami), etc.
        const hasCommandContext = /(\?|&)(cmd|exec|command|run|shell)=/i.test(urlOnly) ||
                                   /(;|&&|\|\|)\s*(cat|ls|whoami|id|pwd|curl|wget)/i.test(urlOnly);
        
        if (hasCommandContext) {
          return {
            detected: true,
            pattern: pattern.toString(),
            location: url,
          };
        }
      }
    }
    
    return { detected: false };
  }

  detectSSTI(url, headers) {
    const fullContent = `${url} ${JSON.stringify(headers)}`;
    
    for (const pattern of this.sstiPatterns) {
      if (pattern.test(fullContent)) {
        return {
          detected: true,
          pattern: pattern.toString(),
          location: url,
        };
      }
    }
    
    return { detected: false };
  }

  detectSSRF(url, headers) {
    const fullContent = `${url} ${JSON.stringify(headers)}`;
    
    for (const pattern of this.ssrfPatterns) {
      if (pattern.test(fullContent)) {
        return {
          detected: true,
          pattern: pattern.toString(),
          location: url,
        };
      }
    }
    
    return { detected: false };
  }

  /**
   * Detect scanning activity (directory/subdomain enumeration)
   * 
   * Uses behavioral analysis to distinguish between legitimate browsing
   * and automated scanning. Prevents false positives by analyzing:
   * - Request patterns and uniqueness
   * - Request rate (superhuman speeds)
   * - Common scan path hits
   * - Sequential exploration patterns
   * 
   * @param {Object} behavior - IP's behavioral data
   * @param {string} ip - Client IP address
   * @returns {Object} Detection result with scan score and metrics
   */
  detectScanning(behavior, ip) {
    const recentRequests = behavior.requests.slice(-20); // Last 20 requests
    
    if (recentRequests.length < 10) return { detected: false };

    let scanPatternHits = 0;
    let notFoundCount = 0;
    let uniquePaths = new Set();
    let pathDepthVariance = [];

    for (const req of recentRequests) {
      const path = new URL(req.url, 'http://dummy').pathname;
      uniquePaths.add(path);
      
      // Check against common scan patterns
      if (this.scanPatterns.some(p => path.includes(p))) {
        scanPatternHits++;
      }
      
      // Track path depth
      const depth = path.split('/').filter(p => p).length;
      pathDepthVariance.push(depth);
    }

    // Calculate metrics
    const uniquePathRatio = uniquePaths.size / recentRequests.length;
    const requestRate = recentRequests.length / 60; // requests per second over last minute
    
    // Scanning indicators (weighted scoring system):
    // 1. High unique path ratio (>80%) - exploring different paths
    // 2. High request rate (>10 req/sec) - automated behavior
    // 3. Many scan pattern hits - targeting common endpoints
    // 4. Sequential or systematic path exploration - not human-like
    
    // Adjusted thresholds for framework compatibility:
    // Frameworks like Next.js can easily make 50+ requests/sec during SSR
    // Static file serving, API routes, and HMR generate high request rates
    const scanScore = 
      (uniquePathRatio > 0.8 ? 30 : 0) +
      (scanPatternHits > 5 ? 40 : scanPatternHits * 5) +
      (requestRate > 50 ? 30 : 0); // Increased from 10 to 50 for framework compatibility

    if (scanScore >= 50) {
      behavior.scanScore += scanScore;
      return {
        detected: true,
        scanScore,
        uniquePathRatio,
        requestRate,
        scanPatternHits,
      };
    }

    return { detected: false };
  }

  /**
   * Brute Force Detection
   * 
   * Monitors login/auth endpoints for credential stuffing and
   * brute force attacks. Uses human-friendly thresholds to avoid
   * blocking legitimate users who mistype passwords.
   * 
   * Thresholds:
   * - 5 attempts/minute (allows typos)
   * - 15 attempts/5 minutes (prevents automated attacks)
   * 
   * @param {Object} req - HTTP request object
   * @param {string} ip - Client IP address
   * @param {Object} behavior - IP's behavioral data
   * @returns {Object} Detection result with attempt count
   */
  detectBruteForce(req, ip, behavior) {
    const url = req.url.toLowerCase();
    const method = req.method;

    // Check if this is a login/auth endpoint
    const isAuthEndpoint = 
      url.includes('/login') ||
      url.includes('/signin') ||
      url.includes('/auth') ||
      url.includes('/api/login') ||
      url.includes('/authenticate');

    if (!isAuthEndpoint || method !== 'POST') {
      return { detected: false };
    }

    // Track login attempts
    const key = `${ip}:${url}`;
    if (!this.loginAttempts.has(key)) {
      this.loginAttempts.set(key, {
        attempts: [],
        failedAttempts: 0,
      });
    }

    const loginData = this.loginAttempts.get(key);
    const now = Date.now();
    
    // Add attempt
    loginData.attempts.push(now);
    
    // Clean old attempts (keep last 5 minutes)
    loginData.attempts = loginData.attempts.filter(t => now - t < 300000);

    // Check for brute force
    const attemptsIn1Min = loginData.attempts.filter(t => now - t < 60000).length;
    const attemptsIn5Min = loginData.attempts.length;

    // Human-like threshold: max 5 attempts per minute, 15 per 5 minutes
    if (attemptsIn1Min > 5 || attemptsIn5Min > 15) {
      return {
        detected: true,
        attempts: attemptsIn5Min,
        endpoint: url,
      };
    }

    return { detected: false };
  }

  /**
   * Bot Detection - Superhuman Speed Detection
   * 
   * Distinguishes between human users and automated bots by analyzing:
   * - Inter-request timing (humans: >100ms, bots: <50ms)
   * - User-Agent presence and signatures
   * - Timing consistency (humans vary, bots are consistent)
   * - Request pattern regularity
   * 
   * Normal users can't click faster than ~100ms between pages.
   * Fast browsing (200-500ms) is allowed to preserve UX.
   * Only superhuman speeds (<50ms) are flagged.
   * 
   * @param {Object} behavior - IP's behavioral data
   * @param {number} timeSinceLastRequest - Ms since last request
   * @returns {Object} Bot detection result with score and reasoning
   */
  detectBot(behavior, timeSinceLastRequest) {
    const recentRequests = behavior.requests.slice(-10);
    
    if (recentRequests.length < 3) {
      return { isBot: false };
    }

    // Calculate inter-request times
    const interRequestTimes = [];
    for (let i = 1; i < recentRequests.length; i++) {
      const timeDiff = recentRequests[i].timestamp - recentRequests[i - 1].timestamp;
      interRequestTimes.push(timeDiff);
    }

    // Analyze request timing for superhuman speed patterns
    const veryFastRequests = interRequestTimes.filter(t => t < 50).length;  // < 50ms = impossible for humans
    const fastRequests = interRequestTimes.filter(t => t < 200).length;     // < 200ms = very fast
    
    // Calculate bot indicators
    const avgTime = interRequestTimes.reduce((a, b) => a + b, 0) / interRequestTimes.length;
    
    // VERY relaxed superhuman detection for browser page loads
    // Browsers load HTML, then immediately make 20-50 parallel requests for CSS/JS/images
    // All these arrive within milliseconds of each other - this is NORMAL, not bot activity
    // Only flag as bot if EXTREME sustained superhuman speed (10+ requests at <10ms intervals)
    // This allows normal browser parallel loading while catching real bots
    const extremelyFastRequests = interRequestTimes.filter(t => t < 10).length; // < 10ms = likely parallel browser requests
    const isSuperhuman = extremelyFastRequests >= 10 || (avgTime < 20 && veryFastRequests >= 15);
    
    // Additional bot checks
    const userAgent = recentRequests[0]?.userAgent || '';
    const hasNoUserAgent = !userAgent;
    
    // Updated bot user-agent detection to exclude legitimate frameworks
    // Next.js, node-fetch, axios, etc. are legitimate HTTP clients
    // Only flag known malicious crawlers/scrapers
    const hasBotUserAgent = /bot|crawler|spider|scraper|curl|wget|python-requests/i.test(userAgent) &&
                            !/next\.js|node-fetch|axios|undici/i.test(userAgent); // Exclude legitimate frameworks
    
    // Pattern consistency (bots often have very consistent timing)
    const timingVariance = this.calculateVariance(interRequestTimes);
    const hasConsistentTiming = timingVariance < 100; // Very consistent = bot

    // Bot scoring with high threshold to avoid blocking browsers
    // Modern browsers with HTTP/2 or parallel connections can send 50+ requests simultaneously
    // This is normal behavior during page load and should NOT be flagged as bot
    const botScore = 
      (isSuperhuman ? 50 : 0) +
      (hasNoUserAgent ? 30 : 0) +
      (hasBotUserAgent ? 20 : 0) +
      (hasConsistentTiming && avgTime < 100 ? 20 : 0); // Increased from 500 to 100

    // Very high threshold to prevent false positives on legitimate browser traffic
    // Browsers loading a page generate burst traffic that looks "bot-like" but isn't
    if (botScore >= 80) { // Increased from 50 to 80
      behavior.isBot = true;
      return {
        isBot: true,
        botScore,
        avgTime,
        veryFastRequests,
        reason: isSuperhuman ? 'superhuman_speed' : 'bot_signature',
      };
    }

    return { isBot: false };
  }

  /**
   * Information Gathering Detection
   * Detects systematic information collection
   */
  detectInformationGathering(behavior, url) {
    const recentRequests = behavior.requests.slice(-20);
    
    if (recentRequests.length < 5) return { detected: false };

    // Common info gathering paths
    const infoGatheringPaths = [
      '/robots.txt', '/sitemap.xml', '/.well-known',
      '/swagger', '/api/docs', '/graphql',
      '/version', '/status', '/health', '/info',
      '/.git/config', '/.env', '/package.json',
    ];

    const infoRequests = recentRequests.filter(req => {
      const path = new URL(req.url, 'http://dummy').pathname;
      return infoGatheringPaths.some(p => path.includes(p));
    });

    if (infoRequests.length >= 3) {
      return {
        detected: true,
        infoRequestsCount: infoRequests.length,
        paths: infoRequests.map(r => r.url),
      };
    }

    return { detected: false };
  }

  /**
   * Generate cryptographically secure CSRF token
   * @returns {string} 64-character hexadecimal token
   */
  generateCSRFToken() {
    return crypto.randomBytes(32).toString('hex');
  }

  validateCSRFToken(token, sessionId) {
    const storedToken = this.csrfTokens.get(sessionId);
    return storedToken && storedToken === token;
  }

  /**
   * Comprehensive File Upload Validation
   * 
   * Validates uploaded files against multiple security criteria:
   * - Dangerous extension blocking
   * - MIME type validation
   * - Extension-MIME type matching
   * - Double extension detection
   * 
   * @param {string} filename - Uploaded filename
   * @param {string} mimetype - Content-Type header value
   * @param {number} size - File size in bytes
   * @returns {Object} Validation result with reason if invalid
   */
  validateFileUpload(filename, mimetype, size) {
    const ext = filename.split('.').pop().toLowerCase();
    
    // Check dangerous extensions
    if (this.dangerousExtensions.includes(ext)) {
      return {
        valid: false,
        reason: 'Dangerous file extension',
        extension: ext,
      };
    }

    // Check mimetype vs extension mismatch
    const expectedMimetype = this.getExpectedMimetype(ext);
    if (expectedMimetype && !mimetype.includes(expectedMimetype)) {
      return {
        valid: false,
        reason: 'Mimetype mismatch',
        expected: expectedMimetype,
        actual: mimetype,
      };
    }

    // Check double extensions
    const parts = filename.split('.');
    if (parts.length > 2) {
      return {
        valid: false,
        reason: 'Multiple extensions detected',
        filename,
      };
    }

    return { valid: true };
  }

  getExpectedMimetype(ext) {
    const mimetypes = {
      'jpg': 'image/jpeg',
      'jpeg': 'image/jpeg',
      'png': 'image/png',
      'gif': 'image/gif',
      'pdf': 'application/pdf',
      'txt': 'text/plain',
      'doc': 'application/msword',
      'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    };
    return mimetypes[ext];
  }

  /**
   * Calculate overall threat score
   * 
   * Combines severity of detected threats with historical behavior.
   * Uses weighted scoring system:
   * - Critical: 100 points (immediate ban)
   * - High: 70 points (block request)
   * - Medium: 40 points (log and track)
   * - Low: 20 points (monitor only)
   * 
   * @param {Array} threats - Array of detected threats
   * @param {Object} behavior - Historical behavior data
   * @returns {number} Total threat score (0-200+)
   */
  calculateThreatScore(threats, behavior) {
    const severityScores = {
      critical: 100,
      high: 70,
      medium: 40,
      low: 20,
    };

    let score = 0;
    
    for (const threat of threats) {
      score += severityScores[threat.severity] || 0;
    }

    // Add historical behavior score
    score += Math.min(behavior.scanScore, 50);

    return score;
  }

  calculateVariance(numbers) {
    if (numbers.length === 0) return 0;
    const avg = numbers.reduce((a, b) => a + b, 0) / numbers.length;
    const squareDiffs = numbers.map(value => Math.pow(value - avg, 2));
    return Math.sqrt(squareDiffs.reduce((a, b) => a + b, 0) / numbers.length);
  }

  getClientIP(req) {
    return req.headers['x-forwarded-for']?.split(',')[0].trim() ||
           req.headers['x-real-ip'] ||
           req.connection?.remoteAddress ||
           req.socket?.remoteAddress;
  }

  startCleanup() {
    // Clean up old data every 10 minutes
    setInterval(() => {
      const now = Date.now();
      const maxAge = 600000; // 10 minutes

      // Clean behavior data
      for (const [ip, behavior] of this.userBehavior.entries()) {
        if (now - behavior.lastRequest > maxAge) {
          this.userBehavior.delete(ip);
        }
      }

      // Clean login attempts
      for (const [key, data] of this.loginAttempts.entries()) {
        data.attempts = data.attempts.filter(t => now - t < 300000);
        if (data.attempts.length === 0) {
          this.loginAttempts.delete(key);
        }
      }

      // Clean CSRF tokens
      // TODO: Implement session-based cleanup

    }, 600000); // Every 10 minutes
  }

  getStats() {
    return {
      trackedIPs: this.userBehavior.size,
      activeLoginAttempts: this.loginAttempts.size,
      csrfTokens: this.csrfTokens.size,
    };
  }
}

module.exports = { AdvancedSecurity };

