const http = require('http');
const { getLogger } = require('./Logger');
const configs = require('../configs.json');

class AdminAPI {
  constructor(httpServer, httpsServer) {
    this.httpServer = httpServer;
    this.httpsServer = httpsServer;
    this.port = configs.admin.port;
    this.token = configs.admin.token;
    this.allowedIPs = new Set(configs.admin.allowedIPs || []);
    this.server = null;
    this.logger = getLogger();
  }

  authenticate(req) {
    const authHeader = req.headers['authorization'];
    const token = authHeader?.replace('Bearer ', '');
    
    if (token !== this.token) {
      return { authorized: false, reason: 'Invalid token' };
    }

    // IP whitelist check
    if (this.allowedIPs.size > 0) {
      const clientIP = this.getClientIP(req);
      if (!this.allowedIPs.has(clientIP)) {
        return { authorized: false, reason: 'IP not allowed' };
      }
    }

    return { authorized: true };
  }

  getClientIP(req) {
    return req.headers['x-forwarded-for']?.split(',')[0].trim() ||
           req.headers['x-real-ip'] ||
           req.connection?.remoteAddress ||
           req.socket?.remoteAddress;
  }

  async handleRequest(req, res) {
    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    // Authentication
    const auth = this.authenticate(req);
    if (!auth.authorized) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: auth.reason }));
      return;
    }

    const url = new URL(req.url, `http://localhost:${this.port}`);
    const path = url.pathname;

    try {
      // Routes
      if (path === '/api/status' && req.method === 'GET') {
        return this.handleStatus(req, res);
      }

      if (path === '/api/stats' && req.method === 'GET') {
        return this.handleStats(req, res);
      }

      if (path === '/api/firewall/banned-ips' && req.method === 'GET') {
        return this.handleGetBannedIPs(req, res);
      }

      if (path === '/api/firewall/ban' && req.method === 'POST') {
        return this.handleBanIP(req, res);
      }

      if (path === '/api/firewall/unban' && req.method === 'POST') {
        return this.handleUnbanIP(req, res);
      }

      if (path === '/api/reload' && req.method === 'POST') {
        return this.handleReload(req, res);
      }

      if (path === '/api/domains' && req.method === 'GET') {
        return this.handleGetDomains(req, res);
      }

      if (path === '/api/security/stats' && req.method === 'GET') {
        return this.handleSecurityStats(req, res);
      }

      if (path === '/api/security/threats' && req.method === 'GET') {
        return this.handleRecentThreats(req, res);
      }

      if (path === '/api/security/clear-behavior' && req.method === 'POST') {
        return this.handleClearBehavior(req, res);
      }

      // 404
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not found' }));

    } catch (error) {
      this.logger.error('Admin API error', {
        error: error.message,
        stack: error.stack,
        path,
        ip: this.getClientIP(req)
      });

      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Internal server error' }));
    }
  }

  handleStatus(req, res) {
    const status = {
      status: 'running',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      servers: {
        http: {
          enabled: configs.http.enabled,
          port: configs.http.port
        },
        https: {
          enabled: configs.https.enabled,
          port: configs.https.port
        }
      }
    };

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(status, null, 2));
  }

  handleStats(req, res) {
    const stats = {
      http: this.httpServer?.firewall?.getStats() || null,
      https: this.httpsServer?.firewall?.getStats() || null
    };

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(stats, null, 2));
  }

  handleGetBannedIPs(req, res) {
    const firewall = this.httpServer?.firewall || this.httpsServer?.firewall;
    
    if (!firewall) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Firewall not enabled' }));
      return;
    }

    const bannedIPs = Array.from(firewall.bannedIPs);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ bannedIPs }, null, 2));
  }

  async handleBanIP(req, res) {
    let body = '';
    
    req.on('data', chunk => {
      body += chunk.toString();
    });

    req.on('end', () => {
      try {
        const { ip, reason } = JSON.parse(body);
        
        if (!ip) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'IP address required' }));
          return;
        }

        const firewall = this.httpServer?.firewall || this.httpsServer?.firewall;
        
        if (!firewall) {
          res.writeHead(404, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Firewall not enabled' }));
          return;
        }

        firewall.banIP(ip, reason || 'Manual ban via Admin API');
        
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, message: `IP ${ip} banned` }));
        
      } catch (error) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid JSON' }));
      }
    });
  }

  async handleUnbanIP(req, res) {
    let body = '';
    
    req.on('data', chunk => {
      body += chunk.toString();
    });

    req.on('end', () => {
      try {
        const { ip } = JSON.parse(body);
        
        if (!ip) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'IP address required' }));
          return;
        }

        const firewall = this.httpServer?.firewall || this.httpsServer?.firewall;
        
        if (!firewall) {
          res.writeHead(404, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Firewall not enabled' }));
          return;
        }

        firewall.unbanIP(ip);
        
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, message: `IP ${ip} unbanned` }));
        
      } catch (error) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid JSON' }));
      }
    });
  }

  handleReload(req, res) {
    try {
      if (this.httpServer) {
        this.httpServer.reload();
      }
      
      if (this.httpsServer) {
        this.httpsServer.reload();
      }

      this.logger.info('Configuration reloaded via Admin API');
      
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, message: 'Configuration reloaded' }));
      
    } catch (error) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: error.message }));
    }
  }

  handleGetDomains(req, res) {
    const domainManager = this.httpServer?.domainManager || this.httpsServer?.domainManager;
    
    if (!domainManager) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Domain manager not available' }));
      return;
    }

    const domains = domainManager.getAllDomains();
    const domainsData = {};
    
    for (const domain of domains) {
      domainsData[domain] = domainManager.getDomain(domain);
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ domains: domainsData }, null, 2));
  }

  handleSecurityStats(req, res) {
    const advancedSecurity = this.httpServer?.advancedSecurity || this.httpsServer?.advancedSecurity;
    
    if (!advancedSecurity) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Advanced security not enabled' }));
      return;
    }

    const stats = advancedSecurity.getStats();
    const detailedStats = {
      ...stats,
      timestamp: new Date().toISOString(),
      securityFeatures: {
        directoryTraversal: 'enabled',
        sqlInjection: 'enabled',
        nosqlInjection: 'enabled',
        xss: 'enabled',
        commandInjection: 'enabled',
        ssti: 'enabled',
        ssrf: 'enabled',
        scanningDetection: 'enabled',
        bruteForceProtection: 'enabled',
        botDetection: 'enabled',
        informationGatheringDetection: 'enabled',
        csrfProtection: 'enabled',
        fileUploadValidation: 'enabled'
      }
    };

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(detailedStats, null, 2));
  }

  handleRecentThreats(req, res) {
    const advancedSecurity = this.httpServer?.advancedSecurity || this.httpsServer?.advancedSecurity;
    
    if (!advancedSecurity) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Advanced security not enabled' }));
      return;
    }

    // Get recent threats from behavior data
    const recentThreats = [];
    for (const [ip, behavior] of advancedSecurity.userBehavior.entries()) {
      if (behavior.suspiciousActivities && behavior.suspiciousActivities.length > 0) {
        recentThreats.push({
          ip,
          threats: behavior.suspiciousActivities,
          scanScore: behavior.scanScore,
          requestCount: behavior.requestCount,
          isBot: behavior.isBot,
          lastActivity: new Date(behavior.lastRequest).toISOString()
        });
      }
    }

    // Sort by scan score (most dangerous first)
    recentThreats.sort((a, b) => b.scanScore - a.scanScore);

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ 
      totalThreats: recentThreats.length,
      threats: recentThreats.slice(0, 50) // Top 50
    }, null, 2));
  }

  async handleClearBehavior(req, res) {
    let body = '';
    
    req.on('data', chunk => {
      body += chunk.toString();
    });

    req.on('end', () => {
      try {
        const { ip } = JSON.parse(body);
        
        if (!ip) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'IP address required' }));
          return;
        }

        const advancedSecurity = this.httpServer?.advancedSecurity || this.httpsServer?.advancedSecurity;
        
        if (!advancedSecurity) {
          res.writeHead(404, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Advanced security not enabled' }));
          return;
        }

        // Clear behavior data for IP
        advancedSecurity.userBehavior.delete(ip);
        advancedSecurity.loginAttempts.forEach((value, key) => {
          if (key.startsWith(ip + ':')) {
            advancedSecurity.loginAttempts.delete(key);
          }
        });

        this.logger.info(`Cleared behavior data for IP: ${ip}`);
        
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ 
          success: true, 
          message: `Behavior data cleared for IP ${ip}` 
        }));
        
      } catch (error) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid JSON' }));
      }
    });
  }

  start() {
    this.server = http.createServer((req, res) => {
      this.handleRequest(req, res);
    });

    this.server.listen(this.port, () => {
      this.logger.info(`Admin API started on port ${this.port}`);
      this.logger.warn(`Admin API Token: ${this.token}`);
    });
  }

  stop() {
    if (this.server) {
      this.server.close(() => {
        this.logger.info('Admin API stopped');
      });
    }
  }
}

module.exports = { AdminAPI };

