const httpProxy = require('http-proxy');
const { DomainManager } = require('../Utils/DomainManager');
const { Firewall } = require('../Utils/Firewall');
const { AdvancedSecurity } = require('../Utils/AdvancedSecurity');
const { getLogger } = require('../Utils/Logger');
const configs = require('../configs.json');

class BaseProxyServer {
  constructor(serverType = 'http') {
    this.serverType = serverType;
    this.logger = getLogger();
    this.proxy = httpProxy.createProxyServer({
      xfwd: true,
      preserveHeaderKeyCase: true,
      autoRewrite: true,
      secure: false,
      changeOrigin: true,
      proxyTimeout: configs.timeout.proxy,
      timeout: configs.timeout.server
    });

    this.domainManager = new DomainManager();
    this.firewall = configs.firewall.enabled ? new Firewall() : null;
    this.advancedSecurity = configs.firewall.enabled ? new AdvancedSecurity(this.firewall) : null;
    this.server = null;
    this.activeConnections = new Set();

    this.setupProxyErrorHandling();
    this.setupWebSocketHandling();
  }

  setupProxyErrorHandling() {
    this.proxy.on('error', (err, req, res) => {
      this.logger.error(`Proxy error: ${req.headers.host}${req.url}`, {
        error: err.message,
        stack: err.stack,
        type: this.serverType,
        ip: this.logger.getClientIP(req)
      });

      if (!res.headersSent) {
        res.writeHead(502, { 
          'Content-Type': 'text/plain',
          'X-Proxy-Error': 'true'
        });
        res.end('Bad Gateway');
      }
    });

    this.proxy.on('proxyReq', (proxyReq, req, res) => {
      // Add custom headers
      proxyReq.setHeader('X-Forwarded-Proto', this.serverType);
      proxyReq.setHeader('X-Forwarded-Host', req.headers.host);
    });

    // CRITICAL FIX: Add security headers to proxied response (not request!)
    // Next.js and other frameworks need their response headers preserved
    // Security headers must be added AFTER proxy receives backend response
    // This prevents CSP from blocking Next.js inline scripts/styles during hydration
    this.proxy.on('proxyRes', (proxyRes, req, res) => {
      // Add security headers to the proxied response
      this.addSecurityHeaders(res, proxyRes);
    });
  }

  setupWebSocketHandling() {
    if (!configs.websocket.enabled) return;

    this.proxy.on('upgrade', (req, socket, head) => {
      this.logger.info('WebSocket upgrade request', {
        host: req.headers.host,
        url: req.url,
        ip: this.logger.getClientIP(req)
      });
    });

    this.proxy.on('error', (err, req, socket) => {
      this.logger.error('WebSocket error', {
        error: err.message,
        host: req.headers.host,
        ip: this.logger.getClientIP(req)
      });
      socket.end();
    });
  }

  resolveTarget(req) {
    const host = req.headers.host?.split(':')[0] || '';
    const url = req.url || '/';
    const parts = host.split('.');

    if (parts.length < 2) return null;
    let domain = null;
    let subdomain = null;

    for (let i = 0; i < parts.length - 1; i++) {
      const candidate = parts.slice(i).join('.');
      const domainConfig = this.domainManager.getDomain(candidate);
      if (domainConfig) {
        domain = candidate;
        if (i > 0) subdomain = parts.slice(0, i).join('.');
        break;
      }
    }

    if (!domain) return null;
    const domainConfig = this.domainManager.getDomain(domain);
    if (!domainConfig) return null;

    // --- SUBDOMAIN ROUTES ---
    if (subdomain && domainConfig.subdomains[subdomain]) {
      const routes = domainConfig.subdomains[subdomain];
      for (const route of routes) {
        if (route.redirect) {
          return {
            type: 'redirect',
            target: route.redirect,
            domain
          };
        }
        if (route.path && this.matchPath(url, route.path)) {
          return {
            type: 'proxy',
            port: route.port,
            host: route.host || 'localhost'
          };
        }
      }
    }

    // --- DOMAIN ROUTES ---
    if (domainConfig.routes && domainConfig.routes.length > 0) {
      for (const route of domainConfig.routes) {
        if (route.redirect) {
          return {
            type: 'redirect',
            target: route.redirect,
            domain
          };
        }
        if (route.path && this.matchPath(url, route.path)) {
          return {
            type: 'proxy',
            port: route.port,
            host: route.host || 'localhost'
          };
        }
      }
    }

    return null;
  }


  matchPath(requestPath, routePath) {
    // Normalize paths by removing trailing slashes for comparison
    const normalizeRoute = routePath === '/' ? '/' : routePath.replace(/\/$/, '');
    const normalizePath = requestPath === '/' ? '/' : requestPath.replace(/\/$/, '');
    
    // Exact match
    if (normalizeRoute === normalizePath) return true;
    
    // Root path matches everything
    if (normalizeRoute === '/') return true;
    
    // Path prefix match (e.g., /api matches /api/users)
    if (normalizePath.startsWith(normalizeRoute + '/')) return true;
    
    return false;
  }

  addSecurityHeaders(res, proxyRes) {
    const security = configs.security;

    // Only add HSTS for HTTPS
    if (security.enableHSTS && this.serverType === 'https') {
      res.setHeader('Strict-Transport-Security', 
        `max-age=${security.hstsMaxAge}; includeSubDomains; preload`);
    }

    // CRITICAL: Check if response is HTML before adding CSP
    // Next.js serves JS/CSS/JSON that should NOT have CSP applied
    // CSP blocks inline scripts/styles which breaks Next.js hydration
    const contentType = proxyRes ? proxyRes.headers['content-type'] : '';
    const isHTML = contentType && contentType.includes('text/html');
    
    if (security.enableCSP && isHTML) {
      // Relaxed CSP for Next.js compatibility
      // Allow 'unsafe-inline' for Next.js inline scripts and styles
      const nextJsCSP = security.cspPolicy
        .replace("script-src 'self'", "script-src 'self' 'unsafe-inline' 'unsafe-eval'")
        .replace("style-src 'self'", "style-src 'self' 'unsafe-inline'");
      
      res.setHeader('Content-Security-Policy', nextJsCSP);
    }

    if (security.enableXFrameOptions) {
      res.setHeader('X-Frame-Options', security.xFrameOptions);
    }

    // These are safe for all content types
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  }

  handleCORS(req, res) {
    if (!configs.security.enableCORS) return;

    const origin = req.headers.origin;
    const allowedOrigin = configs.security.corsOrigin;

    if (allowedOrigin === '*' || allowedOrigin === origin) {
      res.setHeader('Access-Control-Allow-Origin', allowedOrigin);
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Access-Control-Max-Age', '86400');
    }

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return true;
    }

    return false;
  }

  async handleRequest(req, res) {
    const startTime = Date.now();

    // Track connection
    this.activeConnections.add(req.socket);
    req.socket.on('close', () => {
      this.activeConnections.delete(req.socket);
    });

    try {
      // CORS preflight
      if (this.handleCORS(req, res)) {
        return;
      }

      if (configs.healthCheck.enabled && req.url === configs.healthCheck.path) {
        const host = req.headers.host || '';
        const isLocalhost = host.startsWith('localhost') || host.startsWith('127.0.0.1');
        const isAllowedIP = configs.healthCheck.allowedIPs.includes(host);
        
        // Only serve health check for localhost, IP addresses, or health subdomain
        if (isLocalhost || isAllowedIP ) {
          // Add security headers for health check response
          this.addSecurityHeaders(res);
          return this.handleHealthCheck(req, res);
        }
        // Otherwise, continue to route resolution (will proxy to backend)
      }

      // Advanced Security Analysis
      if (this.advancedSecurity) {
        const securityResult = await this.advancedSecurity.analyze(req);
        
        if (!securityResult.allowed) {
          // Add security headers for error response
          this.addSecurityHeaders(res);
          res.writeHead(securityResult.statusCode, { 
            'Content-Type': 'application/json',
            'X-Security-Block': 'true'
          });
          res.end(JSON.stringify({
            error: 'Request blocked for security reasons',
            requestId: Date.now().toString(36)
          }));
          
          this.logger.error('Request blocked by advanced security', {
            ip: this.advancedSecurity.getClientIP(req),
            reason: securityResult.reason,
            threats: securityResult.threats,
            threatScore: securityResult.threatScore,
            host: req.headers.host,
            url: req.url,
            method: req.method,
            userAgent: req.headers['user-agent']
          });
          return;
        }

        // Log medium-severity threats for monitoring
        if (securityResult.threatScore > 0) {
          this.logger.info('Security analysis completed', {
            ip: this.advancedSecurity.getClientIP(req),
            threatScore: securityResult.threatScore,
            threats: securityResult.threats,
            url: req.url
          });
        }
      }

      // Basic Firewall inspection
      if (this.firewall) {
        const firewallResult = await this.firewall.inspect(req);

        if (!firewallResult.allowed) {
          // Add security headers for error response
          this.addSecurityHeaders(res);
          res.writeHead(firewallResult.statusCode, { 'Content-Type': 'text/plain' });
          res.end(firewallResult.message);
          this.logger.warn('Request blocked by firewall', {
            ip: firewallResult.ip,
            reason: firewallResult.message,
            host: req.headers.host,
            url: req.url
          });
          return;
        }
      }

      // Resolve target
      const target = this.resolveTarget(req);

      if (!target) {
        // Add security headers for 404 response
        this.addSecurityHeaders(res);
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not Found');
        this.logger.warn('No route found', {
          host: req.headers.host,
          url: req.url,
          ip: this.logger.getClientIP(req)
        });
        return;
      }

      // Handle redirect
      if (target.type === 'redirect') {
        const protocol = this.serverType === 'https' ? 'https' : 'http';
        const redirectUrl = `${protocol}://${target.target}.${target.domain}${req.url}`;
        res.writeHead(301, { 'Location': redirectUrl });
        res.end();
        this.logger.info('Redirect', { 
          from: req.headers.host, 
          to: redirectUrl,
          ip: this.logger.getClientIP(req)
        });
        return;
      }

      // Handle proxy
      if (target.type === 'proxy') {
        const proxyTarget = `http://${target.host}:${target.port}`;
        
        // Log request
        res.on('finish', () => {
          const responseTime = Date.now() - startTime;
          this.logger.logRequest(req, res, responseTime);
        });

        this.proxy.web(req, res, { target: proxyTarget });
      }
    } catch (error) {
      this.logger.error('Request handling error', {
        error: error.message,
        stack: error.stack,
        host: req.headers.host,
        url: req.url,
        ip: this.logger.getClientIP(req)
      });

      if (!res.headersSent) {
        // Add security headers for 500 response
        this.addSecurityHeaders(res);
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end('Internal Server Error');
      }
    }
  }

  handleHealthCheck(req, res) {
    const stats = {
      status: 'ok',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      type: this.serverType,
      connections: this.activeConnections.size,
      memory: process.memoryUsage(),
      domains: this.domainManager.getAllDomains().length
    };

    if (this.firewall) {
      stats.firewall = this.firewall.getStats();
    }

    if (this.advancedSecurity) {
      stats.advancedSecurity = this.advancedSecurity.getStats();
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(stats, null, 2));
  }

  handleWebSocketUpgrade(req, socket, head) {
    if (!configs.websocket.enabled) {
      socket.destroy();
      return;
    }

    const target = this.resolveTarget(req);
    
    if (!target || target.type !== 'proxy') {
      socket.destroy();
      return;
    }

    const wsTarget = `ws://${target.host}:${target.port}`;
    this.proxy.ws(req, socket, head, { target: wsTarget });
  }

  stop() {
    this.logger.info(`Stopping ${this.serverType} proxy server...`);
    
    // Close proxy
    this.proxy.close();

    // Close all active connections
    for (const socket of this.activeConnections) {
      socket.destroy();
    }

    // Close server
    if (this.server) {
      this.server.close(() => {
        this.logger.info(`${this.serverType} server stopped`);
        process.exit(0);
      });
    }
  }

  reload() {
    this.logger.info('Reloading configuration...');
    this.domainManager.reload();
    if (this.firewall) {
      this.firewall.loadBannedIPs();
    }
  }
}

module.exports = { BaseProxyServer };




