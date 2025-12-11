import * as http from 'http';
import httpProxy from 'http-proxy';
import { ProxyRoute } from '../types';

/**
 * Proxy handler component
 * Manages HTTP proxy instances and routing logic
 */
export class ProxyHandler {
  private proxy: httpProxy;
  private routes: Map<string, ProxyRoute[]>;
  private redirects: Map<string, string>;

  constructor() {
    this.proxy = httpProxy.createProxyServer();
    this.routes = new Map();
    this.redirects = new Map();
    this.setupErrorHandling();
  }

  /**
   * Register a proxy route
   * @param route Proxy route configuration
   */
  public registerRoute(route: ProxyRoute): void {
    const key = this.getRouteKey(route.domain, route.subdomain);
    
    if (!this.routes.has(key)) {
      this.routes.set(key, []);
    }
    
    this.routes.get(key)!.push(route);

    // Register redirect if present
    if (route.redirect) {
      this.redirects.set(key, route.redirect);
    }
  }

  /**
   * Register multiple proxy routes
   * @param routes Array of proxy route configurations
   */
  public registerRoutes(routes: ProxyRoute[]): void {
    routes.forEach((route) => this.registerRoute(route));
  }

  /**
   * Handle incoming HTTP request
   * @param req HTTP request
   * @param res HTTP response
   */
  public handleRequest(req: http.IncomingMessage, res: http.ServerResponse): void {
    const host = req.headers.host || '';
    const url = req.url || '/';

    // Parse host to extract domain and subdomain
    const { domain, subdomain } = this.parseHost(host);

    if (!domain) {
      this.sendNotFound(res);
      return;
    }

    // Check for redirect
    const routeKey = this.getRouteKey(domain, subdomain);
    const redirect = this.redirects.get(routeKey);
    
    if (redirect) {
      this.handleRedirect(req, res, domain, redirect);
      return;
    }

    // Find matching route
    const route = this.findMatchingRoute(domain, subdomain, url);

    if (!route) {
      this.sendNotFound(res);
      return;
    }

    // Store basePath for response rewriting
    const basePath = route.path;
    
    // Setup response interceptor to rewrite URLs in response headers
    this.setupResponseInterceptor(res, basePath);

    // If basePath is not '/', rewrite the request URL to remove basePath before proxying
    if (basePath !== '/' && req.url) {
      // Remove basePath from the beginning of the URL
      if (req.url.startsWith(basePath)) {
        req.url = req.url.substring(basePath.length) || '/';
      }
    }

    // Proxy the request
    this.proxy.web(req, res, {
      target: route.target,
      ...route.options,
    });
  }

  /**
   * Parse host header to extract domain and subdomain
   * @param host Host header value
   * @returns Object with domain and subdomain
   */
  private parseHost(host: string): { domain: string | null; subdomain: string | null } {
    // Remove port if present
    const hostWithoutPort = host.split(':')[0].toLowerCase();

    const parts = hostWithoutPort.split('.');
    
    if (parts.length < 2) {
      return { domain: null, subdomain: null };
    }

    // For domains like example.com, www.example.com, api.example.com
    if (parts.length === 2) {
      // example.com
      return { domain: hostWithoutPort, subdomain: null };
    } else if (parts.length >= 3) {
      // www.example.com, api.example.com
      const subdomain = parts[0];
      const domain = parts.slice(1).join('.');
      return { domain, subdomain };
    }

    return { domain: null, subdomain: null };
  }

  /**
   * Get route key for domain/subdomain combination
   * @param domain Domain name
   * @param subdomain Subdomain name (optional)
   * @returns Route key
   */
  private getRouteKey(domain: string, subdomain?: string | null): string {
    if (subdomain) {
      return `${subdomain}.${domain}`;
    }
    return domain;
  }

  /**
   * Handle redirect
   * @param req HTTP request
   * @param res HTTP response
   * @param domain Domain name
   * @param redirectTarget Redirect target subdomain
   */
  private handleRedirect(
    req: http.IncomingMessage,
    res: http.ServerResponse,
    domain: string,
    redirectTarget: string
  ): void {
    const protocol = req.headers['x-forwarded-proto'] || 'http';
    const redirectUrl = `${protocol}://${redirectTarget}.${domain}${req.url}`;
    
    res.writeHead(301, { Location: redirectUrl });
    res.end();
  }

  /**
   * Find matching route for the given domain, subdomain, and URL path
   * @param domain Domain name
   * @param subdomain Subdomain name (optional)
   * @param url Request URL path
   * @returns Matching route or null
   */
  private findMatchingRoute(
    domain: string,
    subdomain: string | null,
    url: string
  ): ProxyRoute | null {
    const routeKey = this.getRouteKey(domain, subdomain);
    const domainRoutes = this.routes.get(routeKey) || this.routes.get(domain) || [];

    if (domainRoutes.length === 0) {
      return null;
    }

    // Sort routes by path length (longest first) for more specific matching
    const sortedRoutes = [...domainRoutes].sort(
      (a, b) => b.path.length - a.path.length
    );

    for (const route of sortedRoutes) {
      if (url.startsWith(route.path)) {
        return route;
      }
    }

    return null;
  }

  /**
   * Send 404 Not Found response
   * @param res HTTP response
   */
  private sendNotFound(res: http.ServerResponse): void {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('404 Not Found - No matching service route');
  }

  /**
   * Setup error handling for proxy
   */
  private setupErrorHandling(): void {
    this.proxy.on('error', (err, req, res) => {
      console.error('Proxy error:', err.message);

      // Check if res is a ServerResponse (not a Socket)
      if (res instanceof http.ServerResponse && !res.headersSent) {
        res.writeHead(502, { 'Content-Type': 'text/plain' });
        res.end('502 Bad Gateway - Proxy error occurred');
      }
    });
  }

  /**
   * Setup response interceptor to rewrite URLs in response headers
   * This adds basePath prefix to URLs in Location, Link, and other headers
   * @param res HTTP response
   * @param basePath Base path to prepend to URLs
   */
  private setupResponseInterceptor(res: http.ServerResponse, basePath: string): void {
    if (basePath === '/') {
      return; // No rewriting needed for root path
    }

    const originalWriteHead = res.writeHead.bind(res);
    const originalSetHeader = res.setHeader.bind(res);
    const self = this;

    // Intercept writeHead to rewrite Location header
    res.writeHead = function (statusCode: number, statusMessage?: any, headers?: any): http.ServerResponse {
      const mergedHeaders = self.mergeHeaders(statusMessage, headers);
      self.rewriteHeaders(mergedHeaders, basePath);
      return originalWriteHead(statusCode, mergedHeaders);
    } as typeof res.writeHead;

    // Intercept setHeader to rewrite headers as they are set
    res.setHeader = function (name: string, value: string | number | string[]): http.ServerResponse {
      const headerName = name.toLowerCase();
      if (self.shouldRewriteHeader(headerName)) {
        value = self.rewriteHeaderValue(value, basePath);
      }
      return originalSetHeader(name, value);
    } as typeof res.setHeader;
  }

  /**
   * Merge headers from writeHead parameters
   * @param statusMessage Status message or headers object
   * @param headers Headers object
   * @returns Merged headers object
   */
  private mergeHeaders(
    statusMessage?: string | http.OutgoingHttpHeaders,
    headers?: http.OutgoingHttpHeaders
  ): http.OutgoingHttpHeaders {
    if (typeof statusMessage === 'object' && statusMessage !== null) {
      return { ...statusMessage, ...headers };
    }
    return headers || {};
  }

  /**
   * Rewrite headers to add basePath prefix to URLs
   * @param headers Headers object
   * @param basePath Base path to prepend
   */
  private rewriteHeaders(headers: http.OutgoingHttpHeaders, basePath: string): void {
    for (const [key, value] of Object.entries(headers)) {
      const headerName = key.toLowerCase();
      if (this.shouldRewriteHeader(headerName) && value != null) {
        if (typeof value === 'string' || typeof value === 'number' || Array.isArray(value)) {
          headers[key] = this.rewriteHeaderValue(value, basePath);
        }
      }
    }
  }

  /**
   * Check if a header should be rewritten
   * @param headerName Header name (lowercase)
   * @returns True if header should be rewritten
   */
  private shouldRewriteHeader(headerName: string): boolean {
    return ['location', 'link', 'content-location'].includes(headerName);
  }

  /**
   * Rewrite header value to add basePath prefix to URLs
   * @param value Header value (string, number, or array)
   * @param basePath Base path to prepend
   * @returns Rewritten header value
   */
  private rewriteHeaderValue(value: string | number | string[], basePath: string): string | number | string[] {
    if (typeof value === 'number') {
      return value;
    }

    if (Array.isArray(value)) {
      return value.map((v) => this.rewriteUrl(v, basePath));
    }

    return this.rewriteUrl(value, basePath);
  }

  /**
   * Rewrite a URL to add basePath prefix
   * @param url URL to rewrite
   * @param basePath Base path to prepend
   * @returns Rewritten URL
   */
  private rewriteUrl(url: string, basePath: string): string {
    // Skip if URL is absolute (starts with http:// or https://)
    if (/^https?:\/\//i.test(url)) {
      // Check if it's a relative path within the same domain
      try {
        const urlObj = new URL(url);
        // If it's a path-only URL (no domain), rewrite it
        if (urlObj.pathname && !urlObj.hostname) {
          return basePath + urlObj.pathname + (urlObj.search || '') + (urlObj.hash || '');
        }
      } catch {
        // Invalid URL, try to rewrite as relative path
      }
      return url;
    }

    // Skip if URL starts with // (protocol-relative)
    if (url.startsWith('//')) {
      return url;
    }

    // Skip if URL starts with # (fragment only)
    if (url.startsWith('#')) {
      return url;
    }

    // Skip if URL starts with ? (query only)
    if (url.startsWith('?')) {
      return url;
    }

    // For relative URLs, add basePath prefix
    // Remove leading slash if present to avoid double slashes
    const cleanUrl = url.startsWith('/') ? url : '/' + url;
    
    // Ensure basePath ends with / for proper joining
    const normalizedBasePath = basePath.endsWith('/') ? basePath.slice(0, -1) : basePath;
    
    return normalizedBasePath + cleanUrl;
  }

  /**
   * Get all registered routes
   * @returns Array of registered routes
   */
  public getRoutes(): ProxyRoute[] {
    const allRoutes: ProxyRoute[] = [];
    for (const routes of this.routes.values()) {
      allRoutes.push(...routes);
    }
    return allRoutes;
  }
}
