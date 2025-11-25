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
