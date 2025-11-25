import * as http from 'http';
import { ProxyHandler } from '../proxy/handler';
import { Config, DomainConfig, RouteConfig, ProxyRoute } from '../types';

/**
 * HTTP Server component
 * Manages the HTTP server instance and request handling
 */
export class HttpServer {
  private server: http.Server;
  private proxyHandler: ProxyHandler;
  private port: number;

  constructor(port: number, proxyHandler: ProxyHandler) {
    this.port = port;
    this.proxyHandler = proxyHandler;
    this.server = http.createServer((req, res) => {
      this.handleRequest(req, res);
    });
  }

  /**
   * Start the HTTP server
   */
  public start(): void {
    this.server.listen(this.port, () => {
      console.log(`🚀 Reverse Proxy Server running on port ${this.port}`);
      console.log(`📋 Registered routes:`);
      const routes = this.proxyHandler.getRoutes();
      routes.forEach((route) => {
        const domainInfo = route.subdomain
          ? `${route.subdomain}.${route.domain}`
          : route.domain;
        console.log(`   ${domainInfo}${route.path} -> ${route.target}`);
      });
    });

    this.server.on('error', (err: NodeJS.ErrnoException) => {
      if (err.code === 'EADDRINUSE') {
        console.error(`❌ Port ${this.port} is already in use`);
      } else {
        console.error('❌ Server error:', err.message);
      }
      process.exit(1);
    });
  }

  /**
   * Stop the HTTP server
   */
  public stop(): Promise<void> {
    return new Promise<void>((resolve) => {
      this.server.close(() => {
        console.log('🛑 Server stopped');
        resolve();
      });
    });
  }

  /**
   * Handle incoming HTTP request
   * @param req HTTP request
   * @param res HTTP response
   */
  private handleRequest(req: http.IncomingMessage, res: http.ServerResponse): void {
    // Log request
    const timestamp = new Date().toISOString();
    const host = req.headers.host || 'unknown';
    console.log(`[${timestamp}] ${req.method} ${host}${req.url}`);

    // Handle request through proxy
    this.proxyHandler.handleRequest(req, res);
  }

  /**
   * Convert configuration to proxy routes
   * @param config Configuration object
   * @returns Array of proxy routes
   */
  public static createRoutesFromConfig(config: Config): ProxyRoute[] {
    const routes: ProxyRoute[] = [];

    for (const [domain, domainConfig] of Object.entries(config)) {
      if (domain === 'port') {
        continue; // Skip port key
      }

      const domainCfg = domainConfig as DomainConfig;

      // Process main domain routes
      if (domainCfg.routes) {
        domainCfg.routes.forEach((route: RouteConfig) => {
          const proxyRoute = this.createProxyRoute(domain, undefined, route);
          if (proxyRoute) {
            routes.push(proxyRoute);
          }
        });
      }

      // Process subdomain routes
      if (domainCfg.subdomains) {
        for (const [subdomain, subdomainRoutes] of Object.entries(domainCfg.subdomains)) {
          subdomainRoutes.forEach((route: RouteConfig) => {
            const proxyRoute = this.createProxyRoute(domain, subdomain, route);
            if (proxyRoute) {
              routes.push(proxyRoute);
            }
          });
        }
      }
    }

    return routes;
  }

  /**
   * Create a proxy route from route configuration
   * @param domain Domain name
   * @param subdomain Subdomain name (optional)
   * @param route Route configuration
   * @returns Proxy route or null if redirect
   */
  private static createProxyRoute(
    domain: string,
    subdomain: string | undefined,
    route: RouteConfig
  ): ProxyRoute | null {
    // Handle redirect
    if (route.redirect) {
      return {
        domain,
        subdomain,
        path: '/',
        target: '', // Not used for redirects
        options: {},
        redirect: route.redirect,
      };
    }

    // Determine target URL
    let target: string;
    if (route.target) {
      target = route.target;
    } else if (route.port) {
      target = `http://localhost:${route.port}`;
    } else {
      throw new Error(`Route must have either target or port: ${JSON.stringify(route)}`);
    }

    return {
      domain,
      subdomain,
      path: route.path,
      target,
      options: route.options || {},
    };
  }
}
