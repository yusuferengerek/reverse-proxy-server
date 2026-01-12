import { ServerOptions } from 'http-proxy';

/**
 * Route configuration interface
 */
export interface RouteConfig {
  path: string;
  port?: number;
  host?: string;
  target?: string;
  redirect?: string;
  options?: ServerOptions;
}

/**
 * Subdomain configuration interface
 */
export interface SubdomainConfig {
  [subdomain: string]: RouteConfig[];
}

/**
 * Domain configuration interface
 */
export interface DomainConfig {
  routes?: RouteConfig[];
  subdomains?: SubdomainConfig;
}

/**
 * Main configuration interface
 */
export interface Config {
  [domain: string]: DomainConfig | number | undefined;
}

/**
 * Proxy route interface with domain/subdomain context
 */
export interface ProxyRoute {
  domain: string;
  subdomain?: string;
  path: string;
  target: string;
  options: ServerOptions;
  redirect?: string;
}
