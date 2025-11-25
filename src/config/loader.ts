import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';
import { Config, DomainConfig, RouteConfig } from '../types';

/**
 * Configuration loader component
 * Handles loading and parsing of services.yml file
 */
export class ConfigLoader {
  private configPath: string;

  constructor(configPath: string = 'services.yml') {
    this.configPath = path.resolve(configPath);
  }

  /**
   * Load and parse the configuration file
   * @returns Parsed configuration object
   * @throws Error if file cannot be read or parsed
   */
  public load(): Config {
    try {
      if (!fs.existsSync(this.configPath)) {
        throw new Error(`Configuration file not found: ${this.configPath}`);
      }

      const fileContent = fs.readFileSync(this.configPath, 'utf8');
      const config = yaml.load(fileContent) as Config;

      if (!config || typeof config !== 'object') {
        throw new Error('Invalid configuration: configuration must be an object');
      }

      // Validate configuration structure
      this.validateConfig(config);

      return config;
    } catch (error) {
      if (error instanceof Error) {
        throw new Error(`Failed to load configuration: ${error.message}`);
      }
      throw new Error('Failed to load configuration: Unknown error');
    }
  }

  /**
   * Validate configuration structure
   * @param config Configuration object
   */
  private validateConfig(config: Config): void {
    for (const [domain, domainConfig] of Object.entries(config)) {
      if (domain === 'port') {
        continue; // port is a special key
      }

      if (!domainConfig || typeof domainConfig !== 'object') {
        throw new Error(`Invalid domain configuration for ${domain}`);
      }

      const domainCfg = domainConfig as DomainConfig;

      // Validate routes
      if (domainCfg.routes) {
        if (!Array.isArray(domainCfg.routes)) {
          throw new Error(`Invalid routes for ${domain}: must be an array`);
        }

        domainCfg.routes.forEach((route: RouteConfig, index: number) => {
          this.validateRoute(route, domain, index);
        });
      }

      // Validate subdomains
      if (domainCfg.subdomains) {
        if (typeof domainCfg.subdomains !== 'object') {
          throw new Error(`Invalid subdomains for ${domain}: must be an object`);
        }

        for (const [subdomain, routes] of Object.entries(domainCfg.subdomains)) {
          if (!Array.isArray(routes)) {
            throw new Error(`Invalid routes for ${domain}.${subdomain}: must be an array`);
          }

          routes.forEach((route: RouteConfig, index: number) => {
            this.validateRoute(route, `${domain}.${subdomain}`, index);
          });
        }
      }

      // Must have either routes or subdomains
      if (!domainCfg.routes && !domainCfg.subdomains) {
        throw new Error(`Domain ${domain} must have either routes or subdomains`);
      }
    }
  }

  /**
   * Validate a route configuration
   * @param route Route configuration
   * @param context Context string for error messages
   * @param index Route index
   */
  private validateRoute(route: RouteConfig, context: string, index: number): void {
    if (!route || typeof route !== 'object') {
      throw new Error(`Invalid route at ${context}[${index}]: must be an object`);
    }

    // Route must have either redirect, or path with port/target
    if (route.redirect) {
      if (typeof route.redirect !== 'string') {
        throw new Error(`Invalid redirect at ${context}[${index}]: must be a string`);
      }
    } else {
      if (!route.path || typeof route.path !== 'string') {
        throw new Error(`Invalid route at ${context}[${index}]: path is required`);
      }

      if (!route.port && !route.target) {
        throw new Error(
          `Invalid route at ${context}[${index}]: either port or target is required`
        );
      }
    }
  }

  /**
   * Get the port from configuration or use default
   * @param config Configuration object
   * @returns Port number
   */
  public getPort(config: Config): number {
    return (config.port as number) || 80;
  }
}
