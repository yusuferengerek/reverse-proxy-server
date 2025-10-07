const fs = require('fs');
const path = require('path');
const configs = require('../configs.json');

class DomainManager {
  constructor() {
    this.configPath = path.resolve(configs.domains.configPath);
    this.domains = {};
    this.loadConfig();
  }

  loadConfig() {
    try {
      const configContent = fs.readFileSync(this.configPath, 'utf-8');
      this.parseConfig(configContent);
    } catch (error) {
      console.error(`Failed to load config: ${this.configPath} - ${error.message}`);
      throw error;
    }
  }

  parseConfig(content) {
    const lines = content.split('\n');
    let currentDomain = null;
    let currentSection = null;
    let currentSubdomain = null;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();

      if (!trimmed || trimmed.startsWith('#')) continue;

      if (trimmed.match(/^[\w.-]+:\s*$/)) {
        currentDomain = trimmed.slice(0, -1);
        this.domains[currentDomain] = {
          routes: [],
          subdomains: {}
        };
        currentSection = null;
        currentSubdomain = null;
        continue;
      }

      if (trimmed.startsWith('routes:')) {
        currentSection = 'routes';
        currentSubdomain = null;
        continue;
      }

      if (trimmed.startsWith('subdomains:')) {
        currentSection = 'subdomains';
        currentSubdomain = null;
        continue;
      }

      if (currentSection === 'subdomains' && trimmed.match(/^[\w-]+:\s*\[?\s*$/)) {
        currentSubdomain = trimmed.replace(/:\s*\[?\s*$/, '');
        if (!this.domains[currentDomain].subdomains[currentSubdomain]) {
          this.domains[currentDomain].subdomains[currentSubdomain] = [];
        }
        continue;
      }

      if (trimmed.startsWith('{')) {
        const obj = this.parseObject(trimmed);
        
        if (currentSection === 'routes') {
          this.domains[currentDomain].routes.push(obj);
        } else if (currentSection === 'subdomains' && currentSubdomain) {
          this.domains[currentDomain].subdomains[currentSubdomain].push(obj);
        }
      }
    }
  }

  parseObject(str) {
    const obj = {};
    const content = str.replace(/^\{\s*/, '').replace(/\s*\}.*$/, '');
    const pairs = content.split(',').map(s => s.trim());
    
    for (const pair of pairs) {
      const colonIndex = pair.indexOf(':');
      if (colonIndex === -1) continue;
      
      const key = pair.substring(0, colonIndex).trim();
      let value = pair.substring(colonIndex + 1).trim();
      
      if (value.startsWith("'") || value.startsWith('"')) {
        value = value.slice(1, -1);
      } else if (!isNaN(value)) {
        value = parseInt(value);
      }
      
      obj[key] = value;
    }
    
    return obj;
  }

  getDomain(domain) {
    return this.domains[domain] || null;
  }

  getSubdomain(domain, subdomain) {
    const domainConfig = this.getDomain(domain);
    if (!domainConfig) return null;
    return domainConfig.subdomains[subdomain] || null;
  }

  getAllDomains() {
    return Object.keys(this.domains);
  }

  reload() {
    this.domains = {};
    this.loadConfig();
  }
}

module.exports = { DomainManager };