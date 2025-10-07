const https = require('https');
const fs = require('fs');
const path = require('path');
const { BaseProxyServer } = require('./BaseProxyServer');
const { getLogger } = require('../Utils/Logger');
const configs = require('../configs.json');

class HttpsProxyServer extends BaseProxyServer {
  constructor() {
    super('https');
    this.port = configs.https.port;
    this.certPath = path.resolve(configs.https.certPath);
    this.certificates = {};
    this.logger = getLogger();
    
    this.loadCertificates();
  }

  loadCertificates() {
    const domains = this.domainManager.getAllDomains();
    
    this.logger.info('Loading SSL certificates...');
    
    for (const domain of domains) {
      const keyPath = path.join(this.certPath, domain, 'privkey.pem');
      const certPath = path.join(this.certPath, domain, 'fullchain.pem');
      
      if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
        try {
          this.certificates[domain] = {
            key: fs.readFileSync(keyPath, 'utf8'),
            cert: fs.readFileSync(certPath, 'utf8')
          };
          this.logger.info(`Certificate loaded for ${domain}`);
        } catch (err) {
          this.logger.error(`Certificate load error for ${domain}`, {
            error: err.message
          });
        }
      } else {
        this.logger.warn(`Certificate not found for ${domain}`, {
          keyPath,
          certPath
        });
      }
    }
  }

  getSNICallback() {
    return (servername, cb) => {
      const cert = this.certificates[servername];
      
      if (cert) {
        const tls = require('tls');
        const secureContext = tls.createSecureContext({
          key: cert.key,
          cert: cert.cert,
          minVersion: configs.https.minTlsVersion || 'TLSv1.2'
        });
        cb(null, secureContext);
        this.logger.debug(`SNI certificate served for ${servername}`);
      } else {
        this.logger.warn(`No certificate found for SNI: ${servername}`);
        cb(new Error(`No certificate found for ${servername}`));
      }
    };
  }

  start() {
    const defaultDomain = this.domainManager.getAllDomains()[0];
    const defaultCert = this.certificates[defaultDomain];

    if (!defaultCert) {
      this.logger.error('No SSL certificates found. Please add certificates to the certs directory');
      console.error('Certificate directory:', this.certPath);
      console.error('Expected structure: <certPath>/<domain>/privkey.pem and fullchain.pem');
      process.exit(1);
    }

    const httpsOptions = {
      key: defaultCert.key,
      cert: defaultCert.cert,
      SNICallback: this.getSNICallback(),
      minVersion: configs.https.minTlsVersion || 'TLSv1.2',
      ciphers: 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256',
      honorCipherOrder: true
    };

    this.server = https.createServer(httpsOptions, (req, res) => {
      this.handleRequest(req, res);
    });

    // Fix EventEmitter memory leak warning
    // High-traffic servers generate many simultaneous socket connections
    // Increase max listeners to prevent warnings during normal operation
    this.server.setMaxListeners(100);

    // WebSocket support for HTTPS
    if (configs.websocket.enabled) {
      this.server.on('upgrade', (req, socket, head) => {
        this.handleWebSocketUpgrade(req, socket, head);
      });
    }

    this.server.listen(this.port, () => {
      this.logger.info(`HTTPS Proxy Server started on port ${this.port}`);
      this.logger.info(`Loaded certificates for: ${Object.keys(this.certificates).join(', ')}`);
    });

    // Graceful shutdown
    process.on('SIGTERM', () => this.stop());
    process.on('SIGINT', () => this.stop());
    process.on('SIGUSR2', () => this.reload());
  }

  reload() {
    this.logger.info('Reloading HTTPS server configuration...');
    super.reload();
    this.certificates = {};
    this.loadCertificates();
  }
}

module.exports = { HttpsProxyServer };
