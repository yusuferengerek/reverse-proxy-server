const http = require('http');
const { BaseProxyServer } = require('./BaseProxyServer');
const { getLogger } = require('../Utils/Logger');
const configs = require('../configs.json');

class HttpProxyServer extends BaseProxyServer {
  constructor() {
    super('http');
    this.port = configs.http.port;
    this.logger = getLogger();
  }

  start() {
    this.server = http.createServer((req, res) => {
      // HTTP to HTTPS redirect
      if (configs.https.enabled && configs.https.forceHttps) {
        const host = req.headers.host;
        const redirectUrl = `https://${host}${req.url}`;
        res.writeHead(301, { 
          'Location': redirectUrl,
          'X-Redirect-Reason': 'Force HTTPS'
        });
        res.end();
        this.logger.info('HTTP to HTTPS redirect', { 
          host, 
          url: req.url,
          ip: this.logger.getClientIP(req)
        });
        return;
      }

      this.handleRequest(req, res);
    });

    // Fix EventEmitter memory leak warning
    // High-traffic servers generate many simultaneous socket connections
    // Increase max listeners to prevent warnings during normal operation
    this.server.setMaxListeners(100);

    // WebSocket support
    if (configs.websocket.enabled) {
      this.server.on('upgrade', (req, socket, head) => {
        this.handleWebSocketUpgrade(req, socket, head);
      });
    }

    this.server.listen(this.port, () => {
      this.logger.info(`HTTP Proxy Server started on port ${this.port}`);
    });

    // Graceful shutdown
    process.on('SIGTERM', () => this.stop());
    process.on('SIGINT', () => this.stop());
    process.on('SIGUSR2', () => this.reload());
  }
}

module.exports = { HttpProxyServer };
