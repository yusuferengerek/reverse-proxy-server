const { HttpProxyServer } = require('./Servers/HttpProxyServer');
const { HttpsProxyServer } = require('./Servers/HttpsProxyServer');
const { AdminAPI } = require('./Utils/AdminAPI');
const { getLogger } = require('./Utils/Logger');
const configs = require('./configs.json');

const logger = getLogger();

class ProxyServerManager {
  constructor() {
    this.httpServer = null;
    this.httpsServer = null;
    this.adminAPI = null;
  }

  start() {
    logger.info('Starting Reverse Proxy Server...');

    try {
      // Start HTTP server
      if (configs.http.enabled) {
        this.httpServer = new HttpProxyServer();
        this.httpServer.start();
      }

      // Start HTTPS server
      if (configs.https.enabled) {
        this.httpsServer = new HttpsProxyServer();
        this.httpsServer.start();
      }

      // Start Admin API
      if (configs.admin.enabled) {
        this.adminAPI = new AdminAPI(this.httpServer, this.httpsServer);
        this.adminAPI.start();
      }

      logger.info('All servers started successfully');

    } catch (error) {
      logger.error('Failed to start servers', {
        error: error.message,
        stack: error.stack
      });
      process.exit(1);
    }
  }

  stop() {
    logger.info('Stopping all servers...');
    
    if (this.httpServer) {
      this.httpServer.stop();
    }
    
    if (this.httpsServer) {
      this.httpsServer.stop();
    }
    
    if (this.adminAPI) {
      this.adminAPI.stop();
    }
  }
}

// Start the server
if (require.main === module) {
  const manager = new ProxyServerManager();
  manager.start();

  // Graceful shutdown
  process.on('SIGTERM', () => manager.stop());
  process.on('SIGINT', () => manager.stop());
}

module.exports = { ProxyServerManager };

