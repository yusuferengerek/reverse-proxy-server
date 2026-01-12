import { ConfigLoader } from './config/loader';
import { ProxyHandler } from './proxy/handler';
import { HttpServer } from './server/index';

/**
 * Main application entry point
 */
class ReverseProxyApp {
  private configLoader: ConfigLoader;
  private proxyHandler: ProxyHandler;
  private server: HttpServer | null = null;

  constructor() {
    this.configLoader = new ConfigLoader();
    this.proxyHandler = new ProxyHandler();
  }

  /**
   * Initialize and start the reverse proxy server
   */
  public async start(): Promise<void> {
    try {
      // Load configuration
      console.log('📖 Loading configuration...');
      const config = this.configLoader.load();
      const port = this.configLoader.getPort(config);

      // Setup proxy routes
      console.log('🔧 Setting up proxy routes...');
      const routes = HttpServer.createRoutesFromConfig(config);
      this.proxyHandler.registerRoutes(routes);

      // Create and start server
      this.server = new HttpServer(port, this.proxyHandler);
      this.server.start();

      // Handle graceful shutdown
      this.setupGracefulShutdown();
    } catch (error) {
      console.error('❌ Failed to start server:', error instanceof Error ? error.message : error);
      process.exit(1);
    }
  }

  /**
   * Setup graceful shutdown handlers
   */
  private setupGracefulShutdown(): void {
    const shutdown = async (signal: string) => {
      console.log(`\n${signal} received, shutting down gracefully...`);
      if (this.server) {
        await this.server.stop();
      }
      process.exit(0);
    };

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
  }
}

// Start the application
const app = new ReverseProxyApp();
app.start();

