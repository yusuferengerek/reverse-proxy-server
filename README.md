# Reverse Proxy Server

A simple, componentized HTTP reverse proxy server built with TypeScript and Node.js. This server listens on port 80 and routes incoming HTTP requests to backend services based on domain, subdomain, and path patterns defined in a `services.yml` configuration file.

## Features

- 🚀 Simple and lightweight
- 📋 YAML-based configuration
- 🔧 Componentized architecture
- 🛡️ Error handling and logging
- ⚡ Built with TypeScript for type safety
- 🎯 Domain and subdomain-based routing
- 🔀 Path-based routing within domains
- ↪️ Automatic redirects support
- 🔌 Host+port or URL-based target configuration

## Installation

```bash
# Install dependencies
npm install

# Build the project
npm run build

# Start the server
npm start
```

## Development

```bash
# Run in development mode with ts-node
npm run dev

# Watch mode for development
npm run watch
```

## Configuration

Create a `services.yml` file in the root directory. The configuration supports domain-based routing with subdomains and path patterns.

### Example 1: Basic Domain Routing

```yaml
example.com:
  routes:
    - path: /
      host: localhost
      port: 3000
```

### Example 2: Subdomain Redirect

```yaml
mysite.com:
  routes:
    - redirect: www  # mysite.com -> www.mysite.com
  subdomains:
    www:
      - path: /
        host: localhost
        port: 3000
```

### Example 3: Multiple Subdomains

```yaml
myapp.com:
  routes:
    - redirect: www
  subdomains:
    www:
      - path: /
        host: app-host
        port: 3000
    api:
      - path: /
        host: api-host
        port: 3001
    admin:
      - path: /
        host: admin-host
        port: 3002
    cdn:
      - path: /
        host: cdn-host
        port: 3003
```

### Example 4: Path-based Routing

```yaml
app.io:
  routes:
    - path: /
      host: localhost
      port: 4000
    - path: /api
      host: api-host
      port: 4001
    - path: /admin
      host: admin-host
      port: 4002
```

### Example 5: Subdomain + Path Routing

```yaml
service.com:
  subdomains:
    v1:
      - path: /api
        host: v1-api
        port: 5001
      - path: /auth
        host: v1-auth
        port: 5002
    v2:
      - path: /api
        host: v2-api
        port: 6001
      - path: /auth
        host: v2-auth
        port: 6002
```

### Configuration Options

#### Route Configuration

- **path**: The URL path prefix to match (e.g., `/`, `/api`, `/admin`)
- **host**: Optional target host when using `port` (default: `localhost`)
- **port**: Target port number (creates `http://{host}:{port}` target)
- **target**: Alternative to port - full target server URL (e.g., `http://localhost:3000`)
- **redirect**: Subdomain to redirect to (e.g., `www` redirects to `www.{domain}`)
- **options**: Optional proxy options (see [http-proxy documentation](https://github.com/http-party/node-http-proxy))
  - `changeOrigin`: Change the origin of the host header to the target URL
  - `timeout`: Request timeout in milliseconds

#### Domain Configuration

- **routes**: Array of route configurations for the main domain
- **subdomains**: Object mapping subdomain names to their route configurations

#### Global Configuration

- **port**: Optional server port (default: 80)

## Project Structure

```
reverse-proxy/
├── src/
│   ├── config/
│   │   └── loader.ts          # Configuration loader component
│   ├── proxy/
│   │   └── handler.ts         # Proxy handler component
│   ├── server/
│   │   └── index.ts           # HTTP server component
│   ├── types/
│   │   └── index.ts           # TypeScript type definitions
│   └── index.ts               # Main entry point
├── services.yml               # Service configuration file
├── package.json
├── tsconfig.json
└── README.md
```

## Usage

1. Configure your domains and routes in `services.yml`
2. Start the server: `npm start`
3. Make requests using the configured domains/subdomains

## Examples

### Basic Domain Routing

With this configuration:
```yaml
example.com:
  routes:
    - path: /
      host: localhost
      port: 3000
```

A request to `http://example.com/` will be proxied to `http://localhost:3000/`.

### Subdomain Routing

With this configuration:
```yaml
myapp.com:
  subdomains:
    api:
      - path: /
        host: api-host
        port: 3001
```

A request to `http://api.myapp.com/` will be proxied to `http://api-host:3001/`.

### Path-based Routing

With this configuration:
```yaml
app.io:
  routes:
    - path: /api
      host: api-host
      port: 4001
```

A request to `http://app.io/api/users` will be proxied to `http://api-host:4001/api/users`.

## Requirements

- Node.js 16+
- npm or yarn

## License

MIT
