# Reverse Proxy Server

Modern, secure, and scalable reverse proxy server with HTTP/HTTPS support, integrated firewall, WebSocket support, and comprehensive management features.

## 🚀 Features

### Core Features
- ✅ **HTTP & HTTPS Support** - Multi-domain SSL/TLS certificates (SNI)
- ✅ **Reverse Proxy** - Backend server routing
- ✅ **Domain & Subdomain Routing** - Flexible routing configuration
- ✅ **WebSocket Support** - WS/WSS protocol support
- ✅ **HTTP to HTTPS Redirect** - Automatic HTTPS redirection

### Security (Enterprise Level)
- 🛡️ **Integrated Firewall**
  - IP banning system
  - Rate limiting
  - Suspicious content detection
  - Body/file size control
  - DDoS protection
- 🔒 **Security Headers**
  - HSTS
  - CSP (Content Security Policy)
  - X-Frame-Options
  - X-Content-Type-Options
  - XSS Protection
- 🌐 **CORS Support**
- 🔐 **TLS 1.2+ Enforcement**
- 🚀 **Advanced Security Layer**
  - Directory Traversal Protection
  - SQL Injection Detection
  - NoSQL Injection Detection
  - XSS Prevention
  - Command Injection Protection
  - SSTI (Server-Side Template Injection) Detection
  - SSRF (Server-Side Request Forgery) Prevention
  - Scanning & Enumeration Detection
  - Brute Force Protection (human-friendly thresholds)
  - **Bot Detection** (superhuman speed detection)
  - Information Gathering Detection
  - CSRF Protection
  - File Upload Validation
  - IDOR Protection
  - **Behavioral Analysis** (user experience preserved)

### Management & Monitoring
- 📊 **Admin API** - RESTful management API
- 📝 **Advanced Logging** - Winston-based logging with rotation
- 💓 **Health Check** - Server health monitoring
- 🔄 **Hot Reload** - Configuration reload without downtime
- 📈 **Metrics** - Statistics and metrics

### DevOps
- ⚙️ **PM2 Integration** - Process management
- 🐳 **Docker Ready** - Containerization support (coming soon)
- 📦 **Easy Setup** - One-command installation via NPM

## 📋 Requirements

- Node.js >= 14.0.0
- npm >= 6.0.0

## 🔧 Installation

```bash
# Clone the repository
git clone <repository-url>
cd reverse-proxy-server

# Install dependencies
npm install

# Create configuration file
cp .env.example .env

# Add your SSL certificates (for HTTPS)
# Structure: src/Certs/<domain>/privkey.pem and fullchain.pem
```

## ⚙️ Configuration

### 1. Domain Configuration (`domains` file)

```yaml
example.com:
  routes: [
    { redirect: www }  # example.com -> www.example.com
  ]
  subdomains: {
    www: [
      { path: /, port: 3000 }
    ],
    api: [
      { path: /, port: 3001 }
    ],
    admin: [
      { path: /, port: 3002 }
    ]
  }

another-domain.com:
  routes: [
    { path: /, port: 4000 }
  ]
```

### 2. Main Configuration (`src/configs.json`)

See `src/configs.json` file for detailed configuration options:

- HTTP/HTTPS ports
- Firewall settings
- Security headers
- Logging level
- Admin API settings
- Timeout values

### 3. SSL Certificates

Place your SSL certificates in the following directory structure:

```
src/Certs/
├── example.com/
│   ├── privkey.pem
│   └── fullchain.pem
└── another-domain.com/
    ├── privkey.pem
    └── fullchain.pem
```

**Creating certificates with Let's Encrypt:**

```bash
certbot certonly --standalone -d example.com -d www.example.com
# Certificates will be in: /etc/letsencrypt/live/example.com/
```

## 🚀 Usage

### Direct Node.js

```bash
# Development
npm run dev

# Production
npm start
```

### With PM2 (Recommended)

```bash
# Start
npm run pm2:start

# Stop
npm run pm2:stop

# Restart
npm run pm2:restart

# Hot reload (no downtime)
npm run pm2:reload

# View logs
npm run pm2:logs

# Monitoring
npm run pm2:monit
```

## 📡 Admin API

Admin API runs on port `9090` by default.

### Authentication

All requests require the `Authorization` header:

```bash
Authorization: Bearer your-secret-token
```

### Endpoints

#### 1. Server Status
```bash
GET /api/status
```

**Response:**
```json
{
  "status": "running",
  "timestamp": "2024-01-01T12:00:00.000Z",
  "uptime": 3600,
  "memory": { ... },
  "servers": {
    "http": { "enabled": true, "port": 80 },
    "https": { "enabled": true, "port": 443 }
  }
}
```

#### 2. Statistics
```bash
GET /api/stats
```

#### 3. Banned IPs
```bash
GET /api/firewall/banned-ips
```

#### 4. Ban IP
```bash
POST /api/firewall/ban
Content-Type: application/json

{
  "ip": "192.168.1.100",
  "reason": "Suspicious activity"
}
```

#### 5. Unban IP
```bash
POST /api/firewall/unban
Content-Type: application/json

{
  "ip": "192.168.1.100"
}
```

#### 6. Reload Configuration
```bash
POST /api/reload
```

#### 7. Domain List
```bash
GET /api/domains
```

#### 8. Security Statistics (NEW)
```bash
GET /api/security/stats
```

**Response:**
```json
{
  "trackedIPs": 150,
  "activeLoginAttempts": 5,
  "securityFeatures": {
    "sqlInjection": "enabled",
    "xss": "enabled",
    "commandInjection": "enabled",
    "botDetection": "enabled"
  }
}
```

#### 9. Recent Threats (NEW)
```bash
GET /api/security/threats
```

**Response:**
```json
{
  "totalThreats": 15,
  "threats": [
    {
      "ip": "192.168.1.100",
      "threats": [{"type": "sql_injection", "severity": "critical"}],
      "scanScore": 85,
      "isBot": true
    }
  ]
}
```

#### 10. Clear IP Behavior (NEW)
```bash
POST /api/security/clear-behavior
Content-Type: application/json

{
  "ip": "192.168.1.100"
}
```

### Usage Examples

```bash
# Check server status
curl -H "Authorization: Bearer change-this-secret-token" \
  http://localhost:9090/api/status

# Ban an IP
curl -X POST \
  -H "Authorization: Bearer change-this-secret-token" \
  -H "Content-Type: application/json" \
  -d '{"ip":"192.168.1.100","reason":"Brute force attack"}' \
  http://localhost:9090/api/firewall/ban

# Reload configuration
curl -X POST \
  -H "Authorization: Bearer change-this-secret-token" \
  http://localhost:9090/api/reload
```

## 🛡️ Enterprise Security

### Advanced Security Layer

This reverse proxy is protected by **13 different security layers**:

1. **Directory Traversal Protection** - Path traversal prevention
2. **SQL Injection Detection** - All SQL injection variants
3. **NoSQL Injection Detection** - MongoDB injection protection
4. **XSS Prevention** - Cross-Site Scripting prevention
5. **Command Injection Protection** - OS command injection detection
6. **SSTI Detection** - Template injection protection
7. **SSRF Prevention** - Internal network access blocking
8. **Scanning Detection** - Directory/subdomain enumeration detection
9. **Brute Force Protection** - Login attack protection
10. **Bot Detection** - Superhuman speed detection
11. **Information Gathering Detection** - Information collection detection
12. **CSRF Protection** - Cross-Site Request Forgery protection
13. **File Upload Validation** - Secure file upload

### 🎯 User Experience Focused

**Important:** The security system **does not compromise user experience**:

✅ **Allowed:**
- Fast page transitions (normal users)
- Multiple tab usage
- Legitimate API requests
- Fast website navigation

❌ **Blocked:**
- Superhuman speeds (<50ms between requests)
- Automated scanning
- Bot traffic
- Injection attempts

### Threat Scoring System

```
Critical (100+)  → Automatic ban
High (70-99)     → Request blocked, multiple violations = ban
Medium (40-69)   → Logged and tracked  
Low (<40)        → Monitored
```

**For detailed security documentation:** [SECURITY.md](SECURITY.md)

## 📊 Logging

Logs are stored in the `logs/` directory:

- `combined-YYYY-MM-DD.log` - All logs
- `error-YYYY-MM-DD.log` - Errors only
- `access-YYYY-MM-DD.log` - Access logs
- `exceptions-YYYY-MM-DD.log` - Unhandled exceptions
- `rejections-YYYY-MM-DD.log` - Unhandled promise rejections

### Log Levels

- `error` - Errors only
- `warn` - Warnings and errors
- `info` - Information, warnings and errors (default)
- `debug` - Detailed debug information

Configuration: `src/configs.json` > `logging.level`

## 🔍 Health Check

Health check endpoint: `http://your-domain/health`

```json
{
  "status": "ok",
  "timestamp": "2024-01-01T12:00:00.000Z",
  "uptime": 3600,
  "type": "http",
  "connections": 42,
  "memory": { ... },
  "domains": 3,
  "firewall": {
    "bannedIPs": 5,
    "activeIPs": 150,
    "suspiciousIPs": 3
  }
}
```

## 🔄 Hot Reload

To reload configuration changes:

```bash
# With PM2
pm2 reload reverse-proxy

# Or send SIGUSR2 signal
kill -SIGUSR2 <process-id>

# Or via Admin API
curl -X POST -H "Authorization: Bearer token" \
  http://localhost:9090/api/reload
```

## 📁 Project Structure

```
reverse-proxy-server/
├── src/
│   ├── Servers/              # Proxy servers
│   │   ├── BaseProxyServer.js
│   │   ├── HttpProxyServer.js
│   │   └── HttpsProxyServer.js
│   ├── Utils/                # Utility modules
│   │   ├── DomainManager.js
│   │   ├── Firewall.js
│   │   ├── Logger.js
│   │   ├── AdminAPI.js
│   │   └── AdvancedSecurity.js    ✨ NEW - Enterprise Security
│   ├── Certs/                # SSL certificates
│   ├── Data/                 # Data files
│   │   └── banned-ips.json
│   ├── configs.json          # Main configuration
│   └── index.js              # Entry point
├── domains                   # Domain routing configuration
├── domains.example           # Domain config examples
├── logs/                     # Log files
├── ecosystem.config.js       # PM2 configuration
├── package.json
├── README.md
├── SECURITY.md               ✨ NEW - Security documentation
└── CONTRIBUTING.md
```

## 🔒 Security

### Recommendations

1. **Change Admin API Token**
   ```json
   "admin": {
     "token": "use-a-strong-random-token"
   }
   ```

2. **Use Admin API IP Whitelist**
   ```json
   "admin": {
     "allowedIPs": ["127.0.0.1", "192.168.1.100"]
   }
   ```

3. **Enforce HTTPS**
   ```json
   "https": {
     "forceHttps": true
   }
   ```

4. **Enable Firewall**
   ```json
   "firewall": {
     "enabled": true
   }
   ```

5. **Set appropriate log level in production** (`info` or `warn`)

## 🐛 Troubleshooting

### Port Already in Use

```bash
# Find the process using the port
lsof -i :80
# or
netstat -tulpn | grep :80

# Stop the process
kill -9 <PID>
```

### SSL Certificate Error

- Ensure certificate files are in the correct directory
- Check file permissions: `chmod 600 *.pem`
- Verify certificate format (PEM format required)

### Check Logs

```bash
# PM2 logs
pm2 logs reverse-proxy

# Or check log files directly
tail -f logs/error-*.log
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

MIT License - see [LICENSE](LICENSE) file for details.

## 📚 Documentation

- **[README.md](README.md)** - Main documentation (this file)
- **[SECURITY.md](SECURITY.md)** - Detailed security features and threat detection
- **[CONTRIBUTING.md](CONTRIBUTING.md)** - Contribution guidelines

## 🙏 Acknowledgments

- [http-proxy](https://github.com/http-party/node-http-proxy) - Proxy infrastructure
- [winston](https://github.com/winstonjs/winston) - Logging
- [PM2](https://pm2.keymetrics.io/) - Process management

## 📞 Support

For questions or issues:
- Open an issue: [GitHub Issues]
- Security vulnerabilities: Please see [SECURITY.md](SECURITY.md)
- Documentation: This README and other .md files

---

## ⭐ Features Summary

✅ HTTP/HTTPS Reverse Proxy  
✅ Multi-domain SSL/TLS (SNI)  
✅ WebSocket Support  
✅ **13-Layer Enterprise Security**  
✅ Bot Detection (superhuman speed detection)  
✅ Behavioral Analysis  
✅ Admin API (RESTful)  
✅ Advanced Logging  
✅ PM2 Ready  
✅ Production Ready  
✅ **Zero Compromise Security with Preserved UX**  

---

**Note:** This project is production-ready and equipped with enterprise-level security features.
