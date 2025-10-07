# Contributing Guidelines

Thank you for considering contributing to this project! 🎉

## 🚀 Getting Started

1. **Fork the Repository**
   - Click the "Fork" button in the top-right corner of the project on GitHub

2. **Clone Your Fork**
   ```bash
   git clone https://github.com/YOUR-USERNAME/reverse-proxy-server.git
   cd reverse-proxy-server
   ```

3. **Install Dependencies**
   ```bash
   npm install
   ```

4. **Create a Branch**
   ```bash
   git checkout -b feature/my-new-feature
   ```

## 💻 Development

### Code Standards

- Use **JavaScript Standard Style**
- Use **meaningful variable names**
- Add **comments** (especially for complex logic)
- **Don't use console.log** - Use Logger instead

### Code Examples

```javascript
// ✅ Good
const { getLogger } = require('../Utils/Logger');
const logger = getLogger();

logger.info('User logged in', { userId: 123 });

// ❌ Bad
console.log('User logged in');
```

### File Structure

When adding new files:
- **Servers:** HTTP/HTTPS server implementations
- **Utils:** Helper classes and utilities
- Each file should follow the single responsibility principle

## 🧪 Testing

```bash
npm test
```

Write tests for new features!

## 📝 Commit Messages

Write meaningful commit messages:

```bash
✨ feat: Add new feature
🐛 fix: Bug fix
📚 docs: Documentation update
🔄 refactor: Code refactoring
⚡ perf: Performance improvement
🎨 style: Code formatting
✅ test: Add/update tests
```

## 🔍 Pull Request Process

1. **Commit Your Changes**
   ```bash
   git add .
   git commit -m "✨ feat: Amazing new feature"
   ```

2. **Push to Your Fork**
   ```bash
   git push origin feature/my-new-feature
   ```

3. **Create Pull Request**
   - Go to your repository on GitHub
   - Click "New Pull Request"
   - Describe your changes
   - Add screenshots (for UI changes)

4. **Wait for Review**
   - Maintainers will review your code
   - They may request changes
   - Once approved, it will be merged

## 🐛 Bug Reporting

When you find a bug:

1. **Open an Issue**
2. **Provide detailed description:**
   - What did you expect to happen?
   - What actually happened?
   - How to reproduce?
   - System information (OS, Node version)
   - Log output

**Example Bug Report:**

```markdown
**Expected Behavior:**
HTTPS server should start

**Actual Behavior:**
"Certificate not found" error

**Reproduction Steps:**
1. Enable HTTPS without certificates
2. Run npm start

**System:**
- OS: Ubuntu 22.04
- Node: 18.0.0

**Logs:**
```
[error] No SSL certificates found...
```
```

## 💡 Feature Requests

To suggest a new feature:

1. **Open an Issue**
2. **Add "Feature Request" label**
3. **Explain details:**
   - What problem does it solve?
   - How should it work?
   - Have you considered alternatives?
   - Examples

## ❓ Questions

For questions:
- Use GitHub Discussions
- Open an issue (with Question label)

## 📜 License

Your contributions will be published under the MIT license.

---

Thank you again! 🙏
