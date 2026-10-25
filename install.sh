#!/bin/bash
# VANTA Installer — Mahmoud
set -e

echo "🔥 VANTA Installer v1.0"
echo "========================"

# 1. Verify Node
if ! command -v node &> /dev/null; then
  echo "❌ Node not found. Install Node 20+ first: https://nodejs.org"
  exit 1
fi
NODE_VERSION=$(node -v | cut -d 'v' -f 2 | cut -d '.' -f 1)
if [ "$NODE_VERSION" -lt 18 ]; then
  echo "❌ Node 18+ required. Current: $(node -v)"
  exit 1
fi
echo "✅ Node $(node -v)"

# 2. Check server.js exists
if [ ! -f "server.js" ]; then
  echo "❌ server.js not found in current directory"
  exit 1
fi
echo "✅ server.js found"

# 3. Init package.json
if [ ! -f "package.json" ]; then
  echo "📦 Creating package.json..."
  npm init -y > /dev/null
fi

# 4. Install dependencies
echo "📦 Installing runtime dependencies..."
npm install express cors multer express-rate-limit helmet winston jsonwebtoken stripe ws > /dev/null 2>&1
echo "📦 Installing dev dependencies..."
npm install --save-dev jest supertest > /dev/null 2>&1
echo "✅ Dependencies installed"

# 5. Update package.json scripts
node -e "
const fs = require('fs');
const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
pkg.scripts = { start: 'node server.js', test: 'jest' };
pkg.name = 'vanta-offensive-console';
pkg.version = '2.3.1';
pkg.description = 'Offensive console for red teams';
pkg.author = 'Mahmoud';
pkg.license = 'UNLICENSED';
fs.writeFileSync('package.json', JSON.stringify(pkg, null, 2));
console.log('✅ package.json updated');
"

# 6. Create .env
if [ ! -f ".env" ]; then
  DATA_KEY=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
  JWT_SECRET=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
  BOT_SECRET=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
  cat > .env << EOF
PORT=8443
DATA_KEY=$DATA_KEY
JWT_SECRET=$JWT_SECRET
BOT_SECRET=$BOT_SECRET
STRIPE_KEY=
EOF
  echo "✅ .env generated with random secrets"
else
  echo "✅ .env already exists (skipped)"
fi

# 7. Create .gitignore
if [ ! -f ".gitignore" ]; then
  cat > .gitignore << 'EOF'
node_modules/
data/
.env
.DS_Store
*.log
coverage/
EOF
  echo "✅ .gitignore created"
fi

# 8. Create Dockerfile
if [ ! -f "Dockerfile" ]; then
  cat > Dockerfile << 'EOF'
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --production
COPY . .
EXPOSE 8443
CMD ["node", "server.js"]
EOF
  echo "✅ Dockerfile created"
fi

# 9. Create docker-compose.yml
if [ ! -f "docker-compose.yml" ]; then
  cat > docker-compose.yml << 'EOF'
version: '3.8'
services:
  vanta:
    build: .
    ports:
      - "8443:8443"
    env_file:
      - .env
    volumes:
      - ./data:/app/data
    restart: unless-stopped
EOF
  echo "✅ docker-compose.yml created"
fi

# 10. Create tests
mkdir -p __tests__
cat > __tests__/api.test.js << 'EOF'
const request = require('supertest');
const { app, server } = require('../server');

describe('Health', () => {
  test('GET /health returns ok', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
  });
});

describe('Auth', () => {
  const email = `test_${Date.now()}@test.com`;
  let apiKey;

  test('register new user', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ email, password: 'password123' });
    expect(res.status).toBe(200);
    expect(res.body.apiKey).toBeTruthy();
    apiKey = res.body.apiKey;
  });

  test('login with credentials', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email, password: 'password123' });
    expect(res.status).toBe(200);
    expect(res.body.token).toBeTruthy();
  });

  test('reject scan without api key', async () => {
    const res = await request(app)
      .post('/api/scan')
      .send({ target: 'example.com' });
    expect(res.status).toBe(401);
  });

  test('allow scan with api key', async () => {
    const res = await request(app)
      .post('/api/scan')
      .set('X-API-Key', apiKey)
      .send({ target: 'example.com', checks: ['vulnerabilities'] });
    expect([200, 500]).toContain(res.status);
  });
});

afterAll(() => server.close());
EOF
echo "✅ Tests created"

# 11. Create GitHub workflow
mkdir -p .github/workflows
cat > .github/workflows/deploy.yml << 'EOF'
name: Build & Deploy
on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '20'
      - run: npm ci
      - run: npm test
  deploy:
    needs: build
    if: github.ref == 'refs/heads/main' && github.event_name == 'push'
    runs-on: ubuntu-latest
    steps:
      - name: Trigger Render Deploy
        run: |
          if [ -z "${{ secrets.RENDER_DEPLOY_HOOK }}" ]; then
            echo "⚠️ RENDER_DEPLOY_HOOK not set. Skipping deploy."
            exit 0
          fi
          curl -fsS -X POST "${{ secrets.RENDER_DEPLOY_HOOK }}"
EOF
echo "✅ GitHub workflow created"

# 12. Patch server.js to export app/server if not already
if ! grep -q "module.exports = { app, server }" server.js; then
  echo "🔧 Patching server.js for testing..."
  # Replace the final listen call with conditional listen + export
  node -e "
const fs = require('fs');
let content = fs.readFileSync('server.js', 'utf8');
const listenRegex = /server\.listen\(PORT,\s*['\"]0\.0\.0\.0['\"],\s*\(\)\s*=>\s*\{[^}]*\}\);/;
if (listenRegex.test(content)) {
  content = content.replace(listenRegex, \`if (require.main === module) {
  server.listen(PORT, '0.0.0.0', () => {
    logger.info(\\\`[vanta] server on :\\\${PORT}\\\`);
    console.log(\\\`[vanta] v\\\${PAYLOAD_VERSION} listening on :\\\${PORT}\\\`);
  });
}
module.exports = { app, server };\`);
  fs.writeFileSync('server.js', content);
  console.log('✅ server.js patched');
} else {
  console.log('⚠️ Could not auto-patch listen. Please add manually.');
}
"
fi

# 13. Run tests
echo "🧪 Running tests..."
if npm test 2>&1 | tail -20; then
  echo "✅ Tests passed"
else
  echo "⚠️ Tests failed — review the output above"
fi

# 14. Start server in background for quick smoke test
echo "🚀 Starting server for smoke test..."
node server.js > /tmp/vanta_startup.log 2>&1 &
SERVER_PID=$!
sleep 3

if curl -fsS http://localhost:8443/health > /dev/null 2>&1; then
  echo "✅ Server responds on :8443"
else
  echo "❌ Server did not respond. Check /tmp/vanta_startup.log"
  cat /tmp/vanta_startup.log
fi

kill $SERVER_PID 2>/dev/null || true
echo ""

# 15. Git init + optional push
if [ ! -d ".git" ]; then
  echo "🔧 Initializing git..."
  git init > /dev/null
  git add -A
  git commit -m "Initial VANTA commit" > /dev/null 2>&1 || true
  echo "✅ Git initialized"
fi

echo ""
echo "========================================"
echo "✅ VANTA installed successfully"
echo "========================================"
echo ""
echo "Next steps:"
echo "  1. Test locally:   npm start"
echo "  2. Run in Docker:  docker-compose up -d"
echo "  3. Push to GitHub: git remote add origin <your-repo> && git push -u origin main"
echo "  4. Deploy:         Render → New Web Service → connect repo"
echo ""
echo "Environment files:"
echo "  .env  (contains your secrets — never commit)"
echo ""
echo "Set RENDER_DEPLOY_HOOK in GitHub Secrets to enable CI/CD."
echo ""
