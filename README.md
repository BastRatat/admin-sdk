# @admin-sdk/auth

**Unified TypeScript SDK for Supabase Auth verification, RBAC, and admin operations**

## 🚀 Easy Integration - Works with ANY TypeScript/Node.js Project

This SDK supports **both CommonJS and ESM** projects automatically. No configuration needed!

### ✅ Compatible With:

- **CommonJS projects** (traditional Node.js)
- **ESM projects** (modern Node.js with `"type": "module"`)
- **TypeScript projects** (any configuration)
- **Express.js, Fastify, Koa, etc.**
- **Next.js, Nuxt.js, SvelteKit**
- **Any Node.js framework**

## 📦 Installation

```bash
npm install @admin-sdk/auth
# or
pnpm add @admin-sdk/auth
# or
yarn add @admin-sdk/auth
```

## 🔧 Usage

### CommonJS Projects (Traditional)

```typescript
// tsconfig.json
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "commonjs",
    "moduleResolution": "node"
  }
}
```

```typescript
// index.ts
const { AuthSDK, AdminSDK } = require('@admin-sdk/auth');

const authSDK = new AuthSDK({
  issuer: "https://your-project.supabase.co/auth/v1",
  jwksUri: "https://your-project.supabase.co/auth/v1/jwks",
  expectedAudience: "authenticated",
  serviceName: "my-service"
});
```

### ESM Projects (Modern)

```typescript
// tsconfig.json
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "ESNext",
    "moduleResolution": "node"
  }
}
```

```typescript
// package.json
{
  "type": "module"
}
```

```typescript
// index.ts
import { AuthSDK, AdminSDK } from '@admin-sdk/auth';

const authSDK = new AuthSDK({
  issuer: "https://your-project.supabase.co/auth/v1",
  jwksUri: "https://your-project.supabase.co/auth/v1/jwks",
  expectedAudience: "authenticated",
  serviceName: "my-service"
});
```

## 🎯 Express.js Example

```typescript
import express from 'express';
import { AuthSDK } from '@admin-sdk/auth';

const app = express();
const authSDK = new AuthSDK({
  issuer: "https://your-project.supabase.co/auth/v1",
  jwksUri: "https://your-project.supabase.co/auth/v1/jwks",
  expectedAudience: "authenticated",
  serviceName: "api-service"
});

// Auth middleware
app.use('/api', async (req, res, next) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) {
      return res.status(401).json({ error: 'Missing token' });
    }

    const result = await authSDK.verifyToken(token);
    req.user = result.context;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

app.get('/api/protected', (req, res) => {
  res.json({ message: 'Hello authenticated user!', user: req.user });
});
```

## 🔑 Key Features

- **🔒 JWT Verification**: Verify Supabase access tokens via JWKS
- **🛡️ RBAC Support**: Role-based access control helpers
- **👥 Admin Operations**: User management via Supabase Admin API
- **📊 Observability**: Structured logging and audit trails
- **⚡ Performance**: Cached JWKS with configurable TTL
- **🔧 TypeScript**: Full type safety and IntelliSense support

## 📋 API Reference

### AuthSDK

```typescript
const authSDK = new AuthSDK({
  issuer: string;           // Supabase Auth URL
  jwksUri: string;          // JWKS endpoint
  expectedAudience: string; // Usually "authenticated"
  serviceName: string;      // Your service name
  logger?: Logger;          // Optional logger
});

// Verify token
const result = await authSDK.verifyToken(token);

// Check app access
authSDK.assertAppAccess(result.context);

// Check role
authSDK.assertRole(result.context, 'admin');
```

### AdminSDK

```typescript
const adminSDK = new AdminSDK({
  supabaseUrl: string;
  supabaseKey: string;      // Service role key
}, logger?);

// Create user
await adminSDK.createUser({
  email: 'user@example.com',
  password: 'secure-password'
});

// Invite user
await adminSDK.inviteUser({
  email: 'user@example.com'
});
```

## 🏗️ Build System

The SDK uses a **dual package** approach:

- **CommonJS**: `dist/index.js` (for traditional Node.js)
- **ESM**: `dist/index.mjs` (for modern Node.js)
- **Types**: `dist/index.d.ts` (for TypeScript)

```bash
# Build both versions
npm run build

# Build CommonJS only
npm run build:cjs

# Build ESM only
npm run build:esm
```

## 🔧 Configuration

### TypeScript Config Examples

**CommonJS (Traditional):**
```json
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "commonjs",
    "moduleResolution": "node"
  }
}
```

**ESM (Modern):**
```json
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "ESNext",
    "moduleResolution": "node"
  }
}
```

**Your Exact Config (Works!):**
```json
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "commonjs",
    "lib": ["ES2020"],
    "outDir": "./dist",
    "rootDir": ".",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "moduleResolution": "node",
    "resolveJsonModule": true,
    "baseUrl": ".",
    "paths": {
      "@/*": ["./*"]
    },
    "typeRoots": ["./node_modules/@types", "./@types"]
  },
  "include": ["./**/*"],
  "exclude": ["node_modules", "dist"]
}
```

## 🎉 That's It!

Your SDK is now **truly easy to integrate** into any TypeScript/Node.js project. No more ESM/CommonJS compatibility issues!

## 📚 More Examples

See the `examples/` directory for:
- Express.js integration
- Fastify integration
- Next.js API routes
- Custom middleware patterns

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📄 License

MIT License - see LICENSE file for details.
