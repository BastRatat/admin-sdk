# @admin-sdk/auth

**Clean TypeScript SDK for Supabase Auth with microservice authentication**

## 🚀 Quick Start

```bash
npm install @bastratat/admin-sdk-auth
```

```typescript
import { AuthSDK } from '@bastratat/admin-sdk-auth';

const authSDK = new AuthSDK({
  supabaseUrl: process.env.SUPABASE_URL!,
  supabaseServiceKey: process.env.SUPABASE_SERVICE_KEY!,
  issuer: `${process.env.SUPABASE_URL}/auth/v1`,
  jwksUri: `${process.env.SUPABASE_URL}/auth/v1/.well-known/jwks.json`,
  expectedAudience: "authenticated",
  serviceName: process.env.SERVICE_NAME || "NekoChan",
  logger: {
    debug: (message: string, meta?: any) =>
      console.debug(`[DEBUG] ${message}`, meta),
    info: (message: string, meta?: any) =>
      console.log(`[INFO] ${message}`, meta),
    warn: (message: string, meta?: any) =>
      console.warn(`[WARN] ${message}`, meta),
    error: (message: string, meta?: any) =>
      console.error(`[ERROR] ${message}`, meta),
  },
});
```

## 🎯 Features

- **🔐 Microservice Authentication** - Service-scoped access control
- **⚡ Express Middleware** - Seamless authentication for Express.js
- **🛡️ JWT Verification** - Secure token verification via JWKS
- **📊 User Management** - Sign up, sign in, service management
- **🎯 Type Safety** - Full TypeScript support with clean types
- **🔒 Security** - Built-in security headers and validation

## 📦 Installation

```bash
npm install @bastratat/admin-sdk-auth
# or
pnpm add @bastratat/admin-sdk-auth
# or
yarn add @bastratat/admin-sdk-auth
```

## 🔧 Basic Usage

### Express.js Integration

```typescript
import express from 'express';
import { AuthSDK } from '@bastratat/admin-sdk-auth';

const app = express();
app.use(express.json());

// Initialize auth SDK
const authSDK = new AuthSDK({
  supabaseUrl: process.env.SUPABASE_URL!,
  supabaseServiceKey: process.env.SUPABASE_SERVICE_KEY!,
  issuer: `${process.env.SUPABASE_URL}/auth/v1`,
  jwksUri: `${process.env.SUPABASE_URL}/auth/v1/.well-known/jwks.json`,
  expectedAudience: "authenticated",
  serviceName: process.env.SERVICE_NAME || "user-service",
});

// Public routes
app.post('/auth/signup', async (req, res) => {
  const { email, password, firstName, lastName } = req.body;

  const result = await authSDK.signUp({
    email,
    password,
    userData: {
      first_name: firstName,
      last_name: lastName,
    }
  });

  if (result.success) {
    res.json({ message: 'User created', user: result.user });
  } else {
    res.status(400).json({ error: result.error.message });
  }
});

app.post('/auth/signin', async (req, res) => {
  const { email, password } = req.body;

  const result = await authSDK.signIn({ email, password });

  if (result.success) {
    res.json({
      message: 'Signin successful',
      user: result.user,
      session: result.session
    });
  } else {
    res.status(401).json({ error: result.error.message });
  }
});

// Protected routes
app.use('/api', authSDK.middleware({
  requireAuth: true,
  updateLastSeen: true
}));

app.get('/api/profile', (req, res) => {
  res.json({
    user: req.user,
    service: 'user-service'
  });
});

// Admin routes
app.use('/admin', authSDK.middleware({
  requireAuth: true,
  requireRole: 'admin',
  updateLastSeen: true
}));

app.get('/admin/users', (req, res) => {
  res.json({ message: 'Admin access granted', user: req.user });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});
```

### Service Management

```typescript
// Add user to service
app.post('/admin/services/add', async (req, res) => {
  const { userId, serviceName, role } = req.body;

  const result = await authSDK.addUserToService({
    userId,
    serviceName,
    role: role || 'user'
  });

  if (result.success) {
    res.json({ message: 'User added to service' });
  } else {
    res.status(400).json({ error: result.error.message });
  }
});

// Get user's services
app.get('/admin/users/:userId/services', async (req, res) => {
  const { userId } = req.params;

  const { services, roles, error } = await authSDK.getUserServices(userId);

  if (error) {
    res.status(400).json({ error: error.message });
  } else {
    res.json({ userId, services, roles });
  }
});
```

## 🏗️ Microservice Architecture

### Environment Setup

```bash
# .env
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SERVICE_KEY=your-service-role-key
SERVICE_NAME=user-service
```

### Multi-Service Configuration

```typescript
// user-service/app.ts
const userAuthSDK = new AuthSDK({
  supabaseUrl: process.env.SUPABASE_URL!,
  supabaseServiceKey: process.env.SUPABASE_SERVICE_KEY!,
  issuer: `${process.env.SUPABASE_URL}/auth/v1`,
  jwksUri: `${process.env.SUPABASE_URL}/auth/v1/.well-known/jwks.json`,
  expectedAudience: "authenticated",
  serviceName: "user-service",
});

// payment-service/app.ts
const paymentAuthSDK = new AuthSDK({
  supabaseUrl: process.env.SUPABASE_URL!,
  supabaseServiceKey: process.env.SUPABASE_SERVICE_KEY!,
  issuer: `${process.env.SUPABASE_URL}/auth/v1`,
  jwksUri: `${process.env.SUPABASE_URL}/auth/v1/.well-known/jwks.json`,
  expectedAudience: "authenticated",
  serviceName: "payment-service",
});

// notification-service/app.ts
const notificationAuthSDK = new AuthSDK({
  supabaseUrl: process.env.SUPABASE_URL!,
  supabaseServiceKey: process.env.SUPABASE_SERVICE_KEY!,
  issuer: `${process.env.SUPABASE_URL}/auth/v1`,
  jwksUri: `${process.env.SUPABASE_URL}/auth/v1/.well-known/jwks.json`,
  expectedAudience: "authenticated",
  serviceName: "notification-service",
});
```

## 📋 API Reference

### AuthSDK

```typescript
const authSDK = new AuthSDK({
  supabaseUrl: string;           // Supabase project URL
  supabaseServiceKey: string;    // Service role key
  issuer: string;               // Supabase Auth URL
  jwksUri: string;              // JWKS endpoint
  expectedAudience: string;     // Usually "authenticated"
  serviceName: string;          // Current microservice name
  logger?: Logger;              // Optional logger
});
```

### Methods

```typescript
// Authentication
await authSDK.signUp({ email, password, userData? });
await authSDK.signIn({ email, password });
await authSDK.signOut(userId);

// Token verification
const result = await authSDK.verifyToken(token);

// Service management
await authSDK.addUserToService({ userId, serviceName, role? });
await authSDK.removeUserFromService({ userId, serviceName });
await authSDK.getUserServices(userId);

// Express middleware
app.use('/api', authSDK.middleware({
  requireAuth: true,
  requireRole?: 'admin',
  requireAAL?: 'aal2',
  updateLastSeen: true
}));
```

### Types

```typescript
// Essential types exported
export type {
  AuthContext,
  MicroserviceAuthConfig,
  MicroserviceSignupOptions,
  MicroserviceSigninOptions,
  TokenVerificationResult,
};

// Error classes
export { AuthError, PermissionError, ConfigError };
```

## 🚨 Error Handling

```typescript
// Centralized error handling
app.use((error: any, req: any, res: any, next: any) => {
  console.error('Error:', error);

  if (error.code === 'AUTH_ERROR') {
    return res.status(401).json({
      error: error.message,
      code: error.reason,
    });
  }

  if (error.code === 'PERMISSION_ERROR') {
    return res.status(403).json({
      error: error.message,
      code: error.reason,
    });
  }

  res.status(500).json({ error: 'Internal server error' });
});
```

## 🔒 Security Best Practices

```typescript
// Rate limiting
import rateLimit from 'express-rate-limit';

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 requests per windowMs
  message: 'Too many authentication attempts',
});

app.use('/auth', authLimiter);

// Security headers (automatically added by middleware)
// X-Content-Type-Options: nosniff
// X-Frame-Options: DENY
// X-XSS-Protection: 1; mode=block
```

## 🐛 Troubleshooting

### Common Issues

**"SERVICE_ACCESS_DENIED" Error**
```typescript
// User doesn't have access to the service
await authSDK.addUserToService({
  userId: 'user-id',
  serviceName: 'your-service',
  role: 'user'
});
```

**"INVALID_TOKEN" Error**
```typescript
// Check token format
const token = req.headers.authorization?.replace('Bearer ', '');
if (!token || token.split('.').length !== 3) {
  return res.status(401).json({ error: 'Invalid token format' });
}
```

**"MISSING_SERVICE_NAME" Error**
```typescript
// Always provide serviceName in config
const authSDK = new AuthSDK({
  // ... other config
  serviceName: 'your-microservice-name', // REQUIRED
});
```

### Debug Mode

```typescript
const authSDK = new AuthSDK({
  // ... config
  logger: {
    info: (msg, meta) => console.log(`[INFO] ${msg}`, meta),
    warn: (msg, meta) => console.warn(`[WARN] ${msg}`, meta),
    error: (msg, meta) => console.error(`[ERROR] ${msg}`, meta),
    debug: (msg, meta) => console.debug(`[DEBUG] ${msg}`, meta),
  },
});
```

## 🏗️ Build System

```bash
# Build the SDK
npm run build

# Clean build artifacts
npm run clean
```

The SDK outputs to `dist/` with:
- `index.js` - CommonJS build
- `index.d.ts` - TypeScript declarations
- Source maps for debugging

## 📄 License

MIT License - see LICENSE file for details.
