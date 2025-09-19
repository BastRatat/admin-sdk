# @admin-sdk/auth

**Unified TypeScript SDK for Supabase Auth verification, RBAC, admin operations, and microservice authentication**

## 🚀 Easy Integration - Works with ANY TypeScript/Node.js Project

This SDK supports **both CommonJS and ESM** projects automatically. No configuration needed!

### ✅ Compatible With:

- **CommonJS projects** (traditional Node.js)
- **ESM projects** (modern Node.js with `"type": "module"`)
- **TypeScript projects** (any configuration)
- **Express.js, Fastify, Koa, etc.**
- **Any Node.js framework**

## 📦 Installation

```bash
npm install @bastratat/admin-sdk-auth
# or
pnpm add @bastratat/admin-sdk-auth
# or
yarn add @bastratat/admin-sdk-auth
```

## 🎯 **RECOMMENDED: Microservice Authentication**

The `MicroserviceAuthSDK` is the **recommended approach** for server-side applications. It provides:

- **🔐 Centralized user management** across multiple microservices
- **🛡️ Service-scoped access control** using `serviceName`
- **⚡ Express middleware** for seamless authentication
- **📊 Automatic user metadata updates** (last_seen, etc.)
- **🔒 Built-in security features** (rate limiting, security headers)
- **✅ Input validation** and comprehensive error handling
- **🎯 Type-safe** with full TypeScript support

### Quick Start

```typescript
import { MicroserviceAuthSDK } from '@bastratat/admin-sdk-auth';

// Initialize once in your app.ts
const authSDK = new MicroserviceAuthSDK({
  supabaseUrl: "https://your-project.supabase.co",
  supabaseServiceKey: "your-service-role-key",
  issuer: "https://your-project.supabase.co/auth/v1",
  jwksUri: "https://your-project.supabase.co/auth/v1/jwks",
  expectedAudience: "authenticated",
  serviceName: "user-service", // CRITICAL: identifies this microservice
});

// Express middleware
app.use('/api', authSDK.middleware({
  requireAuth: true,
  requireRole: 'user', // Optional role requirement
  updateLastSeen: true // Auto-update user metadata
}));

// Your protected routes
app.get('/api/profile', (req, res) => {
  res.json({
    message: 'Hello authenticated user!',
    user: req.user,
    service: 'user-service'
  });
});
```

### Complete Microservice Example

```typescript
import express from 'express';
import { MicroserviceAuthSDK } from '@bastratat/admin-sdk-auth';

const app = express();
app.use(express.json());

// Initialize auth SDK for this microservice
const authSDK = new MicroserviceAuthSDK({
  supabaseUrl: "https://your-project.supabase.co",
  supabaseServiceKey: "your-service-role-key",
  issuer: "https://your-project.supabase.co/auth/v1",
  jwksUri: "https://your-project.supabase.co/auth/v1/jwks",
  expectedAudience: "authenticated",
  serviceName: "user-service", // This microservice name
});

// Public routes (no auth required)
app.post('/auth/signup', async (req, res) => {
  const { email, password, firstName, lastName } = req.body;

  const result = await authSDK.signUp({
    email,
    password,
    userData: {
      first_name: firstName,
      last_name: lastName,
      language: 'en'
    }
  });

  if (result.success) {
    res.json({
      message: 'User created successfully',
      user: result.user
    });
  } else {
    res.status(400).json({
      error: result.error.message
    });
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
    res.status(401).json({
      error: result.error.message
    });
  }
});

// Protected routes (auth required)
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

// Admin routes (role required)
app.use('/admin', authSDK.middleware({
  requireAuth: true,
  requireRole: 'admin',
  updateLastSeen: true
}));

app.get('/admin/users', (req, res) => {
  res.json({
    message: 'Admin access granted',
    user: req.user
  });
});

// Service management (for admins)
app.post('/admin/services/add', async (req, res) => {
  const { userId, serviceName, role } = req.body;

  const result = await authSDK.addUserToService({
    userId,
    serviceName,
    role: role || 'user'
  });

  if (result.success) {
    res.json({ message: 'User added to service successfully' });
  } else {
    res.status(400).json({ error: result.error.message });
  }
});

app.listen(3000, () => {
  console.log('User service running on port 3000');
});
```

## 🏗️ **Microservice Architecture Best Practices**

### **1. Service Configuration**

```typescript
// app.ts - Initialize once per microservice
import { MicroserviceAuthSDK } from '@bastratat/admin-sdk-auth';

const authSDK = new MicroserviceAuthSDK({
  supabaseUrl: process.env.SUPABASE_URL!,
  supabaseServiceKey: process.env.SUPABASE_SERVICE_KEY!,
  issuer: `${process.env.SUPABASE_URL}/auth/v1`,
  jwksUri: `${process.env.SUPABASE_URL}/auth/v1/jwks`,
  expectedAudience: "authenticated",
  serviceName: process.env.SERVICE_NAME!, // e.g., "user-service", "payment-service"
  logger: {
    info: (msg, meta) => console.log(`[INFO] ${msg}`, meta),
    warn: (msg, meta) => console.warn(`[WARN] ${msg}`, meta),
    error: (msg, meta) => console.error(`[ERROR] ${msg}`, meta),
    debug: (msg, meta) => console.debug(`[DEBUG] ${msg}`, meta),
  },
});
```

### **2. Environment Variables**

```bash
# .env
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SERVICE_KEY=your-service-role-key
SERVICE_NAME=user-service
```

### **3. Multi-Service Setup**

```typescript
// user-service/app.ts
const userAuthSDK = new MicroserviceAuthSDK({
  // ... config
  serviceName: "user-service",
});

// payment-service/app.ts
const paymentAuthSDK = new MicroserviceAuthSDK({
  // ... config
  serviceName: "payment-service",
});

// notification-service/app.ts
const notificationAuthSDK = new MicroserviceAuthSDK({
  // ... config
  serviceName: "notification-service",
});
```

### **4. Flexible User Data Structure**

The SDK provides **generic types** for maximum flexibility:

```typescript
import { User } from '@bastratat/admin-sdk-auth';

// Default usage (any metadata)
const user: User = {
  id: "user-123",
  email: "john@example.com",
  app_metadata: {
    services: ["user-service"],
    roles: { "user-service": "admin" },
    // Any additional fields
    subscription_tier: "premium",
    custom_field: "value"
  },
  user_metadata: {
    first_name: "John",
    last_name: "Doe",
    // Any additional fields
    shopping_cart: ["product-1"],
    loyalty_points: 150
  },
  aud: "authenticated",
  created_at: "2024-01-15T10:30:00Z"
};

// Typed usage (when you want type safety)
type MyAppMetadata = {
  services: string[];
  roles: Record<string, string>;
  subscription_tier?: "free" | "premium";
};

type MyUserMetadata = {
  first_name?: string;
  last_name?: string;
  shopping_cart?: string[];
  loyalty_points?: number;
};

const typedUser: User<MyAppMetadata, MyUserMetadata> = {
  id: "user-123",
  email: "john@example.com",
  app_metadata: {
    services: ["user-service"],
    roles: { "user-service": "admin" },
    subscription_tier: "premium" // TypeScript knows this field
  },
  user_metadata: {
    first_name: "John",
    shopping_cart: ["product-1"],
    loyalty_points: 150
  },
  aud: "authenticated",
  created_at: "2024-01-15T10:30:00Z"
};
```

### **5. Generic Type Benefits**

```typescript
// ✅ Maximum flexibility with any
function processAnyUser(user: User) {
  // Can access any field, no type restrictions
  const services = user.app_metadata.services;
  const customField = user.app_metadata.anything_you_want;
  const userData = user.user_metadata.any_field;
}

// ✅ Type safety when you need it
function processTypedUser(user: User<MyAppMetadata, MyUserMetadata>) {
  // TypeScript knows the exact structure
  const tier = user.app_metadata.subscription_tier; // "free" | "premium" | undefined
  const points = user.user_metadata.loyalty_points; // number | undefined
}
```

### **6. Service Management Flow**

```typescript
// Admin service - Manage user access across services
app.post('/admin/services/grant-access', async (req, res) => {
  const { userId, serviceName, role = 'user' } = req.body;

  // Add user to service
  const result = await authSDK.addUserToService({
    userId,
    serviceName,
    role
  });

  if (result.success) {
    res.json({
      message: `User granted ${role} access to ${serviceName}`,
      userId,
      serviceName,
      role
    });
  } else {
    res.status(400).json({
      error: result.error.message,
      code: result.error.reason
    });
  }
});

// Check user's service access
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

### **7. Error Handling Patterns**

```typescript
// Centralized error handling
app.use((error: any, req: any, res: any, next: any) => {
  console.error('Unhandled error:', error);

  // Handle SDK-specific errors
  if (error.code === 'AUTH_ERROR') {
    return res.status(401).json({
      error: error.message,
      code: error.reason,
      hint: error.hint
    });
  }

  if (error.code === 'PERMISSION_ERROR') {
    return res.status(403).json({
      error: error.message,
      code: error.reason,
      remediation: error.remediation
    });
  }

  // Generic error
  res.status(500).json({ error: 'Internal server error' });
});
```

### **8. Security Best Practices**

```typescript
// Rate limiting middleware
import rateLimit from 'express-rate-limit';

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 requests per windowMs
  message: 'Too many authentication attempts, please try again later.',
});

app.use('/auth', authLimiter);

// Security headers middleware
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});
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
const { MicroserviceAuthSDK, AuthSDK, AdminSDK } = require('@bastratat/admin-sdk-auth');

// Recommended: Microservice authentication
const authSDK = new MicroserviceAuthSDK({
  supabaseUrl: "https://your-project.supabase.co",
  supabaseServiceKey: "your-service-role-key",
  issuer: "https://your-project.supabase.co/auth/v1",
  jwksUri: "https://your-project.supabase.co/auth/v1/jwks",
  expectedAudience: "authenticated",
  serviceName: "my-service"
});

// Legacy: Server-side auth verification only
const legacyAuthSDK = new AuthSDK({
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
import { MicroserviceAuthSDK, AuthSDK, AdminSDK } from '@bastratat/admin-sdk-auth';

// Recommended: Microservice authentication
const authSDK = new MicroserviceAuthSDK({
  supabaseUrl: "https://your-project.supabase.co",
  supabaseServiceKey: "your-service-role-key",
  issuer: "https://your-project.supabase.co/auth/v1",
  jwksUri: "https://your-project.supabase.co/auth/v1/jwks",
  expectedAudience: "authenticated",
  serviceName: "my-service"
});
```

## 🎯 Client-Side Authentication Examples

### React Example

```typescript
import React, { useState, useEffect } from 'react';
import { ClientAuthSDK } from '@bastratat/admin-sdk-auth';

const clientAuth = new ClientAuthSDK({
  supabaseUrl: "https://your-project.supabase.co",
  supabaseAnonKey: "your-anon-key"
});

function AuthComponent() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Get initial session
    clientAuth.getSession().then(({ session }) => {
      setUser(session?.user || null);
      setLoading(false);
    });

    // Listen for auth changes
    const { data: { subscription } } = clientAuth.onAuthStateChange((event, session) => {
      setUser(session?.user || null);
    });

    return () => subscription.unsubscribe();
  }, []);

  const handleSignup = async (email: string, password: string) => {
    const result = await clientAuth.signup({ email, password });
    if (result.success) {
      console.log('User signed up:', result.user);
    } else {
      console.error('Signup failed:', result.error.message);
    }
  };

  const handleSignin = async (email: string, password: string) => {
    const result = await clientAuth.signin({ email, password });
    if (result.success) {
      console.log('User signed in:', result.user);
    } else {
      console.error('Signin failed:', result.error.message);
    }
  };

  const handleSignout = async () => {
    const { success } = await clientAuth.signout();
    if (success) {
      console.log('User signed out');
    }
  };

  if (loading) return <div>Loading...</div>;

  return (
    <div>
      {user ? (
        <div>
          <p>Welcome, {user.email}!</p>
          <button onClick={handleSignout}>Sign Out</button>
        </div>
      ) : (
        <div>
          <button onClick={() => handleSignup('user@example.com', 'password123')}>
            Sign Up
          </button>
          <button onClick={() => handleSignin('user@example.com', 'password123')}>
            Sign In
          </button>
        </div>
      )}
    </div>
  );
}
```

### Vue Example

```typescript
import { ref, onMounted, onUnmounted } from 'vue';
import { ClientAuthSDK } from '@bastratat/admin-sdk-auth';

const clientAuth = new ClientAuthSDK({
  supabaseUrl: "https://your-project.supabase.co",
  supabaseAnonKey: "your-anon-key"
});

export default {
  setup() {
    const user = ref(null);
    const loading = ref(true);

    onMounted(async () => {
      // Get initial session
      const { session } = await clientAuth.getSession();
      user.value = session?.user || null;
      loading.value = false;

      // Listen for auth changes
      const { data: { subscription } } = clientAuth.onAuthStateChange((event, session) => {
        user.value = session?.user || null;
      });

      onUnmounted(() => subscription.unsubscribe());
    });

    const signup = async (email: string, password: string) => {
      const result = await clientAuth.signup({ email, password });
      if (result.success) {
        console.log('User signed up:', result.user);
      } else {
        console.error('Signup failed:', result.error.message);
      }
    };

    const signin = async (email: string, password: string) => {
      const result = await clientAuth.signin({ email, password });
      if (result.success) {
        console.log('User signed in:', result.user);
      } else {
        console.error('Signin failed:', result.error.message);
      }
    };

    const signout = async () => {
      const { success } = await clientAuth.signout();
      if (success) {
        console.log('User signed out');
      }
    };

    return { user, loading, signup, signin, signout };
  }
};
```

### Vanilla JavaScript Example

```javascript
import { ClientAuthSDK } from '@bastratat/admin-sdk-auth';

const clientAuth = new ClientAuthSDK({
  supabaseUrl: "https://your-project.supabase.co",
  supabaseAnonKey: "your-anon-key"
});

// Sign up
async function signup(email, password) {
  const result = await clientAuth.signup({ email, password });
  if (result.success) {
    console.log('User signed up:', result.user);
    return result.user;
  } else {
    console.error('Signup failed:', result.error.message);
    throw result.error;
  }
}

// Sign in
async function signin(email, password) {
  const result = await clientAuth.signin({ email, password });
  if (result.success) {
    console.log('User signed in:', result.user);
    return result.user;
  } else {
    console.error('Signin failed:', result.error.message);
    throw result.error;
  }
}

// Sign out
async function signout() {
  const { success } = await clientAuth.signout();
  if (success) {
    console.log('User signed out');
  }
}

// Get current user
async function getCurrentUser() {
  const { user } = await clientAuth.getCurrentUser();
  return user;
}

// Listen for auth changes
clientAuth.onAuthStateChange((event, session) => {
  console.log('Auth state changed:', event, session?.user);
});
```

## 🎯 Server-Side Express.js Example

```typescript
import express from 'express';
import { AuthSDK } from '@bastratat/admin-sdk-auth';

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
    if (result.success) {
      req.user = result.context;
      next();
    } else {
      res.status(401).json({ error: 'Invalid token' });
    }
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

app.get('/api/protected', (req, res) => {
  res.json({ message: 'Hello authenticated user!', user: req.user });
});
```

## 🔑 Key Features

### Microservice Authentication (RECOMMENDED)
- **🔐 Centralized User Management**: Single user database across all microservices
- **🛡️ Service-Scoped Access Control**: Users only access authorized services
- **⚡ Express Middleware**: Seamless authentication for Express.js apps
- **📊 Automatic Metadata Updates**: Track last_seen, user activity, etc.
- **🔄 Service Management**: Add/remove users from services dynamically
- **🎯 Role-Based Access**: Service-specific roles and permissions

### Legacy Server-Side Verification
- **🔒 JWT Verification**: Verify Supabase access tokens via JWKS
- **🛡️ RBAC Support**: Role-based access control helpers
- **👥 Admin Operations**: User management via Supabase Admin API
- **📊 Observability**: Structured logging and audit trails
- **⚡ Performance**: Cached JWKS with configurable TTL
- **🔧 TypeScript**: Full type safety and IntelliSense support

## 📋 API Reference

### MicroserviceAuthSDK (RECOMMENDED)

```typescript
const authSDK = new MicroserviceAuthSDK({
  supabaseUrl: string;           // Supabase project URL
  supabaseServiceKey: string;    // Service role key (server-side only)
  issuer: string;               // Supabase Auth URL
  jwksUri: string;              // JWKS endpoint
  expectedAudience: string;     // Usually "authenticated"
  serviceName: string;          // CRITICAL: current microservice name
  logger?: Logger;              // Optional logger
});

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

### AuthSDK (Legacy)

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

## 🚨 **Troubleshooting**

### **Common Issues**

#### **1. "SERVICE_ACCESS_DENIED" Error**
```typescript
// Problem: User doesn't have access to the service
// Solution: Add user to service
await authSDK.addUserToService({
  userId: 'user-id',
  serviceName: 'your-service',
  role: 'user'
});
```

#### **2. "INVALID_TOKEN" Error**
```typescript
// Problem: Token is malformed or expired
// Solution: Check token format and expiration
const token = req.headers.authorization?.replace('Bearer ', '');
if (!token || token.split('.').length !== 3) {
  return res.status(401).json({ error: 'Invalid token format' });
}
```

#### **3. "JWKS_KEY_NOT_FOUND" Error**
```typescript
// Problem: JWKS endpoint not accessible or key not found
// Solution: Check JWKS URI and network connectivity
const jwksUri = `${supabaseUrl}/auth/v1/jwks`;
// Ensure this endpoint is accessible from your server
```

#### **4. "MISSING_SERVICE_NAME" Error**
```typescript
// Problem: Service name not configured
// Solution: Always provide serviceName in config
const authSDK = new MicroserviceAuthSDK({
  // ... other config
  serviceName: 'your-microservice-name', // REQUIRED
});
```

### **Debug Mode**

```typescript
// Enable debug logging
const authSDK = new MicroserviceAuthSDK({
  // ... config
  logger: {
    info: (msg, meta) => console.log(`[INFO] ${msg}`, meta),
    warn: (msg, meta) => console.warn(`[WARN] ${msg}`, meta),
    error: (msg, meta) => console.error(`[ERROR] ${msg}`, meta),
    debug: (msg, meta) => console.debug(`[DEBUG] ${msg}`, meta),
  },
});
```

### **Health Check Endpoint**

```typescript
// Add health check for your microservice
app.get('/health', async (req, res) => {
  try {
    // Test Supabase connection
    const { data, error } = await supabase.auth.admin.listUsers({ page: 1, perPage: 1 });

    if (error) {
      return res.status(503).json({
        status: 'unhealthy',
        error: 'Supabase connection failed',
        details: error.message
      });
    }

    res.json({
      status: 'healthy',
      service: process.env.SERVICE_NAME,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(503).json({
      status: 'unhealthy',
      error: 'Health check failed'
    });
  }
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
