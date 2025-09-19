/**
 * Unified types for Supabase Auth SDK with RBAC and Admin operations
 */

/**
 * Standard JWT header claims
 */
export type JWTHeader = {
  readonly alg: string;
  readonly typ: "JWT";
  readonly kid?: string;
};

/**
 * Standard JWT payload claims
 */
export type StandardClaims = {
  readonly iss: string; // Issuer (Supabase Auth URL)
  readonly aud: string | string[]; // Audience (usually 'authenticated')
  readonly exp: number; // Expiration time (Unix timestamp)
  readonly iat: number; // Issued at (Unix timestamp)
  readonly sub: string; // Subject (user ID)
  readonly role: "authenticated" | "anon" | "service_role";
  readonly session_id?: string; // Supabase session identifier
};

/**
 * Supabase-specific claims injected via Custom Access Token Hook
 */
export type SupabaseClaims = {
  readonly app_metadata?: {
    readonly apps?: readonly string[]; // Apps/microservices user has access to
    readonly roles?: Readonly<Record<string, string>>; // App-scoped roles
    readonly is_service_account?: boolean; // Service account flag
  };
  readonly user_metadata?: Readonly<Record<string, unknown>>; // User-controlled data
  readonly aal?: "aal1" | "aal2" | "aal3"; // Authentication Assurance Level
  readonly email?: string;
  readonly phone?: string;
  readonly email_confirmed_at?: string;
  readonly phone_confirmed_at?: string;
};

/**
 * Complete JWT payload combining standard and Supabase claims
 */
export type JWTPayload = StandardClaims & SupabaseClaims;

/**
 * Normalized authentication context after token verification
 */
export type AuthContext = {
  readonly userId: string;
  readonly email: string | undefined;
  readonly phone: string | undefined;
  readonly sessionId: string | undefined;
  readonly apps: readonly string[];
  readonly roles: Readonly<Record<string, string>>;
  readonly isServiceAccount: boolean;
  readonly aal: "aal1" | "aal2" | "aal3" | undefined;
  readonly issuedAt: Date;
  readonly expiresAt: Date;
  readonly rawClaims: JWTPayload;
};

/**
 * SDK configuration options
 */
export type AuthConfig = {
  readonly issuer: string; // Supabase Auth URL (e.g., https://project.supabase.co/auth/v1)
  readonly jwksUri: string; // JWKS endpoint URL
  readonly expectedAudience: string | string[]; // Expected audience (usually 'authenticated')
  readonly serviceName: string; // Current microservice name for app membership checks
  readonly sessionCheck?: boolean | SessionCheckFunction; // Optional session existence validation
  readonly jwksCacheTtl?: number; // JWKS cache TTL in seconds (default: 300)
  readonly clockSkewTolerance?: number; // Clock skew tolerance in seconds (default: 30)
  readonly logger?: Logger;
};

/**
 * Admin client configuration
 */
export type AdminConfig = {
  readonly supabaseUrl: string;
  readonly supabaseKey: string; // Service role key (server-only)
};

/**
 * Function type for custom session existence checking
 */
export type SessionCheckFunction = (sessionId: string) => Promise<boolean>;

/**
 * Logger interface for observability
 */
export type Logger = {
  readonly info: (message: string, meta?: LogMeta) => void;
  readonly warn: (message: string, meta?: LogMeta) => void;
  readonly error: (message: string, meta?: LogMeta) => void;
  readonly debug: (message: string, meta?: LogMeta) => void;
};

/**
 * Log metadata for structured logging
 */
export type LogMeta = {
  readonly userId?: string;
  readonly sessionId?: string;
  readonly serviceName?: string;
  readonly decision?: "allow" | "deny";
  readonly reason?: string;
  readonly [key: string]: unknown;
};

/**
 * Base error class for all SDK errors
 */
export abstract class SDKError extends Error {
  abstract readonly code: string;
  abstract readonly statusCode: number;
  abstract readonly reason: string;
  abstract readonly hint?: string;
  abstract readonly remediation?: string;
}

/**
 * Authentication error - invalid, missing, or expired token
 */
export class AuthError extends SDKError {
  readonly code = "AUTH_ERROR";
  readonly statusCode = 401;

  constructor(
    message: string,
    readonly reason: string,
    readonly hint?: string,
    readonly remediation?: string
  ) {
    super(message);
    this.name = "AuthError";
  }
}

/**
 * Permission error - valid token but insufficient permissions
 */
export class PermissionError extends SDKError {
  readonly code = "PERMISSION_ERROR";
  readonly statusCode = 403;

  constructor(
    message: string,
    readonly reason: string,
    readonly hint?: string,
    readonly remediation?: string
  ) {
    super(message);
    this.name = "PermissionError";
  }
}

/**
 * Token freshness error - session revoked or AAL requirements not met
 */
export class TokenFreshnessError extends SDKError {
  readonly code = "TOKEN_FRESHNESS_ERROR";
  readonly statusCode = 401;

  constructor(
    message: string,
    readonly reason: string,
    readonly hint?: string,
    readonly remediation?: string
  ) {
    super(message);
    this.name = "TokenFreshnessError";
  }
}

/**
 * Configuration error - invalid SDK setup
 */
export class ConfigError extends SDKError {
  readonly code = "CONFIG_ERROR";
  readonly statusCode = 500;

  constructor(
    message: string,
    readonly reason: string,
    readonly hint?: string,
    readonly remediation?: string
  ) {
    super(message);
    this.name = "ConfigError";
  }
}

/**
 * Authorization assertion options
 */
export type AssertionOptions = {
  readonly requireSession?: boolean; // Force session existence check
  readonly requireAAL?: "aal1" | "aal2" | "aal3"; // Require specific AAL
  readonly logger?: Logger; // Override logger for this assertion
};

/**
 * Role assertion options
 */
export type RoleAssertionOptions = AssertionOptions & {
  readonly appScoped?: boolean; // Check role within current service context
};

/**
 * AAL assertion options
 */
export type AALAssertionOptions = AssertionOptions & {
  readonly allowHigher?: boolean; // Allow higher AAL levels (e.g., aal3 satisfies aal2 requirement)
};

/**
 * Token verification result
 */
export type TokenVerificationResult =
  | {
      readonly success: true;
      readonly context: AuthContext;
    }
  | {
      readonly success: false;
      readonly error: SDKError;
    };

/**
 * User creation options for admin operations
 */
export type UserCreateOptions = {
  readonly email: string;
  readonly password?: string;
  readonly emailConfirm?: boolean;
  readonly appMetadata?: Record<string, unknown>;
  readonly userMetadata?: Record<string, unknown>;
};

/**
 * User invitation options
 */
export type UserInviteOptions = {
  readonly email: string;
  readonly redirectTo?: string;
  readonly data?: Record<string, unknown>;
};

/**
 * JSON Web Key for signature verification
 */
export type JWK = {
  readonly kty: string;
  readonly use: string;
  readonly kid: string;
  readonly x5t?: string;
  readonly n?: string;
  readonly e?: string;
  readonly x5c?: readonly string[];
  readonly alg?: string;
};

/**
 * JWKS response from Supabase
 */
export type JWKSResponse = {
  readonly keys: readonly JWK[];
};
