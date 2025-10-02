/**
 * Unified types for Supabase Auth SDK with RBAC and Admin operations
 */

import type { SDKError } from './errors';

/**
 * Standard JWT header claims
 */
export type JWTHeader = {
  readonly alg: string;
  readonly typ: 'JWT';
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
  readonly role: 'authenticated' | 'anon' | 'service_role';
  readonly session_id?: string; // Supabase session identifier
};

/**
 * Supabase-specific claims injected via Custom Access Token Hook
 */
export type SupabaseClaims = {
  readonly app_metadata?: {
    readonly services?: readonly string[]; // Services/microservices user has access to
    readonly roles?: Readonly<Record<string, string>>; // Service-scoped roles
    readonly is_service_account?: boolean; // Service account flag
  };
  readonly user_metadata?: Readonly<Record<string, unknown>>; // User-controlled data
  readonly aal?: 'aal1' | 'aal2' | 'aal3'; // Authentication Assurance Level
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
  readonly aal: 'aal1' | 'aal2' | 'aal3' | undefined;
  readonly issuedAt: Date;
  readonly expiresAt: Date;
  readonly rawClaims: JWTPayload;
};

/**
 * Authentication configuration
 */
export type AuthConfig = {
  readonly supabaseUrl: string;
  readonly supabaseServiceKey: string;
  readonly supabaseJwtSecret?: string; // Legacy JWT secret for HS256 verification
  readonly issuer: string; // Supabase Auth URL (e.g., https://project.supabase.co/auth/v1)
  readonly jwksUri: string; // JWKS endpoint URL
  readonly expectedAudience: string | string[]; // Expected audience (usually 'authenticated')
  readonly serviceName: string; // Current microservice name - CRITICAL for service-scoped auth
  readonly sessionCheck?: boolean | SessionCheckFunction;
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
  readonly decision?: 'allow' | 'deny';
  readonly reason?: string;
  readonly [key: string]: unknown;
};

/**
 * Authorization assertion options
 */
export type AssertionOptions = {
  readonly requireSession?: boolean; // Force session existence check
  readonly requireAAL?: 'aal1' | 'aal2' | 'aal3'; // Require specific AAL
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
 * Microservice signup options
 */
export type SignupOptions = {
  readonly email: string;
  readonly password: string;
  readonly userData?: {
    readonly first_name?: string;
    readonly last_name?: string;
    readonly language?: string;
    readonly serviceName?: string;
    readonly [key: string]: unknown;
  };
};

/**
 * Microservice signin options
 */
export type SigninOptions = {
  readonly email: string;
  readonly password: string;
};

/**
 * Service management options
 */
export type ServiceManagementOptions = {
  readonly userId: string;
  readonly serviceName: string;
  readonly role?: string; // Optional role for the service
};

/**
 * Express middleware options for microservice auth
 */
export type MicroserviceMiddlewareOptions = {
  readonly requireAuth?: boolean; // Default: true
  readonly requireSession?: boolean; // Default: false
  readonly requireRole?: string; // Optional role requirement for current service
  readonly requireAAL?: 'aal1' | 'aal2' | 'aal3'; // Optional AAL requirement
  readonly allowServiceAccounts?: boolean; // Default: false
  readonly updateLastSeen?: boolean; // Default: true - update user metadata with last_seen
};

/**
 * Generic Supabase User type with flexible metadata
 * @template TAppMetadata - Type for app_metadata (defaults to any for maximum flexibility)
 * @template TUserMetadata - Type for user_metadata (defaults to any for maximum flexibility)
 */
export type User<
  TAppMetadata extends object = Record<string, unknown>,
  TUserMetadata extends object = Record<string, unknown>,
> = {
  readonly id: string;
  readonly email?: string;
  readonly phone?: string;
  readonly email_confirmed_at?: string;
  readonly phone_confirmed_at?: string;
  readonly app_metadata: TAppMetadata;
  readonly user_metadata: TUserMetadata;
  readonly aud: string;
  readonly created_at: string;
};

/**
 * Supabase Auth Response type with generic User
 * @template TAppMetadata - Type for app_metadata (defaults to any)
 * @template TUserMetadata - Type for user_metadata (defaults to any)
 */
export type AuthResponse<
  TAppMetadata extends object = Record<string, unknown>,
  TUserMetadata extends object = Record<string, unknown>,
> = {
  readonly user: User<TAppMetadata, TUserMetadata> | null;
  readonly session: SessionData | null;
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

/**
 * Client-side authentication configuration
 */
export type ClientAuthConfig = {
  readonly supabaseUrl: string;
  readonly supabaseAnonKey: string; // Anon key for client-side operations
  readonly logger?: Logger;
};

/**
 * Password reset options
 */
export type PasswordResetOptions = {
  readonly email: string;
  readonly options?: {
    readonly redirectTo?: string;
    readonly captchaToken?: string;
    readonly language?: string; // Language code (e.g., 'en', 'fr', 'es')
  };
};

/**
 * Password update options
 */
export type PasswordUpdateOptions = {
  readonly password: string;
  readonly options?: {
    readonly captchaToken?: string;
  };
};

/**
 * Email verification options
 */
export type EmailVerificationOptions = {
  readonly email: string;
  readonly token: string;
  readonly type: 'signup' | 'recovery' | 'email_change';
};

/**
 * OAuth provider options
 */
export type OAuthOptions = {
  readonly provider:
    | 'google'
    | 'github'
    | 'discord'
    | 'facebook'
    | 'twitter'
    | 'apple';
  readonly options?: {
    readonly redirectTo?: string;
    readonly scopes?: string;
    readonly queryParams?: Record<string, string>;
  };
};

/**
 * Session data returned from authentication
 */
export type SessionData = {
  readonly access_token: string;
  readonly refresh_token: string;
  readonly expires_in: number;
  readonly expires_at?: number;
  readonly token_type: 'bearer';
  readonly user: {
    readonly id: string;
    readonly email?: string;
    readonly phone?: string;
    readonly email_confirmed_at?: string;
    readonly phone_confirmed_at?: string;
    readonly app_metadata: Record<string, unknown>;
    readonly user_metadata: Record<string, unknown>;
    readonly aud: string;
    readonly created_at: string;
  };
};

/**
 * Authentication result
 */
export type AuthResult =
  | {
      readonly success: true;
      readonly session: SessionData;
      readonly user: SessionData['user'];
    }
  | {
      readonly success: false;
      readonly error: SDKError;
    };

/**
 * Express middleware types - minimal types to avoid Express dependency
 */
export type ExpressRequest = {
  readonly headers: Record<string, string | string[] | undefined>;
  user?: AuthContext;
  session?: { readonly access_token: string };
};

export type ExpressResponse = {
  readonly status: (code: number) => ExpressResponse;
  readonly json: (data: unknown) => void;
  readonly setHeader: (name: string, value: string) => void;
};

export type ExpressNextFunction = () => void;

/**
 * JWKS Client types
 */
export type JWKSClient = {
  readonly getSigningKey: (kid: string) => Promise<{
    readonly getPublicKey: () => string;
  }>;
};

export type JWKSClientModule = {
  readonly default?: (options: {
    readonly jwksUri: string;
    readonly cache: boolean;
  }) => JWKSClient;
} & ((options: {
  readonly jwksUri: string;
  readonly cache: boolean;
}) => JWKSClient);
