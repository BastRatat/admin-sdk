/**
 * Main entry point for @admin-sdk/auth
 *
 * Unified TypeScript SDK for Supabase Auth verification, RBAC, and admin operations
 */

// Core types
export type {
  JWTHeader,
  StandardClaims,
  SupabaseClaims,
  JWTPayload,
  AuthContext,
  AuthConfig,
  MicroserviceAuthConfig,
  AdminConfig,
  ClientAuthConfig,
  SignupOptions,
  SigninOptions,
  PasswordResetOptions,
  PasswordUpdateOptions,
  EmailVerificationOptions,
  OAuthOptions,
  SessionData,
  AuthResult,
  MicroserviceSignupOptions,
  MicroserviceSigninOptions,
  ServiceManagementOptions,
  MicroserviceMiddlewareOptions,
  SessionCheckFunction,
  Logger,
  LogMeta,
  AssertionOptions,
  RoleAssertionOptions,
  AALAssertionOptions,
  TokenVerificationResult,
  UserCreateOptions,
  UserInviteOptions,
  JWK,
  JWKSResponse,
} from "./types";

// Error classes
export {
  SDKError,
  AuthError,
  PermissionError,
  TokenFreshnessError,
  ConfigError,
  ClientAuthError,
} from "./types";

// Core auth functionality
export { AuthSDK } from "./auth-sdk";

// Admin functionality
export { AdminSDK } from "./admin-sdk";

// Client auth functionality
export { ClientAuthSDK } from "./client-auth-sdk";

// Microservice auth functionality (RECOMMENDED)
export { MicroserviceAuthSDK } from "./microservice-auth-sdk";
