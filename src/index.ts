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
  AdminConfig,
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
} from "./types";

// Core auth functionality
export { AuthSDK } from "./auth-sdk";

// Admin functionality
export { AdminSDK } from "./admin-sdk";
