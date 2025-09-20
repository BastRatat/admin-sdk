/**
 * Error classes for Supabase Auth SDK
 */

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
  readonly code = 'AUTH_ERROR';
  readonly statusCode = 401;

  constructor(
    message: string,
    readonly reason: string,
    readonly hint?: string,
    readonly remediation?: string
  ) {
    super(message);
    this.name = 'AuthError';
  }
}

/**
 * Permission error - valid token but insufficient permissions
 */
export class PermissionError extends SDKError {
  readonly code = 'PERMISSION_ERROR';
  readonly statusCode = 403;

  constructor(
    message: string,
    readonly reason: string,
    readonly hint?: string,
    readonly remediation?: string
  ) {
    super(message);
    this.name = 'PermissionError';
  }
}

/**
 * Token freshness error - session revoked or AAL requirements not met
 */
export class TokenFreshnessError extends SDKError {
  readonly code = 'TOKEN_FRESHNESS_ERROR';
  readonly statusCode = 401;

  constructor(
    message: string,
    readonly reason: string,
    readonly hint?: string,
    readonly remediation?: string
  ) {
    super(message);
    this.name = 'TokenFreshnessError';
  }
}

/**
 * Configuration error - invalid SDK setup
 */
export class ConfigError extends SDKError {
  readonly code = 'CONFIG_ERROR';
  readonly statusCode = 500;

  constructor(
    message: string,
    readonly reason: string,
    readonly hint?: string,
    readonly remediation?: string
  ) {
    super(message);
    this.name = 'ConfigError';
  }
}

/**
 * Client authentication error
 */
export class ClientAuthError extends SDKError {
  readonly code = 'CLIENT_AUTH_ERROR';
  readonly statusCode = 400;

  constructor(
    message: string,
    readonly reason: string,
    readonly hint?: string,
    readonly remediation?: string
  ) {
    super(message);
    this.name = 'ClientAuthError';
  }
}
