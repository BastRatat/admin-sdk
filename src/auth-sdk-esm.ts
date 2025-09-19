/**
 * Core AuthSDK class for JWT verification and authorization
 */

import jwt from "jsonwebtoken";
import jwksClient from "jwks-client";
import {
  type AuthConfig,
  type AuthContext,
  type JWTPayload,
  type TokenVerificationResult,
  type AssertionOptions,
  type RoleAssertionOptions,
  type AALAssertionOptions,
  AuthError,
  PermissionError,
  TokenFreshnessError,
  ConfigError,
  type Logger,
} from "./types";

// ESM version with proper jwks-client import
function createJwksClient(jwksUri: string) {
  return jwksClient({
    jwksUri,
    cache: false,
  });
}

/**
 * Main AuthSDK class for token verification and authorization
 */
export class AuthSDK {
  private readonly config: AuthConfig;
  private readonly jwksClient: any;
  private readonly logger?: Logger;

  constructor(config: AuthConfig) {
    this.config = config;
    this.logger = config.logger;

    // Validate configuration
    this.validateConfig();

    // Initialize JWKS client
    this.jwksClient = createJwksClient(config.jwksUri);
  }

  /**
   * Verify JWT token and return normalized auth context
   */
  async verifyToken(token: string): Promise<TokenVerificationResult> {
    try {
      // Parse token header to get key ID
      const header = this.parseTokenHeader(token);

      // Get signing key from JWKS
      const signingKey = await this.getSigningKey(header.kid ?? "");

      // Verify token signature and parse payload
      const payload = jwt.verify(token, signingKey, {
        algorithms: ["RS256"],
        issuer: this.config.issuer,
        audience: Array.isArray(this.config.expectedAudience)
          ? this.config.expectedAudience[0]
          : this.config.expectedAudience,
        clockTolerance: this.config.clockSkewTolerance ?? 30,
      }) as unknown as JWTPayload;

      // Validate standard claims
      this.validateStandardClaims(payload);

      // Create normalized auth context
      const context = this.normalizeClaims(payload);

      // Log successful verification
      this.logger?.info("Token verified successfully", {
        userId: context.userId,
        sessionId: context.sessionId,
        serviceName: this.config.serviceName,
        decision: "allow",
      });

      return { success: true, context };
    } catch (error) {
      return this.handleVerificationError(error);
    }
  }

  /**
   * Assert that user has access to the current service
   */
  async assertAppAccess(
    context: AuthContext,
    options: AssertionOptions = {}
  ): Promise<void> {
    const logger = options.logger ?? this.logger;

    if (!context.apps.includes(this.config.serviceName)) {
      const error = new PermissionError(
        "User not authorized for this service",
        "APP_ACCESS_DENIED",
        `User ${context.userId} not member of service ${this.config.serviceName}`,
        "Add user to service membership or check service configuration"
      );

      logger?.warn("App access denied", {
        userId: context.userId,
        serviceName: this.config.serviceName,
        userApps: context.apps,
        decision: "deny",
        reason: error.reason,
      });

      throw error;
    }

    // Optional session existence check
    if (options.requireSession && context.sessionId) {
      await this.checkSessionExists(context.sessionId, logger);
    }

    logger?.info("App access granted", {
      userId: context.userId,
      serviceName: this.config.serviceName,
      decision: "allow",
    });
  }

  /**
   * Assert that user has specific role
   */
  async assertRole(
    context: AuthContext,
    role: string,
    options: RoleAssertionOptions = {}
  ): Promise<void> {
    const logger = options.logger ?? this.logger;
    const appScoped = options.appScoped ?? true;

    let userRole: string | undefined;

    if (appScoped) {
      userRole = context.roles[this.config.serviceName];
    } else {
      // Check if user has role in any app
      userRole = Object.values(context.roles).find((r) => r === role);
    }

    if (userRole !== role) {
      const error = new PermissionError(
        "Insufficient role permissions",
        "ROLE_ACCESS_DENIED",
        `User ${context.userId} has role '${userRole}' but '${role}' required`,
        "Assign required role to user or check role configuration"
      );

      logger?.warn("Role access denied", {
        userId: context.userId,
        requiredRole: role,
        userRole,
        serviceName: this.config.serviceName,
        decision: "deny",
        reason: error.reason,
      });

      throw error;
    }

    // Optional session existence check
    if (options.requireSession && context.sessionId) {
      await this.checkSessionExists(context.sessionId, logger);
    }

    logger?.info("Role access granted", {
      userId: context.userId,
      role,
      serviceName: this.config.serviceName,
      decision: "allow",
    });
  }

  /**
   * Assert Authentication Assurance Level (AAL)
   */
  async assertAAL(
    context: AuthContext,
    requiredAAL: "aal1" | "aal2" | "aal3",
    options: AALAssertionOptions = {}
  ): Promise<void> {
    const logger = options.logger ?? this.logger;
    const allowHigher = options.allowHigher ?? true;

    const userAAL = context.aal ?? "aal1";

    if (!this.isAALSufficient(userAAL, requiredAAL, allowHigher)) {
      const error = new TokenFreshnessError(
        "Insufficient authentication assurance level",
        "AAL_REQUIREMENT_NOT_MET",
        `User AAL '${userAAL}' does not meet requirement '${requiredAAL}'`,
        "User must authenticate with higher assurance level (e.g., MFA)"
      );

      logger?.warn("AAL requirement not met", {
        userId: context.userId,
        requiredAAL,
        userAAL,
        decision: "deny",
        reason: error.reason,
      });

      throw error;
    }

    logger?.info("AAL requirement satisfied", {
      userId: context.userId,
      requiredAAL,
      userAAL,
      decision: "allow",
    });
  }

  /**
   * Parse JWT header without verification
   */
  private parseTokenHeader(token: string): jwt.JwtHeader {
    try {
      const parts = token.split(".");
      if (parts.length !== 3) {
        throw new AuthError(
          "Invalid token format",
          "INVALID_TOKEN_FORMAT",
          "JWT must have exactly 3 parts separated by dots",
          "Ensure the token is a valid JWT"
        );
      }

      const header = JSON.parse(Buffer.from(parts[0]!, "base64url").toString());

      if (header.typ !== "JWT") {
        throw new AuthError(
          "Invalid token type",
          "INVALID_TOKEN_TYPE",
          `Expected JWT, got ${header.typ}`,
          "Ensure the token is a valid JWT"
        );
      }

      return header;
    } catch (error) {
      if (error instanceof AuthError) {
        throw error;
      }
      throw new AuthError(
        "Invalid token header",
        "INVALID_TOKEN_HEADER",
        "Token header is not valid JSON",
        "Ensure the token is a valid JWT"
      );
    }
  }

  /**
   * Get signing key from JWKS
   */
  private async getSigningKey(kid: string): Promise<string> {
    try {
      const key = await this.jwksClient.getSigningKey(kid);
      return key.getPublicKey();
    } catch (error) {
      this.logger?.error("Failed to get signing key", {
        kid,
        error: error instanceof Error ? error.message : "Unknown error",
      });
      throw new AuthError(
        "Invalid token signature",
        "JWKS_KEY_NOT_FOUND",
        `Key ID ${kid} not found in JWKS`,
        "Verify the token was issued by the correct Supabase project"
      );
    }
  }

  /**
   * Validate standard JWT claims
   */
  private validateStandardClaims(payload: JWTPayload): void {
    // Check role
    if (payload.role !== "authenticated") {
      throw new AuthError(
        "Invalid token role",
        "INVALID_TOKEN_ROLE",
        `Expected 'authenticated', got '${payload.role}'`,
        "Token must be issued for authenticated users"
      );
    }

    // Check expiration with clock skew tolerance
    const now = Math.floor(Date.now() / 1000);
    const clockSkew = this.config.clockSkewTolerance ?? 30;

    if (payload.exp < now - clockSkew) {
      throw new AuthError(
        "Token expired",
        "TOKEN_EXPIRED",
        `Token expired at ${new Date(payload.exp * 1000).toISOString()}`,
        "Request a new token or refresh the current one"
      );
    }

    // Check issued at time (not in the future beyond clock skew)
    if (payload.iat > now + clockSkew) {
      throw new AuthError(
        "Token issued in the future",
        "INVALID_IAT",
        `Token issued at ${new Date(payload.iat * 1000).toISOString()}`,
        "Check system clock synchronization"
      );
    }
  }

  /**
   * Normalize JWT claims into AuthContext
   */
  private normalizeClaims(payload: JWTPayload): AuthContext {
    const appMetadata = payload.app_metadata ?? {};
    const apps = appMetadata.apps ?? [];
    const roles = appMetadata.roles ?? {};
    const isServiceAccount = appMetadata.is_service_account ?? false;

    return {
      userId: payload.sub,
      email: payload.email,
      phone: payload.phone,
      sessionId: payload.session_id,
      apps: Object.freeze([...apps]),
      roles: Object.freeze({ ...roles }),
      isServiceAccount,
      aal: payload.aal,
      issuedAt: new Date(payload.iat * 1000),
      expiresAt: new Date(payload.exp * 1000),
      rawClaims: Object.freeze({ ...payload }),
    };
  }

  /**
   * Check if AAL level is sufficient
   */
  private isAALSufficient(
    userAAL: string,
    requiredAAL: string,
    allowHigher: boolean
  ): boolean {
    const aalLevels = { aal1: 1, aal2: 2, aal3: 3 };
    const userLevel = aalLevels[userAAL as keyof typeof aalLevels] ?? 1;
    const requiredLevel = aalLevels[requiredAAL as keyof typeof aalLevels] ?? 1;

    if (allowHigher) {
      return userLevel >= requiredLevel;
    }
    return userLevel === requiredLevel;
  }

  /**
   * Check if session still exists (for instant logout effect)
   */
  private async checkSessionExists(
    sessionId: string,
    logger?: Logger
  ): Promise<void> {
    if (typeof this.config.sessionCheck === "function") {
      try {
        const exists = await this.config.sessionCheck(sessionId);
        if (!exists) {
          throw new TokenFreshnessError(
            "Session no longer exists",
            "SESSION_REVOKED",
            `Session ${sessionId} has been revoked`,
            "User must re-authenticate"
          );
        }
      } catch (error) {
        logger?.error("Session check failed", {
          sessionId,
          error: error instanceof Error ? error.message : "Unknown error",
        });
        throw error;
      }
    }
  }

  /**
   * Handle verification errors and convert to appropriate SDK errors
   */
  private handleVerificationError(error: unknown): TokenVerificationResult {
    if (error instanceof AuthError || error instanceof ConfigError) {
      this.logger?.error("Token verification failed", {
        error: error.message,
        reason: error.reason,
        decision: "deny",
      });
      return { success: false, error };
    }

    if (error instanceof jwt.JsonWebTokenError) {
      const authError = new AuthError(
        "Invalid token",
        "INVALID_TOKEN",
        error.message,
        "Verify the token is valid and not tampered with"
      );

      this.logger?.error("JWT verification failed", {
        error: error.message,
        reason: authError.reason,
        decision: "deny",
      });

      return { success: false, error: authError };
    }

    if (error instanceof jwt.TokenExpiredError) {
      const authError = new AuthError(
        "Token expired",
        "TOKEN_EXPIRED",
        `Token expired at ${error.expiredAt.toISOString()}`,
        "Request a new token or refresh the current one"
      );

      this.logger?.error("Token expired", {
        expiredAt: error.expiredAt.toISOString(),
        reason: authError.reason,
        decision: "deny",
      });

      return { success: false, error: authError };
    }

    if (error instanceof jwt.NotBeforeError) {
      const authError = new AuthError(
        "Token not yet valid",
        "TOKEN_NOT_ACTIVE",
        `Token valid from ${error.date.toISOString()}`,
        "Wait until the token becomes valid"
      );

      this.logger?.error("Token not yet valid", {
        validFrom: error.date.toISOString(),
        reason: authError.reason,
        decision: "deny",
      });

      return { success: false, error: authError };
    }

    // Unknown error
    const authError = new AuthError(
      "Token verification failed",
      "UNKNOWN_ERROR",
      error instanceof Error ? error.message : "Unknown error occurred",
      "Check token validity and system configuration"
    );

    this.logger?.error("Unknown verification error", {
      error: error instanceof Error ? error.message : "Unknown error",
      reason: authError.reason,
      decision: "deny",
    });

    return { success: false, error: authError };
  }

  /**
   * Validate SDK configuration
   */
  private validateConfig(): void {
    if (!this.config.issuer) {
      throw new ConfigError(
        "Missing issuer configuration",
        "MISSING_ISSUER",
        "Issuer URL is required",
        "Set the Supabase Auth URL in SDK configuration"
      );
    }

    if (!this.config.jwksUri) {
      throw new ConfigError(
        "Missing JWKS URI configuration",
        "MISSING_JWKS_URI",
        "JWKS URI is required for token verification",
        "Set the JWKS endpoint URL in SDK configuration"
      );
    }

    if (!this.config.serviceName) {
      throw new ConfigError(
        "Missing service name configuration",
        "MISSING_SERVICE_NAME",
        "Service name is required for app membership checks",
        "Set the current microservice name in SDK configuration"
      );
    }
  }
}
