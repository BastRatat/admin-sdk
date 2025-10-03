import { createClient } from '@supabase/supabase-js';
import jwt from 'jsonwebtoken';
import type {
  AuthConfig,
  SignupOptions,
  SigninOptions,
  ServiceManagementOptions,
  OAuthMetadataOptions,
  MicroserviceMiddlewareOptions,
  AuthContext,
  JWTPayload,
  TokenVerificationResult,
  SessionData,
  Logger,
  User,
  ExpressRequest,
  ExpressResponse,
  ExpressNextFunction,
  JWKSClient,
} from './types';
import { AuthError, PermissionError, ConfigError } from './errors';
import { getJwksClient } from './jwks-client';
import { isValidLanguageCode } from './language-utils';

/**
 * AuthSDK for server-side microservice authentication
 *
 * This class provides centralized user management across multiple microservices
 * using Supabase Auth with service-scoped access control.
 */
export class AuthSDK {
  private readonly config: AuthConfig;
  private readonly supabase;
  private jwksClient: JWKSClient | null = null;
  private readonly logger?: Logger;

  private static AUTH_CONFIG = {
    autoRefreshToken: false,
    persistSession: false,
  };

  private static PASSWORD_MIN_LENGTH = 6;

  constructor(config: AuthConfig) {
    this.config = config;
    this.logger = config.logger;

    this.validateConfig();

    this.supabase = createClient(
      config.supabaseUrl,
      config.supabaseServiceKey,
      {
        auth: AuthSDK.AUTH_CONFIG,
      }
    );
  }

  /**
   * Sign up a new user and grant access to current service
   */
  public async signUp(
    options: SignupOptions
  ): Promise<
    { success: true; user: User } | { success: false; error: AuthError }
  > {
    try {
      this.validateSignupOptions(options);

      const user = {
        email: options.email,
        password: options.password,
        email_confirm: true,
        app_metadata: {
          services: [this.config.serviceName],
          roles: {
            [this.config.serviceName]: 'user',
          },
        },
        user_metadata: {
          ...options.userData,
          last_seen: new Date().toISOString(),
        },
      };

      const { data, error } = await this.supabase.auth.admin.createUser(user);

      if (error) {
        this.logger?.error('User signup failed', {
          email: options.email,
          serviceName: this.config.serviceName,
          error: error.message,
        });
        return {
          success: false,
          error: new AuthError(
            'Signup failed',
            'SIGNUP_ERROR',
            error.message,
            'Check email format and password requirements'
          ),
        };
      }

      this.logger?.info('User signed up successfully', {
        userId: data.user?.id,
        email: options.email,
        serviceName: this.config.serviceName,
      });

      return {
        success: true,
        user: data.user as User,
      };
    } catch (error) {
      this.logger?.error('Signup error', {
        email: options.email,
        serviceName: this.config.serviceName,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      return {
        success: false,
        error: new AuthError(
          'Signup failed',
          'SIGNUP_ERROR',
          error instanceof Error ? error.message : 'Unknown error',
          'Check network connection and try again'
        ),
      };
    }
  }

  /**
   * Sign in user and verify service access
   */
  public async signIn(
    options: SigninOptions
  ): Promise<
    | { success: true; user: User; session: SessionData | null }
    | { success: false; error: AuthError | PermissionError }
  > {
    try {
      this.validateSigninOptions(options);

      const { data, error } = await this.supabase.auth.signInWithPassword({
        email: options.email,
        password: options.password,
      });

      if (error) {
        this.logger?.error('User signin failed', {
          email: options.email,
          serviceName: this.config.serviceName,
          error: error.message,
        });
        return {
          success: false,
          error: new AuthError(
            'Signin failed',
            'SIGNIN_ERROR',
            error.message,
            'Check email and password'
          ),
        };
      }

      const userServices = data.user?.app_metadata?.services || [];
      if (!userServices.includes(this.config.serviceName)) {
        this.logger?.warn('User signin denied - no service access', {
          userId: data.user?.id,
          email: options.email,
          serviceName: this.config.serviceName,
          userServices,
        });
        return {
          success: false,
          error: new PermissionError(
            'Access denied to service',
            'SERVICE_ACCESS_DENIED',
            `User not authorized for service: ${this.config.serviceName}`,
            'Contact administrator to grant service access'
          ),
        };
      }

      await this.updateUserLastSeen(data.user.id);

      this.logger?.info('User signed in successfully', {
        userId: data.user?.id,
        email: options.email,
        serviceName: this.config.serviceName,
      });

      return {
        success: true,
        user: data.user as User,
        session: data.session as SessionData | null,
      };
    } catch (error) {
      this.logger?.error('Signin error', {
        email: options.email,
        serviceName: this.config.serviceName,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      return {
        success: false,
        error: new AuthError(
          'Signin failed',
          'SIGNIN_ERROR',
          error instanceof Error ? error.message : 'Unknown error',
          'Check network connection and try again'
        ),
      };
    }
  }

  /**
   * Verify JWT token and check service access
   */
  public async verifyToken(token: string): Promise<TokenVerificationResult> {
    try {
      const header = this.parseTokenHeader(token);

      this.logger?.debug('Using JWKS verification for token', {
        kid: header.kid,
        algorithm: header.alg,
      });

      const signingKey = await this.getSigningKey(header.kid ?? '', header.alg);

      const algs = header.alg?.startsWith('HS')
        ? (['HS256', 'HS384', 'HS512'] as jwt.Algorithm[])
        : (['RS256', 'RS384', 'RS512'] as jwt.Algorithm[]);

      const payload = jwt.verify(token, signingKey, {
        algorithms: algs,
        issuer: this.config.issuer,
        audience: Array.isArray(this.config.expectedAudience)
          ? this.config.expectedAudience[0]
          : (this.config.expectedAudience ?? 'authenticated'),
        clockTolerance: this.config.clockSkewTolerance ?? 30,
      }) as unknown as JWTPayload;

      this.validateStandardClaims(payload);

      const context = this.normalizeClaims(payload);

      if (!context.apps.includes(this.config.serviceName)) {
        this.logger?.warn('Token verification denied - no service access', {
          userId: context.userId,
          serviceName: this.config.serviceName,
          userServices: context.apps,
        });
        return {
          success: false,
          error: new PermissionError(
            'Access denied to service',
            'SERVICE_ACCESS_DENIED',
            `User not authorized for service: ${this.config.serviceName}`,
            'Contact administrator to grant service access'
          ),
        };
      }

      this.logger?.info('Token verified successfully', {
        userId: context.userId,
        sessionId: context.sessionId,
        serviceName: this.config.serviceName,
        decision: 'allow',
      });

      return { success: true, context };
    } catch (error) {
      return this.handleVerificationError(error);
    }
  }

  /**
   * Sign out user (revoke session)
   */
  public async signOut(
    userId: string
  ): Promise<{ success: boolean; error?: AuthError }> {
    try {
      const { error } = await this.supabase.auth.admin.signOut(userId);

      if (error) {
        this.logger?.error('User signout failed', {
          userId,
          serviceName: this.config.serviceName,
          error: error.message,
        });
        return {
          success: false,
          error: new AuthError(
            'Signout failed',
            'SIGNOUT_ERROR',
            error.message,
            'Try refreshing the page'
          ),
        };
      }

      this.logger?.info('User signed out successfully', {
        userId,
        serviceName: this.config.serviceName,
      });

      return { success: true };
    } catch (error) {
      this.logger?.error('Signout error', {
        userId,
        serviceName: this.config.serviceName,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      return {
        success: false,
        error: new AuthError(
          'Signout failed',
          'SIGNOUT_ERROR',
          error instanceof Error ? error.message : 'Unknown error',
          'Try refreshing the page'
        ),
      };
    }
  }

  /**
   * Add user to a service
   */
  public async addUserToService(
    options: ServiceManagementOptions
  ): Promise<{ success: boolean; error?: AuthError }> {
    try {
      const { data: userData, error: getUserError } =
        await this.supabase.auth.admin.getUserById(options.userId);

      if (getUserError) {
        return {
          success: false,
          error: new AuthError(
            'Failed to get user',
            'USER_NOT_FOUND',
            getUserError.message,
            'Check user ID'
          ),
        };
      }

      const currentServices = userData.user?.app_metadata?.services || [];
      const currentRoles = userData.user?.app_metadata?.roles || {};

      if (!currentServices.includes(options.serviceName)) {
        const updatedServices = [...currentServices, options.serviceName];
        const updatedRoles = {
          ...currentRoles,
          [options.serviceName]: options.role || 'user',
        };

        const { error: updateError } =
          await this.supabase.auth.admin.updateUserById(options.userId, {
            app_metadata: {
              services: updatedServices,
              roles: updatedRoles,
            },
          });

        if (updateError) {
          return {
            success: false,
            error: new AuthError(
              'Failed to add user to service',
              'SERVICE_ADD_ERROR',
              updateError.message,
              'Check service name and try again'
            ),
          };
        }
      }

      this.logger?.info('User added to service', {
        userId: options.userId,
        serviceName: options.serviceName,
        role: options.role || 'user',
      });

      return { success: true };
    } catch (error) {
      this.logger?.error('Add user to service error', {
        userId: options.userId,
        serviceName: options.serviceName,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      return {
        success: false,
        error: new AuthError(
          'Failed to add user to service',
          'SERVICE_ADD_ERROR',
          error instanceof Error ? error.message : 'Unknown error',
          'Check network connection and try again'
        ),
      };
    }
  }

  /**
   * Remove user from a service
   */
  public async removeUserFromService(
    options: ServiceManagementOptions
  ): Promise<{ success: boolean; error?: AuthError }> {
    try {
      const { data: userData, error: getUserError } =
        await this.supabase.auth.admin.getUserById(options.userId);

      if (getUserError) {
        return {
          success: false,
          error: new AuthError(
            'Failed to get user',
            'USER_NOT_FOUND',
            getUserError.message,
            'Check user ID'
          ),
        };
      }

      const currentServices = userData.user?.app_metadata?.services || [];
      const currentRoles = userData.user?.app_metadata?.roles || {};

      if (currentServices.includes(options.serviceName)) {
        const updatedServices = currentServices.filter(
          (service: string) => service !== options.serviceName
        );
        const updatedRoles = { ...currentRoles };
        delete updatedRoles[options.serviceName];

        const { error: updateError } =
          await this.supabase.auth.admin.updateUserById(options.userId, {
            app_metadata: {
              services: updatedServices,
              roles: updatedRoles,
            },
          });

        if (updateError) {
          return {
            success: false,
            error: new AuthError(
              'Failed to remove user from service',
              'SERVICE_REMOVE_ERROR',
              updateError.message,
              'Check service name and try again'
            ),
          };
        }
      }

      this.logger?.info('User removed from service', {
        userId: options.userId,
        serviceName: options.serviceName,
      });

      return { success: true };
    } catch (error) {
      this.logger?.error('Remove user from service error', {
        userId: options.userId,
        serviceName: options.serviceName,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      return {
        success: false,
        error: new AuthError(
          'Failed to remove user from service',
          'SERVICE_REMOVE_ERROR',
          error instanceof Error ? error.message : 'Unknown error',
          'Check network connection and try again'
        ),
      };
    }
  }

  /**
   * Get user's services
   */
  public async getUserServices(userId: string): Promise<{
    services: string[];
    roles: Record<string, string>;
    error?: AuthError;
  }> {
    try {
      const { data: userData, error: getUserError } =
        await this.supabase.auth.admin.getUserById(userId);

      if (getUserError) {
        return {
          services: [],
          roles: {},
          error: new AuthError(
            'Failed to get user',
            'USER_NOT_FOUND',
            getUserError.message,
            'Check user ID'
          ),
        };
      }

      const services = userData.user?.app_metadata?.services || [];
      const roles = userData.user?.app_metadata?.roles || {};

      return { services, roles };
    } catch (error) {
      this.logger?.error('Get user services error', {
        userId,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      return {
        services: [],
        roles: {},
        error: new AuthError(
          'Failed to get user services',
          'GET_SERVICES_ERROR',
          error instanceof Error ? error.message : 'Unknown error',
          'Check network connection and try again'
        ),
      };
    }
  }

  /**
   * Update OAuth user metadata with service information
   *
   * This method is used to add service_name to OAuth users
   * who signed up through external providers (Google, GitHub, etc.)
   */
  public async updateOAuthUserMetadata(
    options: OAuthMetadataOptions
  ): Promise<{ success: boolean; error?: AuthError }> {
    try {
      // Validate ISO 639-1 language code
      if (!isValidLanguageCode(options.language)) {
        this.logger?.error('Invalid language code provided', {
          userId: options.userId,
          serviceName: options.serviceName,
          language: options.language,
        });
        return {
          success: false,
          error: new AuthError(
            'Invalid language code',
            'INVALID_LANGUAGE_CODE',
            `Language code '${options.language}' is not a valid ISO 639-1 code`,
            'Use a valid 2-character language code (e.g., "en", "fr", "es")'
          ),
        };
      }
      const { data: userData, error: getUserError } =
        await this.supabase.auth.admin.getUserById(options.userId);

      if (getUserError) {
        this.logger?.error('Failed to get OAuth user for metadata update', {
          userId: options.userId,
          serviceName: options.serviceName,
          error: getUserError.message,
        });
        return {
          success: false,
          error: new AuthError(
            'Failed to get user',
            'USER_NOT_FOUND',
            getUserError.message,
            'Check user ID'
          ),
        };
      }

      const currentUserMetadata = userData.user?.user_metadata || {};
      const currentAppMetadata = userData.user?.app_metadata || {};
      const currentServices = currentAppMetadata.services || [];
      const currentRoles = currentAppMetadata.roles || {};

      const updatedUserMetadata = {
        ...currentUserMetadata,
        service_name: options.serviceName,
        last_seen: new Date().toISOString(),
        language: options.language,
      };

      // Add service to app metadata if not already present
      const updatedServices = currentServices.includes(options.serviceName)
        ? currentServices
        : [...currentServices, options.serviceName];

      const updatedRoles = {
        ...currentRoles,
        [options.serviceName]: currentRoles[options.serviceName] || 'user',
      };

      const { error: updateError } =
        await this.supabase.auth.admin.updateUserById(options.userId, {
          user_metadata: updatedUserMetadata,
          app_metadata: {
            ...currentAppMetadata,
            services: updatedServices,
            roles: updatedRoles,
          },
        });

      if (updateError) {
        this.logger?.error('Failed to update OAuth user metadata', {
          userId: options.userId,
          serviceName: options.serviceName,
          error: updateError.message,
        });
        return {
          success: false,
          error: new AuthError(
            'Failed to update user metadata',
            'METADATA_UPDATE_ERROR',
            updateError.message,
            'Check user permissions and try again'
          ),
        };
      }

      this.logger?.info('OAuth user metadata updated successfully', {
        userId: options.userId,
        serviceName: options.serviceName,
      });

      return { success: true };
    } catch (error) {
      this.logger?.error('OAuth metadata update error', {
        userId: options.userId,
        serviceName: options.serviceName,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      return {
        success: false,
        error: new AuthError(
          'Failed to update OAuth user metadata',
          'OAUTH_METADATA_ERROR',
          error instanceof Error ? error.message : 'Unknown error',
          'Check network connection and try again'
        ),
      };
    }
  }

  /**
   * Create Express middleware for authentication
   */
  public middleware(options: MicroserviceMiddlewareOptions = {}) {
    const {
      requireAuth = true,
      requireRole,
      requireAAL,
      allowServiceAccounts = false,
      updateLastSeen = true,
    } = options;

    return async (
      req: ExpressRequest,
      res: ExpressResponse,
      next: ExpressNextFunction
    ) => {
      try {
        if (!requireAuth) {
          return next();
        }

        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-Frame-Options', 'DENY');
        res.setHeader('X-XSS-Protection', '1; mode=block');

        const authHeader = req.headers.authorization;
        if (
          !authHeader ||
          typeof authHeader !== 'string' ||
          !authHeader.startsWith('Bearer ')
        ) {
          return res.status(401).json({
            error: 'Missing or invalid authorization header',
            code: 'MISSING_TOKEN',
          });
        }

        const token = authHeader.substring(7); // Remove 'Bearer ' prefix

        const result = await this.verifyToken(token);
        if (!result.success) {
          return res.status(401).json({
            error: result.error.message,
            code: result.error.reason,
          });
        }

        const context = result.context;

        if (context.isServiceAccount && !allowServiceAccounts) {
          return res.status(403).json({
            error: 'Service accounts not allowed',
            code: 'SERVICE_ACCOUNT_DENIED',
          });
        }

        if (requireRole) {
          const userRole = context.roles[this.config.serviceName];
          if (userRole !== requireRole) {
            return res.status(403).json({
              error: `Required role: ${requireRole}, user role: ${userRole}`,
              code: 'INSUFFICIENT_ROLE',
            });
          }
        }

        if (requireAAL) {
          const userAAL = context.aal || 'aal1';
          const aalLevels = { aal1: 1, aal2: 2, aal3: 3 };
          const userLevel = aalLevels[userAAL as keyof typeof aalLevels] || 1;
          const requiredLevel = aalLevels[requireAAL];

          if (userLevel < requiredLevel) {
            return res.status(403).json({
              error: `Required AAL: ${requireAAL}, user AAL: ${userAAL}`,
              code: 'INSUFFICIENT_AAL',
            });
          }
        }

        if (updateLastSeen) {
          this.updateUserLastSeen(context.userId).catch(err => {
            this.logger?.warn('Failed to update last seen', {
              userId: context.userId,
              error: err.message,
            });
          });
        }

        // Attach user context to request
        req.user = context;
        req.session = { access_token: token };

        next();
      } catch (error) {
        this.logger?.error('Middleware error', {
          error: error instanceof Error ? error.message : 'Unknown error',
        });
        return res.status(500).json({
          error: 'Internal server error',
          code: 'MIDDLEWARE_ERROR',
        });
      }
    };
  }

  /**
   * Construct redirectTo URL with language parameter
   *
   * @param baseUrl - Base redirect URL
   * @param language - Language code to append as query parameter
   * @returns URL with language parameter appended
   *
   * @example
   * const url = authSDK.buildRedirectUrlWithLanguage(
   *   'https://myapp.com/reset-password',
   *   'fr'
   * );
   * // Returns: 'https://myapp.com/reset-password?lang=fr'
   */
  public buildRedirectUrlWithLanguage(
    baseUrl: string,
    language: string
  ): string {
    try {
      const url = new URL(baseUrl);
      url.searchParams.set('lang', language);
      return url.toString();
    } catch (error) {
      this.logger?.warn('Invalid base URL provided for redirect', {
        baseUrl,
        language,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      // Fallback: append language parameter manually
      const separator = baseUrl.includes('?') ? '&' : '?';
      return `${baseUrl}${separator}lang=${encodeURIComponent(language)}`;
    }
  }

  /**
   * Update user's last seen timestamp
   */
  private async updateUserLastSeen(userId: string): Promise<void> {
    try {
      const { data: userData } =
        await this.supabase.auth.admin.getUserById(userId);
      if (userData.user) {
        const currentMetadata = userData.user.user_metadata || {};
        await this.supabase.auth.admin.updateUserById(userId, {
          user_metadata: {
            ...currentMetadata,
            last_seen: new Date().toISOString(),
          },
        });
      }
    } catch (error) {
      // Don't throw - this is a non-critical operation
      this.logger?.warn('Failed to update last seen', {
        userId,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  }

  /**
   * Parse JWT header without verification
   */
  private parseTokenHeader(token: string): jwt.JwtHeader {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) {
        throw new AuthError(
          'Invalid token format',
          'INVALID_TOKEN_FORMAT',
          'JWT must have exactly 3 parts separated by dots',
          'Ensure the token is a valid JWT'
        );
      }

      const header = JSON.parse(
        Buffer.from(parts[0] || '', 'base64url').toString()
      );

      if (header.typ !== 'JWT') {
        throw new AuthError(
          'Invalid token type',
          'INVALID_TOKEN_TYPE',
          `Expected JWT, got ${header.typ}`,
          'Ensure the token is a valid JWT'
        );
      }

      return header;
    } catch (error) {
      if (error instanceof AuthError) {
        throw error;
      }
      throw new AuthError(
        'Invalid token header',
        'INVALID_TOKEN_HEADER',
        'Token header is not valid JSON',
        'Ensure the token is a valid JWT'
      );
    }
  }

  /**
   * Get signing key from JWKS or use service key for HMAC
   */
  private async getSigningKey(
    kid: string,
    algorithm?: string
  ): Promise<string | Buffer> {
    try {
      if (algorithm?.startsWith('HS')) {
        const secret = this.config.supabaseJwtSecret;
        if (!secret) {
          throw new ConfigError(
            'Missing legacy JWT secret',
            'MISSING_JWT_SECRET',
            'Set config.supabaseJwtSecret or SUPABASE_JWT_SECRET for HS256 verification',
            'In Supabase Studio: Project Settings → API → JWT Settings → JWT secret'
          );
        }

        this.logger?.debug('Using Legacy JWT secret for HS256 verification', {
          kid,
          algorithm,
          secretLength: secret.length,
        });

        const looksBase64 =
          /^[A-Za-z0-9_\-+/=]+$/.test(secret) && secret.length % 4 === 0;

        this.logger?.debug('Secret format analysis', {
          looksBase64,
          secretLength: secret.length,
          firstChars: secret.substring(0, 10),
        });

        this.logger?.debug('Using raw secret string');
        return secret;
      }

      if (!this.jwksClient) {
        const jwksClientModule = await getJwksClient();
        const clientFactory = jwksClientModule.default || jwksClientModule;
        this.jwksClient = clientFactory({
          jwksUri: this.config.jwksUri,
          cache: false,
        });
      }
      if (!this.jwksClient) {
        throw new ConfigError(
          'JWKS client not initialized',
          'JWKS_CLIENT_NOT_INITIALIZED',
          'JWKS client failed to initialize',
          'Check JWKS URI and network connectivity'
        );
      }
      const key = await this.jwksClient.getSigningKey(kid);
      return key.getPublicKey();
    } catch (error) {
      this.logger?.error('Failed to get signing key', {
        kid,
        algorithm,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      throw new AuthError(
        'Invalid token signature',
        'JWKS_KEY_NOT_FOUND',
        `Key ID ${kid} not found in JWKS`,
        'Verify the token was issued by the correct Supabase project'
      );
    }
  }

  /**
   * Validate standard JWT claims
   */
  private validateStandardClaims(payload: JWTPayload): void {
    if (payload.role !== 'authenticated') {
      throw new AuthError(
        'Invalid token role',
        'INVALID_TOKEN_ROLE',
        `Expected 'authenticated', got '${payload.role}'`,
        'Token must be issued for authenticated users'
      );
    }

    const now = Math.floor(Date.now() / 1000);
    const clockSkew = this.config.clockSkewTolerance ?? 30;

    if (payload.exp < now - clockSkew) {
      throw new AuthError(
        'Token expired',
        'TOKEN_EXPIRED',
        `Token expired at ${new Date(payload.exp * 1000).toISOString()}`,
        'Request a new token or refresh the current one'
      );
    }

    if (payload.iat > now + clockSkew) {
      throw new AuthError(
        'Token issued in the future',
        'INVALID_IAT',
        `Token issued at ${new Date(payload.iat * 1000).toISOString()}`,
        'Check system clock synchronization'
      );
    }
  }

  /**
   * Normalize JWT claims into AuthContext
   */
  private normalizeClaims(payload: JWTPayload): AuthContext {
    const appMetadata = payload.app_metadata ?? {};
    const apps = appMetadata.services ?? [];
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
   * Handle verification errors and convert to appropriate SDK errors
   */
  private handleVerificationError(error: unknown): TokenVerificationResult {
    if (
      error instanceof AuthError ||
      error instanceof PermissionError ||
      error instanceof ConfigError
    ) {
      this.logger?.error('Token verification failed', {
        error: error.message,
        reason: error.reason,
        decision: 'deny',
      });
      return { success: false, error };
    }

    if (error instanceof jwt.JsonWebTokenError) {
      const authError = new AuthError(
        'Invalid token',
        'INVALID_TOKEN',
        error.message,
        'Verify the token is valid and not tampered with'
      );

      this.logger?.error('JWT verification failed', {
        error: error.message,
        reason: authError.reason,
        decision: 'deny',
      });

      return { success: false, error: authError };
    }

    if (error instanceof jwt.TokenExpiredError) {
      const authError = new AuthError(
        'Token expired',
        'TOKEN_EXPIRED',
        `Token expired at ${error.expiredAt.toISOString()}`,
        'Request a new token or refresh the current one'
      );

      this.logger?.error('Token expired', {
        expiredAt: error.expiredAt.toISOString(),
        reason: authError.reason,
        decision: 'deny',
      });

      return { success: false, error: authError };
    }

    if (error instanceof jwt.NotBeforeError) {
      const authError = new AuthError(
        'Token not yet valid',
        'TOKEN_NOT_ACTIVE',
        `Token valid from ${error.date.toISOString()}`,
        'Wait until the token becomes valid'
      );

      this.logger?.error('Token not yet valid', {
        validFrom: error.date.toISOString(),
        reason: authError.reason,
        decision: 'deny',
      });

      return { success: false, error: authError };
    }

    // Unknown error
    const authError = new AuthError(
      'Token verification failed',
      'UNKNOWN_ERROR',
      error instanceof Error ? error.message : 'Unknown error occurred',
      'Check token validity and system configuration'
    );

    this.logger?.error('Unknown verification error', {
      error: error instanceof Error ? error.message : 'Unknown error',
      reason: authError.reason,
      decision: 'deny',
    });

    return { success: false, error: authError };
  }

  /**
   * Validate signup options
   */
  private validateSignupOptions(options: SignupOptions): void {
    if (!options.email || !this.isValidEmail(options.email)) {
      throw new AuthError(
        'Invalid email address',
        'INVALID_EMAIL',
        'Email must be a valid email address',
        'Provide a valid email address'
      );
    }

    if (
      !options.password ||
      options.password.length < AuthSDK.PASSWORD_MIN_LENGTH
    ) {
      throw new AuthError(
        'Invalid password',
        'INVALID_PASSWORD',
        `Password must be at least ${AuthSDK.PASSWORD_MIN_LENGTH} characters long`,
        'Provide a stronger password'
      );
    }
  }

  /**
   * Validate signin options
   */
  private validateSigninOptions(options: SigninOptions): void {
    if (!options.email || !this.isValidEmail(options.email)) {
      throw new AuthError(
        'Invalid email address',
        'INVALID_EMAIL',
        'Email must be a valid email address',
        'Provide a valid email address'
      );
    }

    if (!options.password) {
      throw new AuthError(
        'Password required',
        'MISSING_PASSWORD',
        'Password is required for signin',
        'Provide a password'
      );
    }
  }

  private isValidEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  /**
   * Send password reset email with optional language support
   *
   * @param email - User's email address
   * @param options - Configuration options including redirectTo and language
   * @param options.redirectTo - Base redirect URL (language will be appended as query param)
   * @param options.language - Language code (e.g., 'en', 'fr', 'es') to include in redirect URL
   *
   * @example
   * // Basic usage
   * await authSDK.forgotPassword('user@example.com', {
   *   redirectTo: 'https://myapp.com/reset-password'
   * });
   *
   * // With language support
   * await authSDK.forgotPassword('user@example.com', {
   *   redirectTo: 'https://myapp.com/reset-password',
   *   language: 'fr'
   * });
   * // Results in: https://myapp.com/reset-password?lang=fr
   */
  public async forgotPassword(
    email: string,
    options: { redirectTo: string; language: string }
  ): Promise<{ success: boolean; error?: AuthError }> {
    try {
      if (!this.isValidEmail(email)) {
        return {
          success: false,
          error: new AuthError(
            'Invalid email address',
            'INVALID_EMAIL',
            'Email must be a valid email address',
            'Provide a valid email address'
          ),
        };
      }

      const url = new URL(options.redirectTo);
      url.searchParams.set('lang', options.language);

      const { error } = await this.supabase.auth.resetPasswordForEmail(email, {
        redirectTo: url.toString(),
      });

      if (error) {
        this.logger?.error('Password reset email failed', {
          email,
          serviceName: this.config.serviceName,
          error: error.message,
        });
        return {
          success: false,
          error: new AuthError(
            'Failed to send password reset email',
            'PASSWORD_RESET_ERROR',
            error.message,
            'Check email address and try again'
          ),
        };
      }

      this.logger?.info('Password reset email sent successfully', {
        email,
        serviceName: this.config.serviceName,
      });

      return { success: true };
    } catch (error) {
      this.logger?.error('Password reset error', {
        email,
        serviceName: this.config.serviceName,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      return {
        success: false,
        error: new AuthError(
          'Password reset failed',
          'PASSWORD_RESET_ERROR',
          error instanceof Error ? error.message : 'Unknown error',
          'Check network connection and try again'
        ),
      };
    }
  }

  /**
   * Update user password using reset token
   */
  public async resetPassword(
    accessToken: string,
    refreshToken: string,
    newPassword: string
  ): Promise<{ success: boolean; error?: AuthError }> {
    try {
      if (!newPassword || newPassword.length < AuthSDK.PASSWORD_MIN_LENGTH) {
        return {
          success: false,
          error: new AuthError(
            'Invalid password',
            'INVALID_PASSWORD',
            `Password must be at least ${AuthSDK.PASSWORD_MIN_LENGTH} characters long`,
            'Provide a stronger password'
          ),
        };
      }

      // Set the session using the tokens from the reset link
      const { data, error: sessionError } = await this.supabase.auth.setSession(
        {
          access_token: accessToken,
          refresh_token: refreshToken,
        }
      );

      if (sessionError || !data.user) {
        this.logger?.error('Invalid reset session', {
          serviceName: this.config.serviceName,
          error: sessionError?.message || 'No user in session',
        });
        return {
          success: false,
          error: new AuthError(
            'Invalid or expired reset link',
            'INVALID_RESET_TOKEN',
            sessionError?.message || 'Reset link is invalid or expired',
            'Request a new password reset link'
          ),
        };
      }

      // Update the password
      const { error: updateError } = await this.supabase.auth.updateUser({
        password: newPassword,
      });

      if (updateError) {
        this.logger?.error('Password update failed', {
          userId: data.user.id,
          serviceName: this.config.serviceName,
          error: updateError.message,
        });
        return {
          success: false,
          error: new AuthError(
            'Failed to update password',
            'PASSWORD_UPDATE_ERROR',
            updateError.message,
            'Try again or request a new reset link'
          ),
        };
      }

      this.logger?.info('Password updated successfully', {
        userId: data.user.id,
        serviceName: this.config.serviceName,
      });

      return { success: true };
    } catch (error) {
      this.logger?.error('Password reset error', {
        serviceName: this.config.serviceName,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      return {
        success: false,
        error: new AuthError(
          'Password reset failed',
          'PASSWORD_RESET_ERROR',
          error instanceof Error ? error.message : 'Unknown error',
          'Check network connection and try again'
        ),
      };
    }
  }

  /**
   * Validate SDK configuration
   */
  private validateConfig(): void {
    if (!this.config.supabaseUrl) {
      throw new ConfigError(
        'Missing Supabase URL',
        'MISSING_SUPABASE_URL',
        'Supabase URL is required',
        'Set the Supabase project URL in SDK configuration'
      );
    }

    if (!this.config.supabaseServiceKey) {
      throw new ConfigError(
        'Missing Supabase service key',
        'MISSING_SERVICE_KEY',
        'Supabase service role key is required',
        'Set the Supabase service role key in SDK configuration'
      );
    }

    if (!this.config.issuer) {
      throw new ConfigError(
        'Missing issuer configuration',
        'MISSING_ISSUER',
        'Issuer URL is required',
        'Set the Supabase Auth URL in SDK configuration'
      );
    }

    if (!this.config.jwksUri) {
      throw new ConfigError(
        'Missing JWKS URI configuration',
        'MISSING_JWKS_URI',
        'JWKS URI is required for token verification',
        'Set the JWKS endpoint URL in SDK configuration'
      );
    }

    if (!this.config.serviceName) {
      throw new ConfigError(
        'Missing service name configuration',
        'MISSING_SERVICE_NAME',
        'Service name is required for microservice authentication',
        'Set the current microservice name in SDK configuration'
      );
    }
  }
}
