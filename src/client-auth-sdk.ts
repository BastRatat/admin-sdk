/**
 * ClientAuthSDK class for client-side authentication operations
 */

import { createClient } from "@supabase/supabase-js";
import type {
  ClientAuthConfig,
  SignupOptions,
  SigninOptions,
  PasswordResetOptions,
  PasswordUpdateOptions,
  EmailVerificationOptions,
  OAuthOptions,
  AuthResult,
  SessionData,
  Logger,
} from "./types";
import { ClientAuthError } from "./types";

/**
 * ClientAuthSDK for client-side authentication operations
 *
 * This class provides a wrapper around Supabase's client-side auth API
 * for user authentication, session management, and OAuth operations.
 * It should be used in client applications (web, mobile, etc.).
 */
export class ClientAuthSDK {
  private readonly supabase;
  private readonly logger?: Logger;

  constructor(config: ClientAuthConfig) {
    this.logger = config.logger;

    // Validate configuration
    this.validateConfig(config);

    // Create Supabase client with anon key
    this.supabase = createClient(config.supabaseUrl, config.supabaseAnonKey, {
      auth: {
        autoRefreshToken: true,
        persistSession: true,
        detectSessionInUrl: true,
      },
    });
  }

  /**
   * Sign up a new user with email and password
   */
  async signup(options: SignupOptions): Promise<AuthResult> {
    try {
      const { data, error } = await this.supabase.auth.signUp({
        email: options.email,
        password: options.password,
        options: options.options,
      });

      if (error) {
        this.logger?.error("Signup failed", {
          email: options.email,
          error: error.message,
        });
        return {
          success: false,
          error: new ClientAuthError(
            "Signup failed",
            "SIGNUP_ERROR",
            error.message,
            "Check email format and password requirements"
          ),
        };
      }

      this.logger?.info("User signed up successfully", {
        userId: data.user?.id,
        email: options.email,
      });

      return {
        success: true,
        session: data.session as SessionData,
        user: data.user as SessionData["user"],
      };
    } catch (error) {
      this.logger?.error("Signup error", {
        email: options.email,
        error: error instanceof Error ? error.message : "Unknown error",
      });
      return {
        success: false,
        error: new ClientAuthError(
          "Signup failed",
          "SIGNUP_ERROR",
          error instanceof Error ? error.message : "Unknown error",
          "Check network connection and try again"
        ),
      };
    }
  }

  /**
   * Sign in with email and password
   */
  async signin(options: SigninOptions): Promise<AuthResult> {
    try {
      const { data, error } = await this.supabase.auth.signInWithPassword({
        email: options.email,
        password: options.password,
        options: options.options,
      });

      if (error) {
        this.logger?.error("Signin failed", {
          email: options.email,
          error: error.message,
        });
        return {
          success: false,
          error: new ClientAuthError(
            "Signin failed",
            "SIGNIN_ERROR",
            error.message,
            "Check email and password"
          ),
        };
      }

      this.logger?.info("User signed in successfully", {
        userId: data.user?.id,
        email: options.email,
      });

      return {
        success: true,
        session: data.session as SessionData,
        user: data.user as SessionData["user"],
      };
    } catch (error) {
      this.logger?.error("Signin error", {
        email: options.email,
        error: error instanceof Error ? error.message : "Unknown error",
      });
      return {
        success: false,
        error: new ClientAuthError(
          "Signin failed",
          "SIGNIN_ERROR",
          error instanceof Error ? error.message : "Unknown error",
          "Check network connection and try again"
        ),
      };
    }
  }

  /**
   * Sign out the current user
   */
  async signout(): Promise<{ success: boolean; error?: ClientAuthError }> {
    try {
      const { error } = await this.supabase.auth.signOut();

      if (error) {
        this.logger?.error("Signout failed", {
          error: error.message,
        });
        return {
          success: false,
          error: new ClientAuthError(
            "Signout failed",
            "SIGNOUT_ERROR",
            error.message,
            "Try refreshing the page"
          ),
        };
      }

      this.logger?.info("User signed out successfully");
      return { success: true };
    } catch (error) {
      this.logger?.error("Signout error", {
        error: error instanceof Error ? error.message : "Unknown error",
      });
      return {
        success: false,
        error: new ClientAuthError(
          "Signout failed",
          "SIGNOUT_ERROR",
          error instanceof Error ? error.message : "Unknown error",
          "Try refreshing the page"
        ),
      };
    }
  }

  /**
   * Get the current session
   */
  async getSession(): Promise<{
    session: SessionData | null;
    error?: ClientAuthError;
  }> {
    try {
      const { data, error } = await this.supabase.auth.getSession();

      if (error) {
        this.logger?.error("Get session failed", {
          error: error.message,
        });
        return {
          session: null,
          error: new ClientAuthError(
            "Failed to get session",
            "SESSION_ERROR",
            error.message,
            "Try signing in again"
          ),
        };
      }

      return { session: data.session as SessionData | null };
    } catch (error) {
      this.logger?.error("Get session error", {
        error: error instanceof Error ? error.message : "Unknown error",
      });
      return {
        session: null,
        error: new ClientAuthError(
          "Failed to get session",
          "SESSION_ERROR",
          error instanceof Error ? error.message : "Unknown error",
          "Try signing in again"
        ),
      };
    }
  }

  /**
   * Refresh the current session
   */
  async refreshSession(): Promise<AuthResult> {
    try {
      const { data, error } = await this.supabase.auth.refreshSession();

      if (error) {
        this.logger?.error("Refresh session failed", {
          error: error.message,
        });
        return {
          success: false,
          error: new ClientAuthError(
            "Session refresh failed",
            "REFRESH_ERROR",
            error.message,
            "User needs to sign in again"
          ),
        };
      }

      this.logger?.info("Session refreshed successfully", {
        userId: data.user?.id,
      });

      return {
        success: true,
        session: data.session as SessionData,
        user: data.user as SessionData["user"],
      };
    } catch (error) {
      this.logger?.error("Refresh session error", {
        error: error instanceof Error ? error.message : "Unknown error",
      });
      return {
        success: false,
        error: new ClientAuthError(
          "Session refresh failed",
          "REFRESH_ERROR",
          error instanceof Error ? error.message : "Unknown error",
          "User needs to sign in again"
        ),
      };
    }
  }

  /**
   * Send password reset email
   */
  async resetPassword(
    options: PasswordResetOptions
  ): Promise<{ success: boolean; error?: ClientAuthError }> {
    try {
      const { error } = await this.supabase.auth.resetPasswordForEmail(
        options.email,
        options.options
      );

      if (error) {
        this.logger?.error("Password reset failed", {
          email: options.email,
          error: error.message,
        });
        return {
          success: false,
          error: new ClientAuthError(
            "Password reset failed",
            "PASSWORD_RESET_ERROR",
            error.message,
            "Check email address and try again"
          ),
        };
      }

      this.logger?.info("Password reset email sent", {
        email: options.email,
      });

      return { success: true };
    } catch (error) {
      this.logger?.error("Password reset error", {
        email: options.email,
        error: error instanceof Error ? error.message : "Unknown error",
      });
      return {
        success: false,
        error: new ClientAuthError(
          "Password reset failed",
          "PASSWORD_RESET_ERROR",
          error instanceof Error ? error.message : "Unknown error",
          "Check network connection and try again"
        ),
      };
    }
  }

  /**
   * Update user password
   */
  async updatePassword(
    options: PasswordUpdateOptions
  ): Promise<{ success: boolean; error?: ClientAuthError }> {
    try {
      const { error } = await this.supabase.auth.updateUser({
        password: options.password,
      });

      if (error) {
        this.logger?.error("Password update failed", {
          error: error.message,
        });
        return {
          success: false,
          error: new ClientAuthError(
            "Password update failed",
            "PASSWORD_UPDATE_ERROR",
            error.message,
            "Check password requirements"
          ),
        };
      }

      this.logger?.info("Password updated successfully");
      return { success: true };
    } catch (error) {
      this.logger?.error("Password update error", {
        error: error instanceof Error ? error.message : "Unknown error",
      });
      return {
        success: false,
        error: new ClientAuthError(
          "Password update failed",
          "PASSWORD_UPDATE_ERROR",
          error instanceof Error ? error.message : "Unknown error",
          "Check network connection and try again"
        ),
      };
    }
  }

  /**
   * Verify email with token
   */
  async verifyEmail(options: EmailVerificationOptions): Promise<AuthResult> {
    try {
      const { data, error } = await this.supabase.auth.verifyOtp({
        email: options.email,
        token: options.token,
        type: options.type,
      });

      if (error) {
        this.logger?.error("Email verification failed", {
          email: options.email,
          type: options.type,
          error: error.message,
        });
        return {
          success: false,
          error: new ClientAuthError(
            "Email verification failed",
            "EMAIL_VERIFICATION_ERROR",
            error.message,
            "Check the verification link or request a new one"
          ),
        };
      }

      this.logger?.info("Email verified successfully", {
        userId: data.user?.id,
        email: options.email,
        type: options.type,
      });

      return {
        success: true,
        session: data.session as SessionData,
        user: data.user as SessionData["user"],
      };
    } catch (error) {
      this.logger?.error("Email verification error", {
        email: options.email,
        type: options.type,
        error: error instanceof Error ? error.message : "Unknown error",
      });
      return {
        success: false,
        error: new ClientAuthError(
          "Email verification failed",
          "EMAIL_VERIFICATION_ERROR",
          error instanceof Error ? error.message : "Unknown error",
          "Check network connection and try again"
        ),
      };
    }
  }

  /**
   * Sign in with OAuth provider
   */
  async signInWithOAuth(
    options: OAuthOptions
  ): Promise<{ success: boolean; error?: ClientAuthError }> {
    try {
      const { error } = await this.supabase.auth.signInWithOAuth({
        provider: options.provider,
        options: options.options,
      });

      if (error) {
        this.logger?.error("OAuth signin failed", {
          provider: options.provider,
          error: error.message,
        });
        return {
          success: false,
          error: new ClientAuthError(
            "OAuth signin failed",
            "OAUTH_ERROR",
            error.message,
            "Check OAuth provider configuration"
          ),
        };
      }

      this.logger?.info("OAuth signin initiated", {
        provider: options.provider,
      });

      return { success: true };
    } catch (error) {
      this.logger?.error("OAuth signin error", {
        provider: options.provider,
        error: error instanceof Error ? error.message : "Unknown error",
      });
      return {
        success: false,
        error: new ClientAuthError(
          "OAuth signin failed",
          "OAUTH_ERROR",
          error instanceof Error ? error.message : "Unknown error",
          "Check network connection and try again"
        ),
      };
    }
  }

  /**
   * Get the current user
   */
  async getCurrentUser(): Promise<{
    user: SessionData["user"] | null;
    error?: ClientAuthError;
  }> {
    try {
      const { data, error } = await this.supabase.auth.getUser();

      if (error) {
        this.logger?.error("Get user failed", {
          error: error.message,
        });
        return {
          user: null,
          error: new ClientAuthError(
            "Failed to get user",
            "USER_ERROR",
            error.message,
            "User may not be authenticated"
          ),
        };
      }

      return { user: data.user as SessionData["user"] | null };
    } catch (error) {
      this.logger?.error("Get user error", {
        error: error instanceof Error ? error.message : "Unknown error",
      });
      return {
        user: null,
        error: new ClientAuthError(
          "Failed to get user",
          "USER_ERROR",
          error instanceof Error ? error.message : "Unknown error",
          "User may not be authenticated"
        ),
      };
    }
  }

  /**
   * Listen to auth state changes
   */
  onAuthStateChange(
    callback: (event: string, session: SessionData | null) => void
  ) {
    return this.supabase.auth.onAuthStateChange((event, session) => {
      this.logger?.info("Auth state changed", {
        event,
        userId: session?.user?.id,
      });
      callback(event, session as SessionData | null);
    });
  }

  /**
   * Validate client configuration
   */
  private validateConfig(config: ClientAuthConfig): void {
    if (!config.supabaseUrl) {
      throw new ClientAuthError(
        "Missing Supabase URL",
        "MISSING_URL",
        "Supabase URL is required",
        "Set the Supabase project URL in SDK configuration"
      );
    }

    if (!config.supabaseAnonKey) {
      throw new ClientAuthError(
        "Missing Supabase anon key",
        "MISSING_ANON_KEY",
        "Supabase anon key is required for client operations",
        "Set the Supabase anon key in SDK configuration"
      );
    }

    // Basic validation that this looks like an anon key
    if (!config.supabaseAnonKey.startsWith("eyJ")) {
      throw new ClientAuthError(
        "Invalid anon key format",
        "INVALID_ANON_KEY",
        "Anon key should be a JWT token",
        "Check the Supabase anon key format"
      );
    }

    // Ensure we're not accidentally using the service role key
    if (config.supabaseAnonKey.includes("service_role")) {
      throw new ClientAuthError(
        "Service role key detected",
        "SERVICE_KEY_USED",
        "Use anon key for client operations, not service role key",
        "Use the anon/public key for client-side operations"
      );
    }
  }
}
