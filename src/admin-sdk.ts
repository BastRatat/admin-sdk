/**
 * AdminSDK class for Supabase Admin API operations
 */

import { createClient } from "@supabase/supabase-js";
import type {
  AdminConfig,
  UserCreateOptions,
  UserInviteOptions,
  Logger,
} from "./types";

/**
 * AdminSDK for server-side Supabase Admin API operations
 *
 * This class provides a thin wrapper around Supabase's Admin API
 * for user management operations. It should only be used on trusted servers
 * with the service role key.
 */
export class AdminSDK {
  private readonly supabase;
  private readonly logger?: Logger;

  constructor(config: AdminConfig, logger?: Logger) {
    this.logger = logger;

    // Validate configuration
    this.validateConfig(config);

    // Create Supabase client with service role key
    this.supabase = createClient(config.supabaseUrl, config.supabaseKey, {
      auth: {
        autoRefreshToken: false,
        persistSession: false,
      },
    });
  }

  /**
   * Create a new user
   */
  async createUser(options: UserCreateOptions) {
    try {
      const { data, error } = await this.supabase.auth.admin.createUser({
        email: options.email,
        password: options.password,
        email_confirm: options.emailConfirm ?? false,
        ...(options.appMetadata && { app_metadata: options.appMetadata }),
        ...(options.userMetadata && { user_metadata: options.userMetadata }),
      });

      if (error) {
        this.logger?.error("Failed to create user", {
          email: options.email,
          error: error.message,
        });
        throw new Error(`Failed to create user: ${error.message}`);
      }

      this.logger?.info("User created successfully", {
        userId: data.user?.id,
        email: options.email,
      });

      return data.user;
    } catch (error) {
      this.logger?.error("User creation failed", {
        email: options.email,
        error: error instanceof Error ? error.message : "Unknown error",
      });
      throw error;
    }
  }

  /**
   * Invite a user via email
   */
  async inviteUser(options: UserInviteOptions) {
    try {
      const { data, error } = await this.supabase.auth.admin.inviteUserByEmail(
        options.email,
        {
          ...(options.redirectTo && { redirectTo: options.redirectTo }),
          ...(options.data && { data: options.data }),
        }
      );

      if (error) {
        this.logger?.error("Failed to invite user", {
          email: options.email,
          error: error.message,
        });
        throw new Error(`Failed to invite user: ${error.message}`);
      }

      this.logger?.info("User invited successfully", {
        userId: data.user?.id,
        email: options.email,
      });

      return data.user;
    } catch (error) {
      this.logger?.error("User invitation failed", {
        email: options.email,
        error: error instanceof Error ? error.message : "Unknown error",
      });
      throw error;
    }
  }

  /**
   * Delete a user
   */
  async deleteUser(userId: string) {
    try {
      const { error } = await this.supabase.auth.admin.deleteUser(userId);

      if (error) {
        this.logger?.error("Failed to delete user", {
          userId,
          error: error.message,
        });
        throw new Error(`Failed to delete user: ${error.message}`);
      }

      this.logger?.info("User deleted successfully", {
        userId,
      });

      return true;
    } catch (error) {
      this.logger?.error("User deletion failed", {
        userId,
        error: error instanceof Error ? error.message : "Unknown error",
      });
      throw error;
    }
  }

  /**
   * Get user by ID
   */
  async getUser(userId: string) {
    try {
      const { data, error } =
        await this.supabase.auth.admin.getUserById(userId);

      if (error) {
        this.logger?.error("Failed to get user", {
          userId,
          error: error.message,
        });
        throw new Error(`Failed to get user: ${error.message}`);
      }

      return data.user;
    } catch (error) {
      this.logger?.error("Get user failed", {
        userId,
        error: error instanceof Error ? error.message : "Unknown error",
      });
      throw error;
    }
  }

  /**
   * Update user metadata
   */
  async updateUserMetadata(userId: string, metadata: Record<string, unknown>) {
    try {
      const { data, error } = await this.supabase.auth.admin.updateUserById(
        userId,
        { user_metadata: metadata }
      );

      if (error) {
        this.logger?.error("Failed to update user metadata", {
          userId,
          error: error.message,
        });
        throw new Error(`Failed to update user metadata: ${error.message}`);
      }

      this.logger?.info("User metadata updated successfully", {
        userId,
      });

      return data.user;
    } catch (error) {
      this.logger?.error("User metadata update failed", {
        userId,
        error: error instanceof Error ? error.message : "Unknown error",
      });
      throw error;
    }
  }

  /**
   * Update user app metadata
   */
  async updateUserAppMetadata(
    userId: string,
    appMetadata: Record<string, unknown>
  ) {
    try {
      const { data, error } = await this.supabase.auth.admin.updateUserById(
        userId,
        { app_metadata: appMetadata }
      );

      if (error) {
        this.logger?.error("Failed to update user app metadata", {
          userId,
          error: error.message,
        });
        throw new Error(`Failed to update user app metadata: ${error.message}`);
      }

      this.logger?.info("User app metadata updated successfully", {
        userId,
      });

      return data.user;
    } catch (error) {
      this.logger?.error("User app metadata update failed", {
        userId,
        error: error instanceof Error ? error.message : "Unknown error",
      });
      throw error;
    }
  }

  /**
   * List users with pagination
   */
  async listUsers(page = 1, perPage = 50) {
    try {
      const { data, error } = await this.supabase.auth.admin.listUsers({
        page,
        perPage,
      });

      if (error) {
        this.logger?.error("Failed to list users", {
          page,
          perPage,
          error: error.message,
        });
        throw new Error(`Failed to list users: ${error.message}`);
      }

      this.logger?.info("Users listed successfully", {
        page,
        perPage,
        count: data.users?.length ?? 0,
      });

      return data;
    } catch (error) {
      this.logger?.error("List users failed", {
        page,
        perPage,
        error: error instanceof Error ? error.message : "Unknown error",
      });
      throw error;
    }
  }

  /**
   * Generate a link for password reset
   */
  async generatePasswordResetLink(email: string, redirectTo?: string) {
    try {
      const { data, error } = await this.supabase.auth.admin.generateLink({
        type: "recovery",
        email,
        ...(redirectTo && { options: { redirectTo } }),
      });

      if (error) {
        this.logger?.error("Failed to generate password reset link", {
          email,
          error: error.message,
        });
        throw new Error(
          `Failed to generate password reset link: ${error.message}`
        );
      }

      this.logger?.info("Password reset link generated successfully", {
        email,
      });

      return data.properties?.action_link;
    } catch (error) {
      this.logger?.error("Password reset link generation failed", {
        email,
        error: error instanceof Error ? error.message : "Unknown error",
      });
      throw error;
    }
  }

  /**
   * Validate admin configuration
   */
  private validateConfig(config: AdminConfig): void {
    if (!config.supabaseUrl) {
      throw new Error("Supabase URL is required");
    }

    if (!config.supabaseKey) {
      throw new Error("Supabase service role key is required");
    }

    // Basic validation that this looks like a service role key
    if (!config.supabaseKey.startsWith("eyJ")) {
      throw new Error("Invalid service role key format");
    }

    // Ensure we're not accidentally using the anon key
    if (config.supabaseKey.includes("anon")) {
      throw new Error("Service role key required, not anon key");
    }
  }
}
