/**
 * Example usage of @admin-sdk/auth
 */

import { AuthSDK, AdminSDK } from "./dist/index.js";

// Example: AuthSDK usage in a microservice
const authSDK = new AuthSDK({
  issuer: "https://your-project.supabase.co/auth/v1",
  jwksUri: "https://your-project.supabase.co/auth/v1/jwks",
  expectedAudience: "authenticated",
  serviceName: "billing-service",
  logger: {
    info: (msg, meta) => console.log(`[INFO] ${msg}`, meta),
    warn: (msg, meta) => console.warn(`[WARN] ${msg}`, meta),
    error: (msg, meta) => console.error(`[ERROR] ${msg}`, meta),
    debug: (msg, meta) => console.debug(`[DEBUG] ${msg}`, meta),
  },
});

// Example: Verify token and check permissions
async function handleRequest(authHeader: string) {
  try {
    const token = authHeader.replace("Bearer ", "");

    // Verify token
    const result = await authSDK.verifyToken(token);
    if (!result.success) {
      throw result.error;
    }

    const context = result.context;

    // Check app access
    await authSDK.assertAppAccess(context);

    // Check role
    await authSDK.assertRole(context, "admin");

    // Check AAL for sensitive operations
    await authSDK.assertAAL(context, "aal2");

    return { success: true, user: context };
  } catch (error) {
    return { success: false, error };
  }
}

// Example: AdminSDK usage on server
const adminSDK = new AdminSDK({
  supabaseUrl: "https://your-project.supabase.co",
  supabaseKey: process.env.SUPABASE_SERVICE_ROLE_KEY!,
});

// Example: Create user with app membership
async function createUserWithAccess(
  email: string,
  apps: string[],
  role: string
) {
  const user = await adminSDK.createUser({
    email,
    emailConfirm: true,
    appMetadata: {
      apps,
      roles: { [apps[0]]: role },
      is_service_account: false,
    },
  });

  return user;
}

export { handleRequest, createUserWithAccess };
