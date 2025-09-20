/**
 * JWKS Client utility for dynamic loading and management
 */

import type { JWKSClientModule } from './types';
import { ConfigError } from './errors';

let jwksClientModule: JWKSClientModule | null = null;

/**
 * Get JWKS client module with dynamic import
 * Handles both CommonJS and ESM module formats
 */
export async function getJwksClient(): Promise<JWKSClientModule> {
  if (!jwksClientModule) {
    const dynamicImport = new Function('specifier', 'return import(specifier)');
    jwksClientModule = await dynamicImport('jwks-client');

    if (!jwksClientModule) {
      throw new ConfigError(
        'Failed to load JWKS client module',
        'JWKS_MODULE_LOAD_ERROR',
        'The jwks-client module could not be loaded',
        'Check that jwks-client is properly installed'
      );
    }
  }
  return jwksClientModule;
}
