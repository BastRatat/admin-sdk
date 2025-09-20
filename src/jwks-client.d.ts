declare module 'jwks-client' {
  interface JwksClient {
    getSigningKey(kid: string): Promise<{ getPublicKey(): string }>;
    getSigningKeys(): Promise<unknown[]>;
  }

  interface JwksClientOptions {
    jwksUri: string;
    cache?: boolean;
    cacheMaxAge?: number;
    cacheMaxEntries?: number;
    jwksRequestsPerMinute?: number;
    jwksRequestsPerMinutePerKey?: number;
    requestHeaders?: Record<string, string>;
  }

  function jwksClient(options: JwksClientOptions): JwksClient;
  export = jwksClient;
}
