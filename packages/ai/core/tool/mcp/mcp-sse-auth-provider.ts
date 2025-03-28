import pkceChallenge from 'pkce-challenge';
import { LATEST_PROTOCOL_VERSION } from './types';

// TODO: ZOD schema parsing, or alternative schema validation

export interface OAuthClientProvider {
  get redirectUrl(): string | URL;

  get clientMetadata(): OAuthClientMetadata;

  clientInformation():
    | OAuthClientInformation
    | undefined
    | Promise<OAuthClientInformation | undefined>;

  saveClientInformation?(
    clientInformation: OAuthClientInformationFull,
  ): void | Promise<void>;

  tokens(): OAuthToken | undefined | Promise<OAuthToken | undefined>;

  saveTokens(tokens: OAuthToken): void | Promise<void>;

  redirectToAuthorization(authorizationUrl: URL): void | Promise<void>;

  saveCodeVerifier(codeVerifier: string): void | Promise<void>;

  codeVerifier(): string | Promise<string>;
}

export class MCPOAuthProvider implements OAuthClientProvider {
  private clientInfo: OAuthClientInformationFull | undefined;
  private _tokens: OAuthToken | undefined;
  private _codeVerifier: string | undefined;
  private redirectUri: string;
  private _clientMetadata: OAuthClientMetadata;

  constructor({
    redirectUri,
    clientMetadata,
  }: {
    redirectUri: string;
    clientMetadata: OAuthClientMetadata;
  }) {
    this.redirectUri = redirectUri;
    this._clientMetadata = clientMetadata;
  }

  get redirectUrl(): string {
    return this.redirectUri;
  }

  get clientMetadata(): OAuthClientMetadata {
    return this._clientMetadata;
  }

  async clientInformation(): Promise<OAuthClientInformation | undefined> {
    return this.clientInfo;
  }

  async saveClientInformation(info: OAuthClientInformationFull): Promise<void> {
    this.clientInfo = info;
    // TODO: Save to persistent storage
    console.log('Save these credentials:', {
      CLIENT_ID: info.client_id,
      CLIENT_SECRET: info.client_secret,
    });
  }

  async tokens(): Promise<OAuthToken | undefined> {
    return this._tokens;
  }

  async saveTokens(tokens: OAuthToken): Promise<void> {
    this._tokens = tokens;
    // TODO: Save to session or other secure storage
    console.log('Save tokens:', tokens);
  }

  async saveCodeVerifier(verifier: string): Promise<void> {
    this._codeVerifier = verifier;
    // TODO: Save to session
    console.log('Save code verifier:', verifier);
  }

  async codeVerifier(): Promise<string> {
    if (!this._codeVerifier) {
      throw new Error('No code verifier saved');
    }
    return this._codeVerifier;
  }

  async redirectToAuthorization(url: URL): Promise<void> {
    console.log('Redirecting to authorization:', url);
    throw new Response(null, {
      status: 302,
      headers: { Location: url.toString() },
    });
  }
}

interface OAuthClientMetadata {
  redirect_uris: string[];
  token_endpoint_auth_method?: string;
  grant_types?: string[];
  response_types?: string[];
  client_name?: string;
  client_uri?: string;
  logo_uri?: string;
  scope?: string;
  contacts?: string[];
  tos_uri?: string;
  policy_uri?: string;
  jwks_uri?: string;
  jwks?: any;
  software_id?: string;
  software_version?: string;
}

interface OAuthClientInformation {
  client_id: string;
  client_secret?: string;
  client_id_issued_at?: number;
  client_secret_expires_at?: number;
}

type OAuthClientInformationFull = OAuthClientInformation & OAuthClientMetadata;

interface OAuthToken {
  access_token: string;
  token_type: string;
  expires_in?: number;
  refresh_token?: string;
  scope?: string;
}

interface OAuth2ServerMetadata {
  // Required fields per MCP spec
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;

  // Required supported methods per MCP spec
  response_types_supported: string[]; // Must include 'code'
  grant_types_supported: string[]; // Must include 'authorization_code', 'refresh_token'
  token_endpoint_auth_methods_supported: string[]; // Must include 'client_secret_basic', 'client_secret_post', 'none'
  code_challenge_methods_supported: string[]; // Must include 'plain', 'S256'

  // Optional but recommended per MCP spec
  registration_endpoint?: string; // For dynamic client registration
  scopes_supported?: string[];
  response_modes_supported?: string[]; // Should include 'query'
  revocation_endpoint?: string;

  // MCP specific fields
  service_documentation?: string; // MCP service documentation URL

  // Additional standard OAuth fields that might be useful
  jwks_uri?: string;
  token_endpoint_auth_signing_alg_values_supported?: string[];
  revocation_endpoint_auth_methods_supported?: string[];
}

type AuthResult = 'AUTHORIZED' | 'REDIRECT';

export class UnauthorizedError extends Error {
  constructor(message?: string) {
    super(message ?? 'Unauthorized');
  }
}

export async function authorize({
  provider,
  serverUrl,
  authorizationCode,
}: {
  provider: OAuthClientProvider;
  serverUrl: string | URL;
  authorizationCode?: string;
}): Promise<AuthResult> {
  const metadata = await discoverOAuthMetadata(serverUrl);
  console.log('[Auth] Metadata:', metadata);

  let clientInformation = await Promise.resolve(provider.clientInformation());
  if (!clientInformation) {
    if (authorizationCode !== undefined) {
      throw new Error(
        'Existing OAuth client information is required when exchanging an authorization code',
      );
    }

    if (!provider.saveClientInformation) {
      throw new Error(
        'OAuth client information must be saveable for dynamic registration',
      );
    }

    const fullInformation = await registerClient(serverUrl, {
      metadata,
      clientMetadata: provider.clientMetadata,
    });

    await provider.saveClientInformation(fullInformation);
    clientInformation = fullInformation;
  }

  if (authorizationCode !== undefined) {
    const codeVerifier = await provider.codeVerifier();
    const tokens = await exchangeAuthorization(serverUrl, {
      metadata,
      clientInformation,
      authorizationCode,
      codeVerifier,
    });

    await provider.saveTokens(tokens);
    return 'AUTHORIZED';
  }

  const tokens = await provider.tokens();

  if (tokens?.refresh_token) {
    try {
      const newTokens = await refreshAuthorization(serverUrl, {
        metadata,
        clientInformation,
        refreshToken: tokens.refresh_token,
      });

      await provider.saveTokens(newTokens);
      return 'AUTHORIZED';
    } catch (error) {
      console.error('Could not refresh OAuth tokens:', error);
    }
  }

  const { authorizationUrl, codeVerifier } = await startAuthorization(
    serverUrl,
    {
      metadata,
      clientInformation,
      redirectUrl: provider.redirectUrl,
    },
  );

  await provider.saveCodeVerifier(codeVerifier);
  await provider.redirectToAuthorization(authorizationUrl);
  return 'REDIRECT';
}

export async function discoverOAuthMetadata(
  serverUrl: string | URL,
  opts?: { protocolVersion?: string },
): Promise<OAuth2ServerMetadata | undefined> {
  const url = new URL('/.well-known/oauth-authorization-server', serverUrl);
  let response: Response;
  try {
    response = await fetch(url, {
      headers: {
        'MCP-Protocol-Version':
          opts?.protocolVersion ?? LATEST_PROTOCOL_VERSION,
      },
    });
  } catch (error) {
    // CORS errors come back as TypeError
    if (error instanceof TypeError) {
      response = await fetch(url);
    } else {
      throw error;
    }
  }

  if (response.status === 404) {
    return undefined;
  }

  if (!response.ok) {
    throw new Error(
      `HTTP ${response.status} trying to load well-known OAuth metadata`,
    );
  }

  return response.json();
}

export async function startAuthorization(
  serverUrl: string | URL,
  {
    metadata,
    clientInformation,
    redirectUrl,
  }: {
    metadata?: OAuth2ServerMetadata;
    clientInformation: OAuthClientInformation;
    redirectUrl: string | URL;
  },
): Promise<{ authorizationUrl: URL; codeVerifier: string }> {
  const responseType = 'code';
  const codeChallengeMethod = 'S256';

  let authorizationUrl: URL;
  if (metadata) {
    authorizationUrl = new URL(metadata.authorization_endpoint);

    if (!metadata.response_types_supported.includes(responseType)) {
      throw new Error(
        `Incompatible auth server: does not support response type ${responseType}`,
      );
    }

    if (
      !metadata.code_challenge_methods_supported ||
      !metadata.code_challenge_methods_supported.includes(codeChallengeMethod)
    ) {
      throw new Error(
        `Incompatible auth server: does not support code challenge method ${codeChallengeMethod}`,
      );
    }
  } else {
    authorizationUrl = new URL('/authorize', serverUrl);
  }

  // Generate PKCE challenge
  const challenge = await pkceChallenge();
  const codeVerifier = challenge.code_verifier;
  const codeChallenge = challenge.code_challenge;

  authorizationUrl.searchParams.set('response_type', responseType);
  authorizationUrl.searchParams.set('client_id', clientInformation.client_id);
  authorizationUrl.searchParams.set('code_challenge', codeChallenge);
  authorizationUrl.searchParams.set(
    'code_challenge_method',
    codeChallengeMethod,
  );
  authorizationUrl.searchParams.set('redirect_uri', String(redirectUrl));

  return { authorizationUrl, codeVerifier };
}

export async function exchangeAuthorization(
  serverUrl: string | URL,
  {
    metadata,
    clientInformation,
    authorizationCode,
    codeVerifier,
  }: {
    metadata?: OAuth2ServerMetadata;
    clientInformation: OAuthClientInformation;
    authorizationCode: string;
    codeVerifier: string;
  },
): Promise<OAuthToken> {
  const grantType = 'authorization_code';

  let tokenUrl: URL;
  if (metadata) {
    tokenUrl = new URL(metadata.token_endpoint);

    if (
      metadata.grant_types_supported &&
      !metadata.grant_types_supported.includes(grantType)
    ) {
      throw new Error(
        `Incompatible auth server: does not support grant type ${grantType}`,
      );
    }
  } else {
    tokenUrl = new URL('/token', serverUrl);
  }

  const params = new URLSearchParams({
    grant_type: grantType,
    client_id: clientInformation.client_id,
    code: authorizationCode,
    code_verifier: codeVerifier,
  });

  if (clientInformation.client_secret) {
    params.set('client_secret', clientInformation.client_secret);
  }

  const response = await fetch(tokenUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: params,
  });

  if (!response.ok) {
    throw new Error(`Token exchange failed: HTTP ${response.status}`);
  }

  return response.json();
}

export async function refreshAuthorization(
  serverUrl: string | URL,
  {
    metadata,
    clientInformation,
    refreshToken,
  }: {
    metadata?: OAuth2ServerMetadata;
    clientInformation: OAuthClientInformation;
    refreshToken: string;
  },
): Promise<OAuthToken> {
  const grantType = 'refresh_token';

  let tokenUrl: URL;
  if (metadata) {
    tokenUrl = new URL(metadata.token_endpoint);

    if (
      metadata.grant_types_supported &&
      !metadata.grant_types_supported.includes(grantType)
    ) {
      throw new Error(
        `Incompatible auth server: does not support grant type ${grantType}`,
      );
    }
  } else {
    tokenUrl = new URL('/token', serverUrl);
  }

  // Exchange refresh token
  const params = new URLSearchParams({
    grant_type: grantType,
    client_id: clientInformation.client_id,
    refresh_token: refreshToken,
  });

  if (clientInformation.client_secret) {
    params.set('client_secret', clientInformation.client_secret);
  }

  const response = await fetch(tokenUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: params,
  });

  if (!response.ok) {
    throw new Error(`Token refresh failed: HTTP ${response.status}`);
  }

  return response.json();
}

export async function registerClient(
  serverUrl: string | URL,
  {
    metadata,
    clientMetadata,
  }: {
    metadata?: OAuth2ServerMetadata;
    clientMetadata: OAuthClientMetadata;
  },
): Promise<OAuthClientInformationFull> {
  let registrationUrl: URL;

  if (metadata) {
    if (!metadata.registration_endpoint) {
      throw new Error(
        'Incompatible auth server: does not support dynamic client registration',
      );
    }

    registrationUrl = new URL(metadata.registration_endpoint);
  } else {
    registrationUrl = new URL('/register', serverUrl);
  }

  const response = await fetch(registrationUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(clientMetadata),
  });

  if (!response.ok) {
    throw new Error(
      `Dynamic client registration failed: HTTP ${response.status}`,
    );
  }

  return response.json();
}
