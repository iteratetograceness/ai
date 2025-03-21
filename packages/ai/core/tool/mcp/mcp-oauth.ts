import pkceChallenge from 'pkce-challenge';
import { MCPClientError } from '../../../errors';
import { LATEST_PROTOCOL_VERSION } from './types';

/**
 * Maps to `@modelcontextprotocol/sdk`'s end-to-end OAuth client
 */
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
  tokens(): OAuthTokens | undefined | Promise<OAuthTokens | undefined>;
  saveTokens(tokens: OAuthTokens): void | Promise<void>;
  redirectToAuthorization(authorizationUrl: URL): void | Promise<void>;
  saveCodeVerifier(codeVerifier: string): void | Promise<void>;
  codeVerifier(): string | Promise<string>;
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
  jwks?: unknown;
  software_id?: string;
  software_version?: string;
}

interface OAuthClientInformation {
  client_id: string;
  client_secret?: string;
  client_id_issued_at?: number;
  client_secret_expires_at?: number;
}

interface OAuthClientInformationFull
  extends OAuthClientMetadata,
    OAuthClientInformation {}

interface OAuthTokens {
  access_token: string;
  refresh_token?: string;
  token_type: string;
  expires_in?: number;
  scope?: string;
}

export interface OAuthMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  registration_endpoint?: string;
  scopes_supported?: string[];
  response_types_supported: string[];
  response_modes_supported?: string[];
  grant_types_supported?: string[];
  token_endpoint_auth_methods_supported?: string[];
  token_endpoint_auth_signing_alg_values_supported?: string[];
  service_documentation?: string;
  revocation_endpoint?: string;
  revocation_endpoint_auth_methods_supported?: string[];
  revocation_endpoint_auth_signing_alg_values_supported?: string[];
  introspection_endpoint?: string;
  introspection_endpoint_auth_methods_supported?: string[];
  introspection_endpoint_auth_signing_alg_values_supported?: string[];
  code_challenge_methods_supported?: string[];
  [key: string]: any;
}

export async function authenticateMCPClient({
  provider,
  serverUrl,
  authorizationCode,
}: {
  provider: OAuthClientProvider;
  serverUrl: string | URL;
  authorizationCode?: string;
}) {
  const metadata = await discoverOAuthMetadata(serverUrl);

  const clientInformation = await getClientInformation({
    provider,
    authorizationCode,
    serverUrl,
    metadata,
  });

  if (authorizationCode !== undefined) {
    const codeVerifier = await provider.codeVerifier();
    const tokens = await exchangeAuthorization({
      serverUrl,
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
      const newTokens = await refreshAuthorization({
        serverUrl,
        metadata,
        clientInformation,
        refreshToken: tokens.refresh_token,
      });

      await provider.saveTokens(newTokens);
      return 'AUTHORIZED';
    } catch (error) {
      // TODO: How/if at all do we want to report this refresh failure?
      console.error('Could not refresh OAuth tokens:', error);
    }
  }

  const { authorizationUrl, codeVerifier } = await startAuthorization({
    serverUrl,
    metadata,
    clientInformation,
    redirectUrl: provider.redirectUrl,
  });

  await provider.saveCodeVerifier(codeVerifier);
  await provider.redirectToAuthorization(authorizationUrl);
  return 'REDIRECT';
}

async function discoverOAuthMetadata(
  serverUrl: string | URL,
): Promise<OAuthMetadata | undefined> {
  const url = new URL('/.well-known/oauth-authorization-server', serverUrl);

  const response = await fetch(url, {
    headers: {
      'MCP-Protocol-Version': LATEST_PROTOCOL_VERSION,
    },
  });

  if (response.status === 404) {
    return undefined;
  }

  if (!response.ok) {
    throw new MCPClientError({
      message: `HTTP ${response.status} trying to load well-known OAuth metadata`,
      cause: response,
    });
  }

  return response.json();
}

async function registerClient({
  serverUrl,
  metadata,
  clientMetadata,
}: {
  serverUrl: string | URL;
  metadata?: OAuthMetadata;
  clientMetadata: OAuthClientMetadata;
}): Promise<OAuthClientInformationFull> {
  const registrationUrl = metadata?.registration_endpoint
    ? new URL(metadata.registration_endpoint)
    : new URL('/register', serverUrl);

  if (metadata && !metadata.registration_endpoint) {
    throw new MCPClientError({
      message: 'Auth server does not support dynamic client registration',
    });
  }

  const response = await fetch(registrationUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(clientMetadata),
  });

  if (!response.ok) {
    throw new MCPClientError({
      message: `Dynamic client registration failed: HTTP ${response.status}`,
      cause: response,
    });
  }

  return response.json();
}

async function getClientInformation({
  provider,
  authorizationCode,
  serverUrl,
  metadata,
}: {
  provider: OAuthClientProvider;
  authorizationCode?: string;
  serverUrl: string | URL;
  metadata?: OAuthMetadata;
}) {
  const clientInformation = await provider.clientInformation();

  if (clientInformation) return clientInformation;

  if (authorizationCode !== undefined) {
    throw new MCPClientError({
      message:
        'Existing OAuth client information is required when exchanging an authorization code',
    });
  }

  if (!provider.saveClientInformation) {
    throw new MCPClientError({
      message:
        'OAuth client information must be saveable for dynamic registration',
    });
  }

  const fullInformation = await registerClient({
    serverUrl,
    metadata,
    clientMetadata: provider.clientMetadata,
  });

  await provider.saveClientInformation(fullInformation);

  return fullInformation;
}

async function exchangeAuthorization({
  serverUrl,
  metadata,
  clientInformation,
  authorizationCode,
  codeVerifier,
}: {
  serverUrl: string | URL;
  metadata?: OAuthMetadata;
  clientInformation: OAuthClientInformation;
  authorizationCode: string;
  codeVerifier: string;
}): Promise<OAuthTokens> {
  const grantType = 'authorization_code';

  const tokenUrl = !metadata
    ? new URL('/token', serverUrl)
    : new URL(metadata.token_endpoint);

  if (
    metadata &&
    metadata.grant_types_supported &&
    !metadata.grant_types_supported.includes(grantType)
  ) {
    throw new MCPClientError({
      message: `Auth server does not support grant type ${grantType}`,
    });
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
    throw new MCPClientError({
      message: `Token exchange failed: HTTP ${response.status}`,
      cause: response,
    });
  }

  return response.json();
}

async function refreshAuthorization({
  serverUrl,
  metadata,
  clientInformation,
  refreshToken,
}: {
  serverUrl: string | URL;
  metadata?: OAuthMetadata;
  clientInformation: OAuthClientInformation;
  refreshToken: string;
}): Promise<OAuthTokens> {
  const grantType = 'refresh_token';

  const tokenUrl = !metadata
    ? new URL('/token', serverUrl)
    : new URL(metadata.token_endpoint);

  if (
    metadata &&
    metadata.grant_types_supported &&
    !metadata.grant_types_supported.includes(grantType)
  ) {
    throw new MCPClientError({
      message: `Auth server does not support grant type ${grantType}`,
    });
  }

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
    throw new MCPClientError({
      message: `Token refresh failed: HTTP ${response.status}`,
      cause: response,
    });
  }

  return response.json();
}

async function startAuthorization({
  serverUrl,
  metadata,
  clientInformation,
  redirectUrl,
}: {
  serverUrl: string | URL;
  metadata?: OAuthMetadata;
  clientInformation: OAuthClientInformation;
  redirectUrl: string | URL;
}): Promise<{ authorizationUrl: URL; codeVerifier: string }> {
  const responseType = 'code';
  const codeChallengeMethod = 'S256';

  const authorizationUrl = !metadata
    ? new URL('/authorize', serverUrl)
    : new URL(metadata.authorization_endpoint);

  if (metadata) {
    if (!metadata.response_types_supported.includes(responseType)) {
      throw new MCPClientError({
        message: `Auth server does not support response type ${responseType}`,
      });
    }

    if (
      !metadata.code_challenge_methods_supported ||
      !metadata.code_challenge_methods_supported.includes(codeChallengeMethod)
    ) {
      throw new MCPClientError({
        message: `Auth server does not support code challenge method ${codeChallengeMethod}`,
      });
    }
  }

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
