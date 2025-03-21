import { MCPClientError } from '../../../errors';
import { createMCPClient } from './mcp-client';
import { SseMCPTransport } from './mcp-sse-transport';

let client: Awaited<ReturnType<typeof createMCPClient>> | undefined;

try {
  client = await createMCPClient({
    transport: {
      type: 'sse',
      url: 'http://localhost:3000/sse',
      authProvider: {
        get redirectUrl(): string | URL {
          return 'http://localhost:3000/oauth/redirect';
        },
        get clientMetadata() {
          return {
            client_id: '123',
            client_secret: '456',
            redirect_uris: ['http://localhost:3000/oauth/redirect'],
          };
        },
        clientInformation() {
          return {
            client_id: '123',
            client_secret: '456',
            redirect_uri: 'http://localhost:3000/oauth/redirect',
          };
        },
        tokens() {
          return {
            access_token: '123',
            refresh_token: '456',
            token_type: 'Bearer',
            expires_in: 3600,
          };
        },
        saveTokens(tokens) {
          // save tokens
        },
        redirectToAuthorization(authorizationUrl) {
          // redirect to authorization url
        },
        saveCodeVerifier(codeVerifier: string) {
          // save code verifier
        },
        codeVerifier() {
          return '123';
        },
      },
    },
  });

  const tools = await client.tools();
} catch (error) {
  if (
    client &&
    error instanceof MCPClientError &&
    client.transport instanceof SseMCPTransport &&
    error.message === 'MCP SSE Transport Error: Unauthorized'
  ) {
    // Would this code ever be reached?
    await client.transport.finishAuth('123');
  }
}
