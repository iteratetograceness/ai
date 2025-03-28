import { MCPOAuthProvider } from 'ai';

export const authProvider = new MCPOAuthProvider({
  redirectUri: 'http://localhost:3000/api/auth/callback',
  clientMetadata: {
    redirect_uris: ['http://localhost:3000/api/auth/callback'],
    token_endpoint_auth_method: 'client_secret_post',
    client_name: 'mcp-next',
  },
});
