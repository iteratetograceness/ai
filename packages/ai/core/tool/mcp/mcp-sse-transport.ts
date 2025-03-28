import { createEventSourceParserStream } from '@ai-sdk/provider-utils';
import { MCPClientError } from '../../../errors';
import { JSONRPCMessage, JSONRPCMessageSchema } from './json-rpc-message';
import {
  authorize,
  OAuthClientProvider,
  UnauthorizedError,
} from './mcp-sse-auth-provider';
import { MCPTransport } from './mcp-transport';

export class SseMCPTransport implements MCPTransport {
  private endpoint?: URL;
  private abortController?: AbortController;
  private url: URL;
  private connected = false;
  private sseConnection?: {
    close: () => void;
  };
  private headers?: Record<string, string>;
  private authProvider?: OAuthClientProvider;

  onclose?: () => void;
  onerror?: (error: unknown) => void;
  onmessage?: (message: JSONRPCMessage) => void;

  constructor({
    url,
    headers,
    authProvider,
  }: {
    url: string;
    headers?: Record<string, string>;
    authProvider?: OAuthClientProvider;
  }) {
    this.url = new URL(url);
    this.headers = headers;
    this.authProvider = authProvider;
  }

  async start(): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      if (this.connected) {
        return resolve();
      }

      this.abortController = new AbortController();

      const establishConnection = async () => {
        try {
          const headers = await this.getHeaders();
          headers.set('Accept', 'text/event-stream');
          const response = await fetch(this.url.href, {
            headers,
            signal: this.abortController?.signal,
          });

          if (!response.ok || !response.body) {
            if (response.status === 401) {
              if (this.authProvider) {
                this.authThenStart().then(resolve, reject);
                return;
              }
            }
            const error = new MCPClientError({
              message: `MCP SSE Transport Error: ${response.status} ${response.statusText}`,
            });
            this.onerror?.(error);
            return reject(error);
          }

          const stream = response.body
            .pipeThrough(new TextDecoderStream())
            .pipeThrough(createEventSourceParserStream());

          const reader = stream.getReader();

          const processEvents = async () => {
            try {
              while (true) {
                const { done, value } = await reader.read();

                if (done) {
                  if (this.connected) {
                    this.connected = false;
                    throw new MCPClientError({
                      message:
                        'MCP SSE Transport Error: Connection closed unexpectedly',
                    });
                  }
                  return;
                }

                const { event, data } = value;

                if (event === 'endpoint') {
                  this.endpoint = new URL(data, this.url);

                  if (this.endpoint.origin !== this.url.origin) {
                    throw new MCPClientError({
                      message: `MCP SSE Transport Error: Endpoint origin does not match connection origin: ${this.endpoint.origin}`,
                    });
                  }

                  this.connected = true;
                  resolve();
                } else if (event === 'message') {
                  try {
                    const message = JSONRPCMessageSchema.parse(
                      JSON.parse(data),
                    );
                    this.onmessage?.(message);
                  } catch (error) {
                    const e = new MCPClientError({
                      message:
                        'MCP SSE Transport Error: Failed to parse message',
                      cause: error,
                    });
                    this.onerror?.(e);
                    // We do not throw here so we continue processing events after reporting the error
                  }
                }
              }
            } catch (error) {
              if (error instanceof Error && error.name === 'AbortError') {
                return;
              }

              this.onerror?.(error);
              reject(error);
            }
          };

          this.sseConnection = {
            close: () => reader.cancel(),
          };

          processEvents();
        } catch (error) {
          if (error instanceof Error && error.name === 'AbortError') {
            return;
          }

          console.log('ESTABLISH CONNECTION ERROR');

          this.onerror?.(error);
          reject(error);
        }
      };

      establishConnection();
    });
  }

  async authThenStart(): Promise<void> {
    if (!this.authProvider) {
      throw new MCPClientError({
        message: 'MCP SSE Transport Error: No auth provider',
      });
    }

    try {
      console.log('[Auth] Authorizing...');
      const result = await authorize({
        provider: this.authProvider,
        serverUrl: this.url,
      });

      console.log('[Auth] Result:', result);

      if (result !== 'AUTHORIZED') {
        console.error('MCP SSE Transport Error: Unauthorized');
        throw new UnauthorizedError();
      }

      return this.start();
    } catch (error) {
      this.onerror?.(error as Error);
      throw error;
    }
  }

  async close(): Promise<void> {
    this.connected = false;
    this.sseConnection?.close();
    this.abortController?.abort();
    this.onclose?.();
  }

  async send(message: JSONRPCMessage): Promise<void> {
    if (!this.endpoint || !this.connected) {
      throw new MCPClientError({
        message: 'MCP SSE Transport Error: Not connected',
      });
    }

    try {
      const headers = await this.getHeaders();
      headers.set('Content-Type', 'application/json');
      const init = {
        method: 'POST',
        headers,
        body: JSON.stringify(message),
        signal: this.abortController?.signal,
      };

      const response = await fetch(this.endpoint, init);

      if (!response.ok) {
        const text = await response.text().catch(() => null);
        const error = new MCPClientError({
          message: `MCP SSE Transport Error: POSTing to endpoint (HTTP ${response.status}): ${text}`,
        });
        this.onerror?.(error);
        return;
      }
    } catch (error) {
      this.onerror?.(error);
      return;
    }
  }

  private async getHeaders(): Promise<Headers> {
    const headers = new Headers(this.headers);
    if (this.authProvider) {
      const tokens = await this.authProvider.tokens();
      if (tokens) {
        headers.set('Authorization', `Bearer ${tokens.access_token}`);
      }
    }
    return headers;
  }
}

export function deserializeMessage(line: string): JSONRPCMessage {
  return JSONRPCMessageSchema.parse(JSON.parse(line));
}
