import { EventSourceParserStream } from 'eventsource-parser/stream';
import { MCPClientError } from '../../../errors';
import { JSONRPCMessage, JSONRPCMessageSchema } from './json-rpc-message';
import { authenticateMCPClient, OAuthClientProvider } from './mcp-oauth';
import { MCPTransport } from './mcp-transport';

export class SseMCPTransport implements MCPTransport {
  private endpoint?: URL;
  private abortController?: AbortController;
  private url: URL;
  private connected = false;
  private sseConnection?: {
    close: () => void;
  };
  private authProvider?: OAuthClientProvider;

  onclose?: () => void;
  onerror?: (error: unknown) => void;
  onmessage?: (message: JSONRPCMessage) => void;

  constructor({
    url,
    authProvider,
  }: {
    url: string;
    authProvider?: OAuthClientProvider;
  }) {
    this.url = new URL(url);
    this.authProvider = authProvider;
  }

  async start(): Promise<void> {
    return new Promise<void>(async (resolve, reject) => {
      if (this.connected) {
        return resolve();
      }

      /**
       * Attempt to auth (MCP waits to do this after connection is established and we get back a 401)
       *
       * Maybe: Throw special error to let user handle?
       */
      if (this.authProvider) {
        const authResult = await authenticateMCPClient({
          provider: this.authProvider,
          serverUrl: this.url,
        });

        if (authResult === 'REDIRECT') {
          return reject(
            new MCPClientError({
              message: 'MCP SSE Transport Error: Redirect',
            }),
          );
        }
      }

      this.abortController = new AbortController();

      const establishConnection = async () => {
        try {
          const headers = new Headers();
          headers.set('Accept', 'text/event-stream');

          if (this.authProvider) {
            const tokens = await this.authProvider.tokens();
            if (tokens) {
              headers.set('Authorization', `Bearer ${tokens.access_token}`);
            }
          }

          const response = await fetch(this.url.href, {
            headers,
            signal: this.abortController?.signal,
          });

          if (response.status === 401 && this.authProvider) {
            // Or should we also retry auth here?
            return reject(
              new MCPClientError({
                message: 'MCP SSE Transport Error: Unauthorized',
              }),
            );
          }

          if (!response.ok || !response.body) {
            const error = new MCPClientError({
              message: `MCP SSE Transport Error: ${response.status} ${response.statusText}`,
            });
            this.onerror?.(error);
            return reject(error);
          }

          const stream = response.body
            .pipeThrough(new TextDecoderStream())
            .pipeThrough(new EventSourceParserStream());

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

          this.onerror?.(error);
          reject(error);
        }
      };

      establishConnection();
    });
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
      const headers = new Headers();
      headers.set('Content-Type', 'application/json');

      if (this.authProvider) {
        const tokens = await this.authProvider.tokens();
        if (tokens) {
          headers.set('Authorization', `Bearer ${tokens.access_token}`);
        }
      }

      const init = {
        method: 'POST',
        headers,
        body: JSON.stringify(message),
        signal: this.abortController?.signal,
      };

      const response = await fetch(this.endpoint, init);

      if (response.status === 401 && this.authProvider) {
        const authResult = await authenticateMCPClient({
          provider: this.authProvider,
          serverUrl: this.url,
        });

        if (authResult === 'AUTHORIZED') {
          return this.send(message);
        } else {
          // This will silently fail, we need to throw again in catch:
          throw new MCPClientError({
            message: 'MCP SSE Transport Error: Unauthorized',
          });
        }
      }

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

  // Called to complete the auth flow after redirection:
  async finishAuth(authorizationCode: string): Promise<void> {
    if (!this.authProvider) {
      throw new MCPClientError({ message: 'No auth provider configured' });
    }

    const authResult = await authenticateMCPClient({
      provider: this.authProvider,
      serverUrl: this.url,
      authorizationCode,
    });

    if (authResult !== 'AUTHORIZED') {
      throw new MCPClientError({ message: 'Failed to complete authorization' });
    }
  }
}

export function deserializeMessage(line: string): JSONRPCMessage {
  return JSONRPCMessageSchema.parse(JSON.parse(line));
}
