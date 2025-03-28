import { authProvider } from '@/app/auth-provider';
import { openai } from '@ai-sdk/openai';
import { experimental_createMCPClient, Message, streamText } from 'ai';

export async function POST(req: Request) {
  const { messages }: { messages: Message[] } = await req.json();

  try {
    const client = await experimental_createMCPClient({
      transport: {
        type: 'sse',
        url: 'http://localhost:8282/sse',
        authProvider,
      },
      onUncaughtError: error => {
        if (error instanceof Response) {
          const status = error.status;
          if (status === 302) {
            const redirectUrl = error.headers.get('Location');
            // And then wut...
          }
        }
        console.error('[Uncaught Error]', error);
      },
    });

    const tools = await client.tools();

    const response = streamText({
      model: openai('gpt-4o'),
      tools,
      messages,
      onFinish: async () => {
        await client.close();
      },
    });

    return response.toDataStreamResponse();
  } catch (error) {
    return new Response('Internal Server Error', { status: 500 });
  }
}
