import { JSONValue } from '@ai-sdk/provider';
import { generateId as generateIdFunction } from '@ai-sdk/provider-utils';
import { UseChatOptions } from '../types';
import { ChatStore } from './chat-store';
import { processTextStream } from './process-text-stream';

export async function processChatTextResponseV2({
  chatId,
  stream,
  update,
  onFinish,
  generateId = generateIdFunction,
  store,
}: {
  chatId: string;
  stream: ReadableStream<Uint8Array>;
  update: (options: { data: JSONValue[] | undefined }) => void;
  onFinish: UseChatOptions['onFinish'];
  generateId?: () => string;
  store: ChatStore;
}) {
  await processTextStream({
    stream,
    onTextPart: chunk => {
      update({ data: [] }); // Sets status to streaming (SWR)
      store.addOrUpdateAssistantMessageParts({
        chatId,
        partDelta: { type: 'text', text: chunk },
        generateId,
      });
    },
  });

  // in text mode, we don't have usage information or finish reason:
  onFinish?.(store.getLastMessage(chatId)!, {
    usage: { completionTokens: NaN, promptTokens: NaN, totalTokens: NaN },
    finishReason: 'unknown',
  });
}
