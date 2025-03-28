'use client'

import { useChat } from '@ai-sdk/react'

export default function Home() {
  const { messages, input, handleInputChange, handleSubmit } = useChat()

  return (
    <div className='size-full flex flex-col items-center justify-center p-12 gap-4'>
      <h1 className='text-2xl font-bold'>MCP Demo</h1>
      <div className='flex items-center w-96 gap-2'>
        <input
          value={input}
          onChange={handleInputChange}
          onSubmit={handleSubmit}
          placeholder='Ask a question...'
        />
        <button onClick={handleSubmit}>Send</button>
      </div>
      {messages.map((message) => {
        return (
          <div key={message.id} className='p-4 flex flex-col gap-2'>
            <p className='font-medium'>{message.role}:</p>
            <p>{message.content}</p>
            {message.role !== 'user' && (
              <pre>{JSON.stringify(message.parts, null, 2)}</pre>
            )}
          </div>
        )
      })}
    </div>
  )
}
