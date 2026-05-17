import { GoogleGenerativeAI } from '@google/generative-ai';
import OpenAI from 'openai';
import { env } from '../config/env.js';

export interface AiJsonRequest {
  system: string;
  prompt: string;
  temperature?: number;
}

export async function completeJson(request: AiJsonRequest): Promise<unknown> {
  const providers = [
    callOpenRouter,
    callGemini,
    callDeepSeek,
    callOpenAi
  ];

  let lastError: unknown;
  for (const provider of providers) {
    try {
      const text = await provider(request);
      return parseJson(text);
    } catch (error) {
      lastError = error;
      console.warn('[ai] provider failed', provider.name, error);
    }
  }
  throw lastError ?? new Error('AI_PROVIDER_UNAVAILABLE');
}

async function callOpenRouter({ system, prompt, temperature = 0.2 }: AiJsonRequest) {
  if (!env.OPENROUTER_API_KEY) throw new Error('OPENROUTER_API_KEY_MISSING');
  const client = new OpenAI({
    apiKey: env.OPENROUTER_API_KEY,
    baseURL: 'https://openrouter.ai/api/v1'
  });
  const result = await client.chat.completions.create({
    model: 'anthropic/claude-3.5-sonnet',
    temperature,
    response_format: { type: 'json_object' },
    messages: [
      { role: 'system', content: system },
      { role: 'user', content: prompt }
    ]
  });
  return result.choices[0]?.message?.content ?? '{}';
}

async function callGemini({ system, prompt, temperature = 0.2 }: AiJsonRequest) {
  if (!env.GEMINI_API_KEY) throw new Error('GEMINI_API_KEY_MISSING');
  const gemini = new GoogleGenerativeAI(env.GEMINI_API_KEY);
  const model = gemini.getGenerativeModel({
    model: 'gemini-1.5-pro',
    systemInstruction: system
  });
  const result = await model.generateContent({
    contents: [{ role: 'user', parts: [{ text: prompt }] }],
    generationConfig: { temperature, responseMimeType: 'application/json' }
  });
  return result.response.text();
}

async function callDeepSeek({ system, prompt, temperature = 0.2 }: AiJsonRequest) {
  if (!env.DEEPSEEK_API_KEY) throw new Error('DEEPSEEK_API_KEY_MISSING');
  const client = new OpenAI({
    apiKey: env.DEEPSEEK_API_KEY,
    baseURL: 'https://api.deepseek.com'
  });
  const result = await client.chat.completions.create({
    model: 'deepseek-chat',
    temperature,
    response_format: { type: 'json_object' },
    messages: [
      { role: 'system', content: system },
      { role: 'user', content: prompt }
    ]
  });
  return result.choices[0]?.message?.content ?? '{}';
}

async function callOpenAi({ system, prompt, temperature = 0.2 }: AiJsonRequest) {
  if (!env.OPENAI_API_KEY) throw new Error('OPENAI_API_KEY_MISSING');
  const client = new OpenAI({ apiKey: env.OPENAI_API_KEY });
  const result = await client.chat.completions.create({
    model: 'gpt-4o-mini',
    temperature,
    response_format: { type: 'json_object' },
    messages: [
      { role: 'system', content: system },
      { role: 'user', content: prompt }
    ]
  });
  return result.choices[0]?.message?.content ?? '{}';
}

function parseJson(text: string) {
  const trimmed = text.trim().replace(/^```json\s*/i, '').replace(/```$/i, '');
  return JSON.parse(trimmed);
}
