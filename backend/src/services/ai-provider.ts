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
    callGroq,
    callGemini,
    callOpenRouter,
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

async function callGroq({ system, prompt, temperature = 0.12 }: AiJsonRequest) {
  if (!env.GROQ_API_KEY) throw new Error('GROQ_API_KEY_MISSING');
  const client = new OpenAI({
    apiKey: env.GROQ_API_KEY,
    baseURL: 'https://api.groq.com/openai/v1'
  });
  const models = [
    env.GROQ_MODEL,
    'llama-3.3-70b-versatile',
    'openai/gpt-oss-120b',
    'qwen/qwen3-32b'
  ].filter((model, index, all): model is string =>
    Boolean(model) &&
    model !== 'llama-3.1-70b-versatile' &&
    all.indexOf(model) === index
  );

  let lastError: unknown;
  for (const model of models) {
    try {
      const result = await client.chat.completions.create({
        model,
        temperature,
        response_format: { type: 'json_object' },
        messages: [
          { role: 'system', content: system },
          { role: 'user', content: prompt }
        ]
      });
      return result.choices[0]?.message?.content ?? '{}';
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError ?? new Error('GROQ_PROVIDER_UNAVAILABLE');
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
