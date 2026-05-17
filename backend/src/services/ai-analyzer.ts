import { z } from 'zod';
import { completeJson } from './ai-provider.js';

const analysisSchema = z.object({
  urgency: z.enum(['LOW', 'NORMAL', 'IMPORTANT', 'URGENT', 'CRITICAL']),
  importance: z.number().min(0).max(100),
  deadline_risk: z.number().min(0).max(100),
  task_summary: z.string(),
  duplicate_task_ids: z.array(z.string()).default([]),
  workload_analysis: z.string(),
  recommendations: z.array(z.string()).default([]),
  confidence_score: z.number().min(0).max(100)
});

export async function analyzeTaskWithAi(input: {
  documentText: string;
  knownTasks?: Array<{ task_id: string; summary: string }>;
}) {
  const result = await completeJson({
    system: 'You are an enterprise AI analyst for Uzbek government execution monitoring. Return strict JSON only.',
    prompt: JSON.stringify({
      instruction: 'Analyze edu.ijro task urgency, deadline risk, duplicates, workload and recommendations.',
      priority_values: ['LOW', 'NORMAL', 'IMPORTANT', 'URGENT', 'CRITICAL'],
      output_schema: analysisSchema.shape,
      documentText: input.documentText.slice(0, 16_000),
      knownTasks: input.knownTasks ?? []
    })
  });
  return analysisSchema.parse(result);
}
