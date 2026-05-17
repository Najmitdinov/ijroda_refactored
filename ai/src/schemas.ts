import { z } from 'zod';

export const aiTaskAnalysisSchema = z.object({
  urgency: z.enum(['LOW', 'NORMAL', 'IMPORTANT', 'URGENT', 'CRITICAL']),
  importance: z.number().min(0).max(100),
  deadline_risk: z.number().min(0).max(100),
  task_summary: z.string(),
  duplicate_task_ids: z.array(z.string()),
  workload_analysis: z.string(),
  recommendations: z.array(z.string()),
  confidence_score: z.number().min(0).max(100)
});

export const aiLetterSchema = z.object({
  recipient: z.string(),
  subject: z.string(),
  body: z.string(),
  legal_basis: z.array(z.string()).default([]),
  confidence_score: z.number().min(0).max(100)
});

export type AiTaskAnalysis = z.infer<typeof aiTaskAnalysisSchema>;
export type AiLetter = z.infer<typeof aiLetterSchema>;
