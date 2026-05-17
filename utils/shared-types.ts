export type UserRole = 'SUPER_ADMIN' | 'RAHBAR' | 'NAZORATCHI' | 'IJROCHI' | 'KUZATUVCHI';

export type TaskPriority = 'LOW' | 'NORMAL' | 'IMPORTANT' | 'URGENT' | 'CRITICAL';

export type TaskStatus = 'NEW' | 'IN_PROGRESS' | 'DONE' | 'OVERDUE' | 'CANCELLED';

export type NotificationChannel = 'TELEGRAM' | 'EMAIL' | 'PUSH';

export interface EmployeeProfile {
  employee_id: string;
  ism: string;
  familiya: string;
  sharif?: string;
  bolim: string;
  lavozim: string;
  telefon?: string;
  telegram_id?: string;
  username?: string;
  aliases: string[];
}

export interface EduIjroParsedDocument {
  document_title: string;
  executor: string;
  deadline: string | null;
  department: string;
  status: string;
  priority: TaskPriority;
  summary: string;
  source_text: string;
}

export interface AiAnalysisResult {
  urgency: TaskPriority;
  importance: number;
  deadline_risk: number;
  task_summary: string;
  duplicate_task_ids: string[];
  workload_analysis: string;
  recommendations: string[];
  confidence_score: number;
}

export interface EmployeeMatchResult {
  status: 'MATCHED' | 'NEEDS_REVIEW' | 'NOT_FOUND';
  employee_id?: string;
  display_name?: string;
  confidence_score: number;
  reasons: string[];
}
