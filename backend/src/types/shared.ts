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
