import { query } from '../db/pool.js';
import type { NotificationChannel, TaskPriority } from '../types/shared.js';

export async function enqueueNotification(input: {
  userId?: string;
  employeeId?: string;
  channel: NotificationChannel;
  title: string;
  body: string;
  priority?: TaskPriority;
  metadata?: Record<string, unknown>;
}) {
  await query(
    `insert into notifications (user_id, employee_id, channel, title, body, priority, metadata)
     values ($1, $2, $3, $4, $5, $6, $7)`,
    [
      input.userId ?? null,
      input.employeeId ?? null,
      input.channel,
      input.title,
      input.body,
      input.priority ?? 'NORMAL',
      JSON.stringify(input.metadata ?? {})
    ]
  );
}
