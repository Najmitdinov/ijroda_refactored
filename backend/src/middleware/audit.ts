import type { NextFunction, Request, Response } from 'express';
import { query } from '../db/pool.js';

export function audit(action: string) {
  return async (req: Request, _res: Response, next: NextFunction) => {
    try {
      await query(
        `insert into logs (actor_user_id, action, entity_type, ip_address, user_agent, metadata)
         values ($1, $2, $3, $4, $5, $6)`,
        [
          req.user?.user_id ?? null,
          action,
          req.baseUrl.replace('/api/', '') || 'system',
          req.ip,
          req.header('user-agent') ?? '',
          JSON.stringify({ method: req.method, path: req.originalUrl })
        ]
      );
    } catch (error) {
      console.warn('[audit] skipped', error);
    }
    next();
  };
}
