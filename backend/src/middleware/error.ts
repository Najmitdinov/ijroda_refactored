import type { ErrorRequestHandler } from 'express';

export const errorHandler: ErrorRequestHandler = (error, _req, res, _next) => {
  console.error('[api]', error);
  const status = Number(error.statusCode || error.status || 500);
  res.status(status).json({
    error: status >= 500 ? 'INTERNAL_SERVER_ERROR' : error.message,
    details: process.env.NODE_ENV === 'production' ? undefined : error.stack
  });
};
