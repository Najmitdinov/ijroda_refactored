import jwt from 'jsonwebtoken';
import { env } from '../config/env.js';

type FirebaseTokenPayload = jwt.JwtPayload & {
  sub: string;
  email?: string;
};

export type FirebaseAdminProfile = {
  uid: string;
  email: string;
  role: string;
};

let certificateCache: { values: Record<string, string>; expiresAt: number } | null = null;

function firestoreValue(value: unknown) {
  if (!value || typeof value !== 'object') return undefined;
  const item = value as Record<string, unknown>;
  if ('stringValue' in item) return item.stringValue;
  if ('booleanValue' in item) return item.booleanValue;
  if ('integerValue' in item) return Number(item.integerValue);
  return undefined;
}

async function getFirebaseCertificates() {
  if (certificateCache && certificateCache.expiresAt > Date.now()) return certificateCache.values;
  const response = await fetch(
    'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com',
    { signal: AbortSignal.timeout(10_000) }
  );
  if (!response.ok) throw new Error(`FIREBASE_CERTIFICATES_HTTP_${response.status}`);
  const values = await response.json() as Record<string, string>;
  const maxAge = Number(response.headers.get('cache-control')?.match(/max-age=(\d+)/)?.[1] || 3600);
  certificateCache = {
    values,
    expiresAt: Date.now() + Math.max(300, maxAge - 60) * 1000
  };
  return values;
}

export async function verifyFirebaseAdminToken(token: string): Promise<FirebaseAdminProfile> {
  const decoded = jwt.decode(token, { complete: true });
  const kid = decoded?.header?.kid;
  if (!kid || decoded.header.alg !== 'RS256') throw new Error('INVALID_FIREBASE_TOKEN');

  const certificates = await getFirebaseCertificates();
  const certificate = certificates[kid];
  if (!certificate) throw new Error('FIREBASE_CERTIFICATE_NOT_FOUND');

  const payload = jwt.verify(token, certificate, {
    algorithms: ['RS256'],
    audience: env.FIREBASE_PROJECT_ID,
    issuer: `https://securetoken.google.com/${env.FIREBASE_PROJECT_ID}`
  }) as FirebaseTokenPayload;
  if (!payload.sub) throw new Error('INVALID_FIREBASE_TOKEN');

  const userUrl = `https://firestore.googleapis.com/v1/projects/${encodeURIComponent(env.FIREBASE_PROJECT_ID)}/databases/(default)/documents/users/${encodeURIComponent(payload.sub)}`;
  const response = await fetch(userUrl, {
    headers: { authorization: `Bearer ${token}` },
    signal: AbortSignal.timeout(10_000)
  });
  if (!response.ok) throw new Error(`FIREBASE_USER_HTTP_${response.status}`);

  const document = await response.json() as { fields?: Record<string, unknown> };
  const role = String(firestoreValue(document.fields?.role) || '');
  const blocked = firestoreValue(document.fields?.blocked) === true;
  if (blocked) throw new Error('FIREBASE_USER_BLOCKED');
  if (!['admin', 'superadmin'].includes(role)) throw new Error('FIREBASE_ADMIN_REQUIRED');

  return {
    uid: payload.sub,
    email: String(payload.email || ''),
    role
  };
}
