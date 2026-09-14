import { createRemoteJWKSet, jwtVerify } from 'jose';
import type { Env } from './types';

interface AccessConfig {
  issuer: string;
  audience: string;
  origin: string;
  email: string;
}

// Cache public signing keys only; identities and tokens remain request-local.
let keySet: { issuer: string; resolve: ReturnType<typeof createRemoteJWKSet> } | undefined;

export function accessConfig(env: Env): AccessConfig | null {
  const { ACCESS_TEAM_DOMAIN: team, ACCESS_AUD: audience, ADMIN_HOST: host, ADMIN_EMAIL: email } = env;
  if (!team || !/^[a-z0-9-]+\.cloudflareaccess\.com$/.test(team) || !audience?.trim() || !host || !email?.trim()) {
    return null;
  }
  try {
    const origin = `https://${host}`;
    const url = new URL(origin);
    if (url.protocol !== 'https:' || url.origin !== origin || url.host !== host) return null;
    return { issuer: `https://${team}`, audience, origin, email: email.trim().toLowerCase() };
  } catch {
    return null;
  }
}

export async function verifyAccess(request: Request, config: AccessConfig): Promise<boolean> {
  const token = request.headers.get('cf-access-jwt-assertion');
  if (!token) return false;
  try {
    if (keySet?.issuer !== config.issuer) {
      keySet = {
        issuer: config.issuer,
        resolve: createRemoteJWKSet(new URL(`${config.issuer}/cdn-cgi/access/certs`), { timeoutDuration: 5_000 }),
      };
    }
    const { payload } = await jwtVerify(token, keySet.resolve, {
      algorithms: ['RS256'],
      issuer: config.issuer,
      audience: config.audience,
      requiredClaims: ['exp', 'iat', 'sub', 'email'],
    });
    return payload.type === 'app' && typeof payload.email === 'string' && payload.email.toLowerCase() === config.email;
  } catch {
    // Invalid assertions and unavailable signing keys both fail closed.
    return false;
  }
}
