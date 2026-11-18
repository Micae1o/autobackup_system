import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import type { Request } from 'express';
import { HmacGuard } from './hmac.guard';
import { signRequest } from '../testing/backup-fixture';

const SECRET = 'test-hmac-secret';
const AGENT = 'local-agent';
const SHA = 'ab'.repeat(32);

function httpContext(req: Partial<Request>): ExecutionContext {
  return {
    switchToHttp: () => ({ getRequest: () => req }),
  } as ExecutionContext;
}

function request(headers: Record<string, string | string[]>, path = '/backups'): Partial<Request> {
  return {
    method: 'POST',
    originalUrl: path,
    headers,
  };
}

function signed(overrides?: {
  timestamp?: string;
  nonce?: string;
  encoding?: 'base64' | 'hex';
  path?: string;
  agentId?: string;
  sha?: string;
  secret?: string;
}) {
  const path = overrides?.path ?? '/backups';
  const agentId = overrides?.agentId ?? AGENT;
  const sha = overrides?.sha ?? SHA;
  const signedRequest = signRequest({
    method: 'POST',
    path,
    agentId,
    secret: overrides?.secret ?? SECRET,
    ciphertextSha256: sha,
    timestamp: overrides?.timestamp,
    nonce: overrides?.nonce,
    encoding: overrides?.encoding,
  });
  return request(
    {
      'x-agent-id': agentId,
      'x-timestamp': signedRequest.timestamp,
      'x-nonce': signedRequest.nonce,
      'x-signature': signedRequest.signature,
      'x-ciphertext-sha256': sha,
    },
    path,
  );
}

describe('HmacGuard', () => {
  let guard: HmacGuard;

  beforeEach(() => {
    process.env.BACKUP_HMAC_SECRET = SECRET;
    process.env.BACKUP_HMAC_SKEW_MS = '300000';
    guard = new HmacGuard();
  });

  afterEach(() => {
    delete process.env.BACKUP_HMAC_SECRET;
    delete process.env.BACKUP_HMAC_SKEW_MS;
  });

  it('accepts a base64 signature', () => {
    expect(guard.canActivate(httpContext(signed()))).toBe(true);
  });

  it('accepts a hex signature', () => {
    expect(guard.canActivate(httpContext(signed({ encoding: 'hex' })))).toBe(true);
  });

  it('accepts a timestamp in seconds', () => {
    const timestamp = String(Math.floor(Date.now() / 1000));
    expect(guard.canActivate(httpContext(signed({ timestamp })))).toBe(true);
  });

  it('reads the first value when a header is repeated', () => {
    const req = signed();
    const headers = req.headers as Record<string, string | string[]>;
    headers['x-agent-id'] = [AGENT, 'other'];
    expect(guard.canActivate(httpContext(req))).toBe(true);
  });

  it('rejects a missing header', () => {
    expect(() => guard.canActivate(httpContext(request({})))).toThrow('Missing header');
  });

  it('rejects an agent id with a space', () => {
    const req = signed({ agentId: 'bad id' });
    expect(() => guard.canActivate(httpContext(req))).toThrow('Invalid X-Agent-Id');
  });

  it('rejects when the server secret is not set', () => {
    delete process.env.BACKUP_HMAC_SECRET;
    expect(() => guard.canActivate(httpContext(signed()))).toThrow(UnauthorizedException);
  });

  it('rejects a timestamp outside the skew window', () => {
    const timestamp = String(Date.now() - 60 * 60 * 1000);
    expect(() => guard.canActivate(httpContext(signed({ timestamp })))).toThrow(
      'Invalid X-Timestamp',
    );
  });

  it('rejects a bad signature', () => {
    const req = signed();
    (req.headers as Record<string, string>)['x-signature'] = 'aaaa';
    expect(() => guard.canActivate(httpContext(req))).toThrow('Invalid HMAC signature');
  });

  it('rejects a signature for a different path', () => {
    const req = signed({ path: '/backups' });
    req.originalUrl = '/backups/other';
    expect(() => guard.canActivate(httpContext(req))).toThrow('Invalid HMAC signature');
  });

  it('rejects a reused nonce', () => {
    const nonce = 'same-nonce-same-nonce';
    expect(guard.canActivate(httpContext(signed({ nonce })))).toBe(true);
    expect(() => guard.canActivate(httpContext(signed({ nonce })))).toThrow('Replay detected');
  });
});
