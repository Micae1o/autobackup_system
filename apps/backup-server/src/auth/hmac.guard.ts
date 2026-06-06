import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { createHmac, timingSafeEqual } from 'crypto';
import type { Request } from 'express';
import { validateAgentId } from './agent-id.util';

type NonceEntry = { expiresAtMs: number };

@Injectable()
export class HmacGuard implements CanActivate {
  private readonly nonces = new Map<string, NonceEntry>();

  canActivate(context: ExecutionContext): boolean {
    const req = context.switchToHttp().getRequest<Request>();

    const agentId = validateAgentId(this.getHeader(req, 'x-agent-id'));
    const timestampRaw = this.getHeader(req, 'x-timestamp');
    const nonce = this.getHeader(req, 'x-nonce');
    const signature = this.getHeader(req, 'x-signature');
    const ciphertextSha256 = this.getHeader(req, 'x-ciphertext-sha256');

    const secret = process.env.BACKUP_HMAC_SECRET;
    if (!secret) {
      throw new UnauthorizedException('HMAC secret is not configured on the server');
    }

    const nowMs = Date.now();
    const timestampMs = this.parseTimestampMs(timestampRaw);
    const skewMs = Math.abs(nowMs - timestampMs);
    const allowedSkewMs = Number(
      process.env.BACKUP_HMAC_SKEW_MS ?? 5 * 60 * 1000,
    );
    if (!Number.isFinite(timestampMs) || skewMs > allowedSkewMs) {
      throw new UnauthorizedException('Invalid X-Timestamp');
    }

    this.gcNonces(nowMs);
    const nonceKey = `${agentId}:${nonce}`;
    if (this.nonces.has(nonceKey)) {
      throw new UnauthorizedException('Replay detected (duplicate nonce)');
    }
    this.nonces.set(nonceKey, { expiresAtMs: nowMs + allowedSkewMs });

    const signingString = this.buildSigningString(req, {
      agentId,
      timestampRaw,
      nonce,
      ciphertextSha256,
    });

    const expected = createHmac('sha256', secret)
      .update(signingString)
      .digest();
    const got = this.decodeSig(signature);
    if (got.length !== expected.length || !timingSafeEqual(got, expected)) {
      throw new UnauthorizedException('Invalid HMAC signature');
    }

    return true;
  }

  private getHeader(req: Request, name: string): string {
    const v = req.headers[name];
    if (!v) throw new UnauthorizedException(`Missing header ${name}`);
    if (Array.isArray(v)) return v[0] ?? '';
    return String(v);
  }

  private parseTimestampMs(raw: string): number {
    const n = Number(raw);
    if (!Number.isFinite(n)) return Number.NaN;
    return n < 10_000_000_000 ? n * 1000 : n;
  }

  private buildSigningString(
    req: Request,
    input: {
      agentId: string;
      timestampRaw: string;
      nonce: string;
      ciphertextSha256: string;
    },
  ): string {
    const method = (req.method ?? '').toUpperCase();
    const path = req.originalUrl ?? req.url ?? '';
    return [
      method,
      path,
      input.timestampRaw,
      input.nonce,
      input.agentId,
      input.ciphertextSha256,
    ].join('\n');
  }

  private decodeSig(sig: string): Buffer {
    const looksHex = /^[0-9a-fA-F]+$/.test(sig) && sig.length % 2 === 0;
    return looksHex ? Buffer.from(sig, 'hex') : Buffer.from(sig, 'base64');
  }

  private gcNonces(nowMs: number): void {
    for (const [k, v] of this.nonces.entries()) {
      if (v.expiresAtMs <= nowMs) this.nonces.delete(k);
    }
  }
}
