import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { createHmac, timingSafeEqual } from 'crypto';
import type { Request } from 'express';

@Injectable()
export class AgentApiGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const req = context.switchToHttp().getRequest<Request>();
    const expected = process.env.BACKUP_AGENT_API_TOKEN;
    if (!expected) {
      throw new UnauthorizedException('BACKUP_AGENT_API_TOKEN is not configured');
    }

    const provided = this.extractToken(req);
    if (!provided) {
      throw new UnauthorizedException('Authorization: Bearer <token> required');
    }

    const a = createHmac('sha256', 'agent-api-token').update(provided).digest();
    const b = createHmac('sha256', 'agent-api-token').update(expected).digest();
    if (!timingSafeEqual(a, b)) {
      throw new UnauthorizedException('Invalid API token');
    }

    return true;
  }

  private extractToken(req: Request): string | undefined {
    const auth = req.headers.authorization;
    if (auth?.startsWith('Bearer ')) {
      return auth.slice('Bearer '.length).trim();
    }
    const header = req.headers['x-agent-api-token'];
    if (typeof header === 'string') return header.trim();
    if (Array.isArray(header)) return header[0]?.trim();
    return undefined;
  }
}
