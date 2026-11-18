import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import type { Request } from 'express';
import { AgentApiGuard } from './agent-api.guard';

function context(headers: Record<string, string | string[] | undefined>): ExecutionContext {
  const req = { headers } as Request;
  return {
    switchToHttp: () => ({ getRequest: () => req }),
  } as ExecutionContext;
}

describe('AgentApiGuard', () => {
  const guard = new AgentApiGuard();

  beforeEach(() => {
    process.env.BACKUP_AGENT_API_TOKEN = 'agent-token';
  });

  afterEach(() => {
    delete process.env.BACKUP_AGENT_API_TOKEN;
  });

  it('accepts a bearer token', () => {
    expect(
      guard.canActivate(context({ authorization: 'Bearer agent-token' })),
    ).toBe(true);
  });

  it('accepts the token header', () => {
    expect(guard.canActivate(context({ 'x-agent-api-token': 'agent-token' }))).toBe(
      true,
    );
  });

  it('rejects a missing token', () => {
    expect(() => guard.canActivate(context({}))).toThrow('Bearer');
  });

  it('rejects a wrong token', () => {
    expect(() =>
      guard.canActivate(context({ authorization: 'Bearer nope' })),
    ).toThrow('Invalid API token');
  });

  it('rejects a short wrong token', () => {
    expect(() => guard.canActivate(context({ authorization: 'Bearer x' }))).toThrow(
      UnauthorizedException,
    );
  });

  it('rejects when the server token is not configured', () => {
    delete process.env.BACKUP_AGENT_API_TOKEN;
    expect(() =>
      guard.canActivate(context({ authorization: 'Bearer agent-token' })),
    ).toThrow('BACKUP_AGENT_API_TOKEN is not configured');
  });
});
