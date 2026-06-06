import { BadRequestException } from '@nestjs/common';
import { resolve } from 'path';

const AGENT_ID_RE = /^[a-zA-Z0-9._-]{1,64}$/;
const BACKUP_ID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function validateAgentId(agentId: string): string {
  const trimmed = agentId.trim();
  if (!AGENT_ID_RE.test(trimmed)) {
    throw new BadRequestException('Invalid X-Agent-Id');
  }
  return trimmed;
}

export function validateBackupId(backupId: string): string {
  const trimmed = backupId.trim();
  if (!BACKUP_ID_RE.test(trimmed)) {
    throw new BadRequestException('Invalid backupId');
  }
  return trimmed;
}

export function assertPathWithinStorage(storageDir: string, targetPath: string): void {
  const base = resolve(storageDir);
  const resolved = resolve(targetPath);
  if (resolved !== base && !resolved.startsWith(base + '/')) {
    throw new BadRequestException('Invalid storage path');
  }
}
