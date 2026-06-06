import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { createHash, randomUUID } from 'crypto';
import { unwrapDataKey } from '../crypto/decrypt-backup.util';
import type { Request } from 'express';
import { createReadStream, createWriteStream } from 'fs';
import { promises as fs } from 'fs';
import { join } from 'path';
import {
  assertPathWithinStorage,
  validateAgentId,
  validateBackupId,
} from '../auth/agent-id.util';

export type BackupMeta = {
  id: string;
  agentId: string;
  dbName: string;
  createdAt: string;
  sizeBytes: number;
  encryptionVersion: string;
  compressed: boolean;
  ivB64: string;
  authTagB64: string;
  encryptedDataKeyB64: string;
  ciphertextSha256Hex: string;
};

type UploadResult = { backupId: string; sizeBytes: number; ciphertextSha256Hex: string };

@Injectable()
export class BackupsService {
  private readonly storageDir = process.env.BACKUP_STORAGE_DIR
    ? join(process.env.BACKUP_STORAGE_DIR)
    : join(process.cwd(), 'data', 'backups');

  async handleUpload(req: Request): Promise<UploadResult> {
    const agentId = validateAgentId(this.requiredHeader(req, 'x-agent-id'));
    const dbName = this.requiredHeader(req, 'x-db-name');
    const encryptionVersion = this.requiredHeader(req, 'x-enc-version');
    const compressed = this.parseCompressedHeader(req);
    const ivB64 = this.requiredHeader(req, 'x-iv');
    const authTagB64 = this.requiredHeader(req, 'x-auth-tag');
    const encryptedDataKeyB64 = this.requiredHeader(req, 'x-encrypted-data-key');
    const declaredSha = this.requiredHeader(req, 'x-ciphertext-sha256');

    const backupId = this.newBackupId();
    const dir = join(this.storageDir, agentId, backupId);
    assertPathWithinStorage(this.storageDir, dir);

    const payloadPath = join(dir, 'payload.bin');
    const metaPath = join(dir, 'meta.json');

    await fs.mkdir(dir, { recursive: true });

    const hash = createHash('sha256');
    let sizeBytes = 0;

    try {
      await new Promise<void>((resolve, reject) => {
        const out = createWriteStream(payloadPath);

        req.on('data', (chunk: Buffer) => {
          sizeBytes += chunk.length;
          hash.update(chunk);
        });
        req.on('error', reject);
        out.on('error', reject);
        out.on('finish', resolve);

        req.pipe(out);
      });

      const ciphertextSha256Hex = hash.digest('hex');
      if (!this.shaEqual(declaredSha, ciphertextSha256Hex)) {
        throw new BadRequestException('ciphertextSha256 mismatch');
      }

      const meta: BackupMeta = {
        id: backupId,
        agentId,
        dbName,
        createdAt: new Date().toISOString(),
        sizeBytes,
        encryptionVersion,
        compressed,
        ivB64,
        authTagB64,
        encryptedDataKeyB64,
        ciphertextSha256Hex,
      };

      await fs.writeFile(metaPath, JSON.stringify(meta, null, 2), 'utf8');

      return { backupId, sizeBytes, ciphertextSha256Hex };
    } catch (err) {
      await fs.rm(dir, { recursive: true, force: true }).catch(() => undefined);
      throw err;
    }
  }

  async listBackups(agentId: string): Promise<BackupMeta[]> {
    const safeAgentId = validateAgentId(agentId);
    await fs.mkdir(this.storageDir, { recursive: true });
    const out: BackupMeta[] = [];

    const agentDir = join(this.storageDir, safeAgentId);
    assertPathWithinStorage(this.storageDir, agentDir);

    const backups = await this.safeListDirs(agentDir);
    for (const bd of backups) {
      const metaPath = join(bd, 'meta.json');
      try {
        const raw = await fs.readFile(metaPath, 'utf8');
        const meta = JSON.parse(raw) as BackupMeta;
        if (meta.agentId === safeAgentId) {
          out.push(meta);
        }
      } catch {}
    }

    return out.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }

  async getMeta(agentId: string, backupId: string): Promise<BackupMeta> {
    const { meta } = await this.findByAgentBackup(agentId, backupId);
    return meta;
  }

  async openPayloadStream(
    agentId: string,
    backupId: string,
  ): Promise<{ stream: NodeJS.ReadableStream; meta: BackupMeta }> {
    const { payloadPath, meta } = await this.findByAgentBackup(agentId, backupId);
    return { stream: createReadStream(payloadPath), meta };
  }

  async getDataKey(
    agentId: string,
    backupId: string,
  ): Promise<{ dataKeyB64: string; keyId?: string }> {
    const { meta } = await this.findByAgentBackup(agentId, backupId);
    const privateKeyPath = process.env.BACKUP_SERVER_PRIVATE_KEY_PATH;
    if (!privateKeyPath) throw new Error('BACKUP_SERVER_PRIVATE_KEY_PATH is required');
    const privateKey = await fs.readFile(privateKeyPath, 'utf8');

    const dataKey = unwrapDataKey(meta, privateKey);
    return { dataKeyB64: dataKey.toString('base64') };
  }

  private requiredHeader(req: Request, name: string): string {
    const v = req.headers[name];
    if (!v) throw new BadRequestException(`Missing header ${name}`);
    if (Array.isArray(v)) return v[0] ?? '';
    return String(v);
  }

  private parseCompressedHeader(req: Request): boolean {
    const raw = req.headers['x-compressed'];
    const value = Array.isArray(raw) ? raw[0] : raw;
    if (value === undefined) return true;
    const normalized = String(value).trim().toLowerCase();
    if (normalized === 'true' || normalized === '1') return true;
    if (normalized === 'false' || normalized === '0') return false;
    throw new BadRequestException('Invalid X-Compressed');
  }

  private newBackupId(): string {
    return randomUUID();
  }

  private async findByAgentBackup(
    agentId: string,
    backupId: string,
  ): Promise<{ payloadPath: string; meta: BackupMeta }> {
    const safeAgentId = validateAgentId(agentId);
    const safeBackupId = validateBackupId(backupId);

    const dir = join(this.storageDir, safeAgentId, safeBackupId);
    assertPathWithinStorage(this.storageDir, dir);

    const metaPath = join(dir, 'meta.json');
    const payloadPath = join(dir, 'payload.bin');

    try {
      const raw = await fs.readFile(metaPath, 'utf8');
      await fs.stat(payloadPath);
      const meta = JSON.parse(raw) as BackupMeta;
      if (meta.agentId !== safeAgentId) {
        throw new ForbiddenException('Backup does not belong to this agent');
      }
      return { meta, payloadPath };
    } catch (err) {
      if (err instanceof ForbiddenException) throw err;
      throw new NotFoundException('Backup not found');
    }
  }

  private async safeListDirs(root: string): Promise<string[]> {
    try {
      const items = await fs.readdir(root, { withFileTypes: true });
      return items.filter((d) => d.isDirectory()).map((d) => join(root, d.name));
    } catch {
      return [];
    }
  }

  private shaEqual(declared: string, actualHex: string): boolean {
    const d = declared.trim().toLowerCase();
    if (/^[0-9a-f]{64}$/.test(d)) return d === actualHex;
    try {
      const buf = Buffer.from(d, 'base64');
      return buf.toString('hex') === actualHex;
    } catch {
      return false;
    }
  }
}
