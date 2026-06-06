import { Injectable } from '@nestjs/common';
import {
  constants,
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  publicEncrypt,
  randomBytes,
  randomUUID,
} from 'crypto';
import { createReadStream, createWriteStream } from 'fs';
import { promises as fs } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { pipeline } from 'stream/promises';
import { PassThrough } from 'stream';
import { createGzip, createGunzip } from 'zlib';
import { spawn } from 'child_process';

@Injectable()
export class BackupAgentService {
  async runBackup(input: { dbName?: string; compress: boolean }) {
    const agentId = process.env.BACKUP_AGENT_ID ?? 'local-agent';
    const serverUrl = process.env.BACKUP_SERVER_URL ?? 'http://localhost:3002';
    const hmacSecret = this.requiredEnv('BACKUP_HMAC_SECRET');
    const serverPublicKeyPath = this.requiredEnv(
      'BACKUP_SERVER_PUBLIC_KEY_PATH',
    );

    const dbName = input.dbName ?? this.requiredEnv('PGDATABASE');
    const tmpId = randomUUID();
    const tmpCipherPath = join(tmpdir(), `backup-${tmpId}.bin`);

    const {
      ivB64,
      authTagB64,
      encryptedDataKeyB64,
      ciphertextSha256Hex,
      sizeBytes,
    } = await this.createEncryptedDumpFile({
      dbName,
      compress: input.compress,
      serverPublicKeyPath,
      outputPath: tmpCipherPath,
    });

    const url = new URL('/backups', serverUrl);
    const timestamp = String(Date.now());
    const nonce = randomBytes(16).toString('hex');
    const signingString = this.buildSigningString({
      method: 'POST',
      path: url.pathname,
      agentId,
      timestamp,
      nonce,
      ciphertextSha256: ciphertextSha256Hex,
    });
    const sigB64 = createHmac('sha256', hmacSecret)
      .update(signingString)
      .digest('base64');

    const res = await fetch(url, {
      method: 'POST',
      duplex: 'half',
      headers: {
        'Content-Type': 'application/octet-stream',
        'X-Agent-Id': agentId,
        'X-Db-Name': dbName,
        'X-Compressed': String(input.compress),
        'X-Enc-Version': 'v1-aes256gcm-rsaoaep-sha256',
        'X-Iv': ivB64,
        'X-Auth-Tag': authTagB64,
        'X-Encrypted-Data-Key': encryptedDataKeyB64,
        'X-Ciphertext-Sha256': ciphertextSha256Hex,
        'X-Timestamp': timestamp,
        'X-Nonce': nonce,
        'X-Signature': sigB64,
      },
      body: createReadStream(tmpCipherPath) as any,
    } as any);

    const text = await res.text();
    if (!res.ok) {
      throw new Error(`Upload failed (${res.status}): ${text}`);
    }

    await fs.unlink(tmpCipherPath).catch(() => undefined);
    const serverResponse = this.safeJson(text) as {
      backupId?: string;
      sizeBytes?: number;
      ciphertextSha256Hex?: string;
    };
    const backupId = serverResponse.backupId;
    if (!backupId) {
      throw new Error('Server did not return backupId');
    }
    return {
      backupId,
      dbName,
      sizeBytes: serverResponse.sizeBytes ?? sizeBytes,
      ciphertextSha256Hex:
        serverResponse.ciphertextSha256Hex ?? ciphertextSha256Hex,
    };
  }

  async runRestore(input: { backupId: string; targetDbName?: string }) {
    const agentId = process.env.BACKUP_AGENT_ID ?? 'local-agent';
    const serverUrl = process.env.BACKUP_SERVER_URL ?? 'http://localhost:3002';
    const hmacSecret = this.requiredEnv('BACKUP_HMAC_SECRET');

    const meta = await this.signedJsonRequest({
      serverUrl,
      agentId,
      hmacSecret,
      method: 'GET',
      path: `/backups/${encodeURIComponent(input.backupId)}/meta`,
      ciphertextSha256: 'meta',
    });

    const keyResp = await this.signedJsonRequest({
      serverUrl,
      agentId,
      hmacSecret,
      method: 'GET',
      path: `/backups/${encodeURIComponent(input.backupId)}/data-key`,
      ciphertextSha256: 'key',
    });

    const dataKey = Buffer.from(String(keyResp.dataKeyB64), 'base64');
    const iv = Buffer.from(String(meta.ivB64), 'base64');
    const authTag = Buffer.from(String(meta.authTagB64), 'base64');

    const tmpCipherPath = join(tmpdir(), `download-${input.backupId}.bin`);
    const tmpDumpPath = join(tmpdir(), `dump-${input.backupId}.dump`);

    await this.downloadToFile({
      serverUrl,
      agentId,
      hmacSecret,
      backupId: input.backupId,
      outPath: tmpCipherPath,
      ciphertextSha256: String(meta.ciphertextSha256Hex),
    });

    await this.decryptToDump({
      cipherPath: tmpCipherPath,
      dumpPath: tmpDumpPath,
      dataKey,
      iv,
      authTag,
      compressed: meta.compressed !== false,
    });

    const targetDbName = input.targetDbName ?? this.requiredEnv('PGDATABASE');
    await this.pgRestore({ dumpPath: tmpDumpPath, targetDbName });

    await fs.unlink(tmpCipherPath).catch(() => undefined);
    await fs.unlink(tmpDumpPath).catch(() => undefined);

    return { ok: true, backupId: input.backupId, restoredTo: targetDbName };
  }

  private async createEncryptedDumpFile(input: {
    dbName: string;
    compress: boolean;
    serverPublicKeyPath: string;
    outputPath: string;
  }): Promise<{
    ivB64: string;
    authTagB64: string;
    encryptedDataKeyB64: string;
    ciphertextSha256Hex: string;
    sizeBytes: number;
  }> {
    const publicKey = await fs.readFile(input.serverPublicKeyPath, 'utf8');
    const dataKey = randomBytes(32);
    const iv = randomBytes(12);

    const cipher = createCipheriv('aes-256-gcm', dataKey, iv);
    const gzip = input.compress ? createGzip() : undefined;

    const hash = createHash('sha256');
    let sizeBytes = 0;

    const out = createWriteStream(input.outputPath);
    cipher.on('data', (chunk: Buffer) => {
      sizeBytes += chunk.length;
      hash.update(chunk);
    });

    const { stream: dump, done } = this.pgDumpStream(input.dbName);
    if (gzip) {
      await pipeline(dump, gzip, cipher, out);
    } else {
      await pipeline(dump, cipher, out);
    }

    await done();

    const authTag = cipher.getAuthTag();
    const ciphertextSha256Hex = hash.digest('hex');

    const encryptedDataKey = publicEncrypt(
      {
        key: publicKey,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      dataKey,
    );

    return {
      ivB64: iv.toString('base64'),
      authTagB64: authTag.toString('base64'),
      encryptedDataKeyB64: encryptedDataKey.toString('base64'),
      ciphertextSha256Hex,
      sizeBytes,
    };
  }

  private pgDumpStream(dbName: string): {
    stream: NodeJS.ReadableStream;
    done: () => Promise<void>;
  } {
    const pgDumpPath = process.env.PG_DUMP_PATH ?? 'pg_dump';
    const args = ['-Fc', '--no-owner', '--no-acl', '--dbname', dbName];

    const child = spawn(pgDumpPath, args, {
      env: process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    const stderrChunks: Buffer[] = [];
    child.stderr?.on('data', (d: Buffer) => {
      stderrChunks.push(d);
    });

    if (!child.stdout) {
      throw new Error('pg_dump stdout is not available');
    }

    const out = new PassThrough();
    child.stdout.pipe(out);

    let dumpFailed: Error | null = null;
    const done = new Promise<void>((resolve, reject) => {
      child.on('error', reject);
      child.on('close', (code) => {
        if (code === 0) return resolve();
        const stderr = Buffer.concat(stderrChunks).toString('utf8');
        reject(new Error(`pg_dump failed (${code}): ${stderr}`));
      });
    }).catch((err: Error) => {
      dumpFailed = err;
    });

    const guardedDone = async () => {
      await done;
      if (dumpFailed) throw dumpFailed;
    };

    return { stream: out, done: guardedDone };
  }

  private async downloadToFile(input: {
    serverUrl: string;
    agentId: string;
    hmacSecret: string;
    backupId: string;
    outPath: string;
    ciphertextSha256: string;
  }): Promise<void> {
    const url = new URL(
      `/backups/${encodeURIComponent(input.backupId)}/download`,
      input.serverUrl,
    );
    const timestamp = String(Date.now());
    const nonce = randomBytes(16).toString('hex');
    const signingString = this.buildSigningString({
      method: 'GET',
      path: url.pathname,
      agentId: input.agentId,
      timestamp,
      nonce,
      ciphertextSha256: input.ciphertextSha256,
    });
    const sigB64 = createHmac('sha256', input.hmacSecret)
      .update(signingString)
      .digest('base64');

    const res = await fetch(url, {
      method: 'GET',
      headers: {
        'X-Agent-Id': input.agentId,
        'X-Timestamp': timestamp,
        'X-Nonce': nonce,
        'X-Signature': sigB64,
        'X-Ciphertext-Sha256': input.ciphertextSha256,
      },
    });

    if (!res.ok || !res.body) {
      throw new Error(`Download failed (${res.status})`);
    }

    const out = createWriteStream(input.outPath);
    await pipeline(res.body as any, out);
  }

  private async decryptToDump(input: {
    cipherPath: string;
    dumpPath: string;
    dataKey: Buffer;
    iv: Buffer;
    authTag: Buffer;
    compressed: boolean;
  }): Promise<void> {
    const decipher = createDecipheriv('aes-256-gcm', input.dataKey, input.iv);
    decipher.setAuthTag(input.authTag);

    const source = createReadStream(input.cipherPath);
    const out = createWriteStream(input.dumpPath);
    if (input.compressed) {
      await pipeline(source, decipher, createGunzip(), out);
    } else {
      await pipeline(source, decipher, out);
    }
  }

  private async pgRestore(input: {
    dumpPath: string;
    targetDbName: string;
  }): Promise<void> {
    const pgRestorePath = process.env.PG_RESTORE_PATH ?? 'pg_restore';
    const args = [
      '--clean',
      '--if-exists',
      '--no-owner',
      '--dbname',
      input.targetDbName,
      input.dumpPath,
    ];

    await new Promise<void>((resolve, reject) => {
      const child = spawn(pgRestorePath, args, {
        env: process.env,
        stdio: ['ignore', 'pipe', 'pipe'],
      });

      let stderr = '';
      child.stderr?.on('data', (d: Buffer) => {
        stderr += d.toString('utf8');
      });

      child.on('error', reject);
      child.on('close', (code) => {
        if (code === 0) return resolve();
        reject(new Error(`pg_restore failed (${code}): ${stderr}`));
      });
    });
  }

  private async signedJsonRequest(input: {
    serverUrl: string;
    agentId: string;
    hmacSecret: string;
    method: 'GET' | 'POST';
    path: string;
    ciphertextSha256: string;
  }): Promise<any> {
    const url = new URL(input.path, input.serverUrl);
    const timestamp = String(Date.now());
    const nonce = randomBytes(16).toString('hex');
    const signingString = this.buildSigningString({
      method: input.method,
      path: url.pathname,
      agentId: input.agentId,
      timestamp,
      nonce,
      ciphertextSha256: input.ciphertextSha256,
    });
    const sigB64 = createHmac('sha256', input.hmacSecret)
      .update(signingString)
      .digest('base64');

    const res = await fetch(url, {
      method: input.method,
      headers: {
        'Content-Type': 'application/json',
        'X-Agent-Id': input.agentId,
        'X-Timestamp': timestamp,
        'X-Nonce': nonce,
        'X-Signature': sigB64,
        'X-Ciphertext-Sha256': input.ciphertextSha256,
      },
    });
    const text = await res.text();
    if (!res.ok) throw new Error(`Request failed (${res.status}): ${text}`);
    return this.safeJson(text);
  }

  private buildSigningString(input: {
    method: string;
    path: string;
    agentId: string;
    timestamp: string;
    nonce: string;
    ciphertextSha256: string;
  }): string {
    return [
      input.method,
      input.path,
      input.timestamp,
      input.nonce,
      input.agentId,
      input.ciphertextSha256,
    ].join('\n');
  }

  private requiredEnv(name: string): string {
    const v = process.env[name];
    if (!v) throw new Error(`Missing env ${name}`);
    return v;
  }

  private safeJson(text: string): any {
    try {
      return JSON.parse(text);
    } catch {
      return { raw: text };
    }
  }
}
