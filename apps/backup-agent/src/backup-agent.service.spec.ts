import { EventEmitter, PassThrough, Readable } from 'stream';
import { spawn } from 'child_process';
import { readFileSync } from 'fs';
import { mkdtemp, rm, writeFile } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { BackupAgentService } from './backup-agent.service';
import { decryptBackupToPlain, type BackupMeta } from '../../backup-server/src/crypto/decrypt-backup.util';
import {
  encryptBackup,
  generateRsaPem,
  signRequest,
} from '../../backup-server/src/testing/backup-fixture';

jest.mock('child_process', () => {
  const actual = jest.requireActual<typeof import('child_process')>('child_process');
  return { ...actual, spawn: jest.fn() };
});

const spawnMock = spawn as jest.MockedFunction<typeof spawn>;

function header(headers: Record<string, string>, name: string): string {
  const key = Object.keys(headers).find((item) => item.toLowerCase() === name.toLowerCase());
  if (!key) throw new Error(`missing header ${name}`);
  return headers[key];
}

function fakeProcess(options: { stdout?: Buffer; code?: number; stderr?: string }) {
  const stdout = new PassThrough();
  const stderr = new PassThrough();
  const proc = new EventEmitter();
  Object.assign(proc, { stdout, stderr, stdin: new PassThrough(), kill: () => true });
  setImmediate(() => {
    stdout.end(options.stdout ?? Buffer.alloc(0));
    stderr.end(options.stderr ?? '');
    proc.emit('close', options.code ?? 0);
  });
  return proc;
}

function jsonResponse(body: unknown, status = 200) {
  return {
    ok: status < 400,
    status,
    text: async () => JSON.stringify(body),
  };
}

describe('BackupAgentService', () => {
  let dir: string;
  let publicKeyPath: string;
  const keys = generateRsaPem();
  const secret = 'agent-hmac-secret';
  const calls: Array<{
    url: string;
    method: string;
    headers: Record<string, string>;
    body?: Buffer;
  }> = [];
  let restoredDump: Buffer | undefined;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 'backup-agent-'));
    publicKeyPath = join(dir, 'public.pem');
    await writeFile(publicKeyPath, keys.publicKey);
    process.env.BACKUP_AGENT_ID = 'local-agent';
    process.env.BACKUP_SERVER_URL = 'http://backup.example';
    process.env.BACKUP_HMAC_SECRET = secret;
    process.env.BACKUP_SERVER_PUBLIC_KEY_PATH = publicKeyPath;
    process.env.PGDATABASE = 'appdb';
    calls.length = 0;
    restoredDump = undefined;
    spawnMock.mockReset();
    spawnMock.mockImplementation(((command: string, args: readonly string[]) => {
      if (String(command).includes('pg_restore')) {
        restoredDump = readFileSync(args[args.length - 1]);
        return fakeProcess({});
      }
      return fakeProcess({ stdout: Buffer.from('PGDUMP-bytes') });
    }) as typeof spawn);
    global.fetch = jest.fn(async (url: string | URL, init?: RequestInit) => {
      const headers = (init?.headers ?? {}) as Record<string, string>;
      let body: Buffer | undefined;
      if (init?.body) {
        const chunks: Buffer[] = [];
        for await (const chunk of init.body as AsyncIterable<Buffer | Uint8Array>) {
          chunks.push(Buffer.from(chunk));
        }
        body = Buffer.concat(chunks);
      }
      const href = String(url);
      calls.push({ url: href, method: init?.method ?? 'GET', headers, body });
      if (href.endsWith('/meta')) return jsonResponse(pendingMeta);
      if (href.endsWith('/data-key')) return jsonResponse(pendingKey);
      if (href.endsWith('/download')) {
        return { ok: true, status: 200, body: Readable.from([pendingCipher]) };
      }
      return jsonResponse({
        backupId: '11111111-1111-4111-8111-111111111111',
        sizeBytes: body?.length ?? 0,
        ciphertextSha256Hex: header(headers, 'x-ciphertext-sha256'),
      }, 201);
    }) as typeof fetch;
  });

  afterEach(async () => {
    delete process.env.BACKUP_AGENT_ID;
    delete process.env.BACKUP_SERVER_URL;
    delete process.env.BACKUP_HMAC_SECRET;
    delete process.env.BACKUP_SERVER_PUBLIC_KEY_PATH;
    delete process.env.PGDATABASE;
    await rm(dir, { recursive: true, force: true });
  });

  let pendingMeta: Partial<BackupMeta> = {};
  let pendingKey: { dataKeyB64: string } = { dataKeyB64: '' };
  let pendingCipher = Buffer.alloc(0);

  function expectSigned(call: (typeof calls)[number], path: string, sha: string) {
    const expected = signRequest({
      method: call.method,
      path,
      agentId: 'local-agent',
      secret,
      ciphertextSha256: sha,
      timestamp: header(call.headers, 'x-timestamp'),
      nonce: header(call.headers, 'x-nonce'),
    });
    expect(header(call.headers, 'x-signature')).toBe(expected.signature);
  }

  it('encrypts a dump, signs the upload, and the server key can decrypt it', async () => {
    const service = new BackupAgentService();
    const result = await service.runBackup({ dbName: 'appdb', compress: true });

    expect(result.backupId).toBe('11111111-1111-4111-8111-111111111111');
    expect(calls).toHaveLength(1);
    const upload = calls[0];
    expect(upload.url).toBe('http://backup.example/backups');
    expect(header(upload.headers, 'x-enc-version')).toBe('v1-aes256gcm-rsaoaep-sha256');
    expect(header(upload.headers, 'x-db-name')).toBe('appdb');
    expect(header(upload.headers, 'x-compressed')).toBe('true');
    expectSigned(upload, '/backups', header(upload.headers, 'x-ciphertext-sha256'));

    const plain = decryptBackupToPlain(
      upload.body as Buffer,
      {
        id: result.backupId,
        agentId: 'local-agent',
        dbName: 'appdb',
        createdAt: '2026-01-01T00:00:00.000Z',
        sizeBytes: upload.body?.length ?? 0,
        encryptionVersion: 'v1-aes256gcm-rsaoaep-sha256',
        compressed: true,
        ivB64: header(upload.headers, 'x-iv'),
        authTagB64: header(upload.headers, 'x-auth-tag'),
        encryptedDataKeyB64: header(upload.headers, 'x-encrypted-data-key'),
        ciphertextSha256Hex: header(upload.headers, 'x-ciphertext-sha256'),
      },
      keys.privateKey,
    );
    expect(plain.toString()).toBe('PGDUMP-bytes');
  });

  it('uploads an uncompressed dump', async () => {
    const service = new BackupAgentService();
    await service.runBackup({ compress: false });
    const upload = calls[0];
    const plain = decryptBackupToPlain(
      upload.body as Buffer,
      {
        id: '11111111-1111-4111-8111-111111111111',
        agentId: 'local-agent',
        dbName: 'appdb',
        createdAt: '2026-01-01T00:00:00.000Z',
        sizeBytes: upload.body?.length ?? 0,
        encryptionVersion: 'v1',
        compressed: false,
        ivB64: header(upload.headers, 'x-iv'),
        authTagB64: header(upload.headers, 'x-auth-tag'),
        encryptedDataKeyB64: header(upload.headers, 'x-encrypted-data-key'),
        ciphertextSha256Hex: header(upload.headers, 'x-ciphertext-sha256'),
      },
      keys.privateKey,
    );
    expect(plain.toString()).toBe('PGDUMP-bytes');
  });

  it('fails when pg_dump fails', async () => {
    spawnMock.mockImplementation((() =>
      fakeProcess({ code: 1, stderr: 'database missing' })) as typeof spawn);
    const service = new BackupAgentService();
    await expect(service.runBackup({ compress: false })).rejects.toThrow('pg_dump failed');
  });

  it('fails when the server rejects the upload', async () => {
    global.fetch = jest.fn(async () => ({
      ok: false,
      status: 500,
      text: async () => 'disk full',
    })) as typeof fetch;
    const service = new BackupAgentService();
    await expect(service.runBackup({ compress: false })).rejects.toThrow(
      'Upload failed (500): disk full',
    );
  });

  it('fails when the server does not return a backup id', async () => {
    global.fetch = jest.fn(async () => ({
      ok: true,
      status: 201,
      text: async () => JSON.stringify({ sizeBytes: 1 }),
    })) as typeof fetch;
    const service = new BackupAgentService();
    await expect(service.runBackup({ compress: false })).rejects.toThrow(
      'Server did not return backupId',
    );
  });

  it('requires the hmac secret', async () => {
    delete process.env.BACKUP_HMAC_SECRET;
    const service = new BackupAgentService();
    await expect(service.runBackup({ compress: false })).rejects.toThrow(
      'Missing env BACKUP_HMAC_SECRET',
    );
  });

  it('downloads, decrypts and restores a backup', async () => {
    const plain = Buffer.from('restored-dump');
    const enc = encryptBackup(plain, keys.publicKey, true);
    const backupId = '22222222-2222-4222-8222-222222222222';
    pendingCipher = enc.ciphertext;
    pendingKey = { dataKeyB64: enc.dataKey.toString('base64') };
    pendingMeta = {
      ivB64: enc.ivB64,
      authTagB64: enc.authTagB64,
      compressed: true,
      ciphertextSha256Hex: enc.ciphertextSha256Hex,
    };

    const service = new BackupAgentService();
    const result = await service.runRestore({ backupId, targetDbName: 'restored' });

    expect(result).toEqual({ ok: true, backupId, restoredTo: 'restored' });
    expect(restoredDump?.equals(plain)).toBe(true);
    expect(calls.map((call) => new URL(call.url).pathname)).toEqual([
      `/backups/${backupId}/meta`,
      `/backups/${backupId}/data-key`,
      `/backups/${backupId}/download`,
    ]);
    expectSigned(calls[0], `/backups/${backupId}/meta`, 'meta');
    expectSigned(calls[1], `/backups/${backupId}/data-key`, 'key');
    expectSigned(calls[2], `/backups/${backupId}/download`, enc.ciphertextSha256Hex);
    const restoreCall = spawnMock.mock.calls.find((call) =>
      String(call[0]).includes('pg_restore'),
    );
    expect(restoreCall?.[1]).toEqual(
      expect.arrayContaining(['--dbname', 'restored']),
    );
  });

  it('fails when restore metadata cannot be loaded', async () => {
    global.fetch = jest.fn(async () => ({
      ok: false,
      status: 404,
      text: async () => 'missing',
    })) as typeof fetch;
    const service = new BackupAgentService();
    await expect(
      service.runRestore({ backupId: '22222222-2222-4222-8222-222222222222' }),
    ).rejects.toThrow('Request failed (404)');
  });

  it('fails when pg_restore fails', async () => {
    const plain = Buffer.from('restored-dump');
    const enc = encryptBackup(plain, keys.publicKey, false);
    pendingCipher = enc.ciphertext;
    pendingKey = { dataKeyB64: enc.dataKey.toString('base64') };
    pendingMeta = {
      ivB64: enc.ivB64,
      authTagB64: enc.authTagB64,
      compressed: false,
      ciphertextSha256Hex: enc.ciphertextSha256Hex,
    };
    spawnMock.mockImplementation((() =>
      fakeProcess({ code: 1, stderr: 'restore boom' })) as typeof spawn);
    const service = new BackupAgentService();
    await expect(
      service.runRestore({ backupId: '22222222-2222-4222-8222-222222222222' }),
    ).rejects.toThrow('pg_restore failed');
  });
});
