import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { Readable } from 'stream';
import type { Request } from 'express';
import { BackupsService } from './backups.service';
import { encryptBackup, generateRsaPem } from '../testing/backup-fixture';

const AGENT = 'local-agent';
const BACKUP_ID = '11111111-1111-4111-8111-111111111111';

function uploadRequest(body: Buffer, headers: Record<string, string>): Request {
  const req = Readable.from([body]);
  return Object.assign(req, { headers, method: 'POST' }) as unknown as Request;
}

describe('BackupsService', () => {
  let dir: string;
  let keyPath: string;
  let service: BackupsService;
  const keys = generateRsaPem();

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 'backup-svc-'));
    keyPath = join(dir, 'private.pem');
    await writeFile(keyPath, keys.privateKey);
    process.env.BACKUP_STORAGE_DIR = dir;
    process.env.BACKUP_SERVER_PRIVATE_KEY_PATH = keyPath;
    service = new BackupsService();
  });

  afterEach(async () => {
    delete process.env.BACKUP_STORAGE_DIR;
    delete process.env.BACKUP_SERVER_PRIVATE_KEY_PATH;
    await rm(dir, { recursive: true, force: true });
  });

  function headers(enc: ReturnType<typeof encryptBackup>, patch: Record<string, string> = {}) {
    return {
      'x-agent-id': AGENT,
      'x-db-name': 'postgres',
      'x-enc-version': 'v1-aes256gcm-rsaoaep-sha256',
      'x-compressed': String(enc.compressed),
      'x-iv': enc.ivB64,
      'x-auth-tag': enc.authTagB64,
      'x-encrypted-data-key': enc.encryptedDataKeyB64,
      'x-ciphertext-sha256': enc.ciphertextSha256Hex,
      ...patch,
    };
  }

  it('stores ciphertext and returns the data key only to the owner', async () => {
    const enc = encryptBackup(Buffer.from('dump-body'), keys.publicKey, true);
    const saved = await service.handleUpload(uploadRequest(enc.ciphertext, headers(enc)));

    expect(saved.ciphertextSha256Hex).toBe(enc.ciphertextSha256Hex);
    expect(saved.sizeBytes).toBe(enc.ciphertext.length);

    const payload = await readFile(join(dir, AGENT, saved.backupId, 'payload.bin'));
    expect(payload.equals(enc.ciphertext)).toBe(true);

    const meta = await service.getMeta(AGENT, saved.backupId);
    expect(meta.dbName).toBe('postgres');
    expect(meta.compressed).toBe(true);

    const opened = await service.openPayloadStream(AGENT, saved.backupId);
    const chunks: Buffer[] = [];
    for await (const chunk of opened.stream) {
      chunks.push(Buffer.from(chunk));
    }
    expect(Buffer.concat(chunks).equals(enc.ciphertext)).toBe(true);

    const key = await service.getDataKey(AGENT, saved.backupId);
    expect(key.dataKeyB64).toBe(enc.dataKey.toString('base64'));

    const listed = await service.listBackups(AGENT);
    expect(listed.map((item) => item.id)).toEqual([saved.backupId]);
  });

  it('accepts an uncompressed upload', async () => {
    const enc = encryptBackup(Buffer.from('plain-dump'), keys.publicKey, false);
    const saved = await service.handleUpload(uploadRequest(enc.ciphertext, headers(enc)));
    const meta = await service.getMeta(AGENT, saved.backupId);
    expect(meta.compressed).toBe(false);
  });

  it('deletes the folder when the declared sha256 does not match', async () => {
    const enc = encryptBackup(Buffer.from('dump-body'), keys.publicKey, false);
    await expect(
      service.handleUpload(
        uploadRequest(enc.ciphertext, headers(enc, { 'x-ciphertext-sha256': 'cd'.repeat(32) })),
      ),
    ).rejects.toThrow('ciphertextSha256 mismatch');
    await expect(readdir(join(dir, AGENT))).resolves.toEqual([]);
  });

  it('rejects a bad compressed flag before writing', async () => {
    const enc = encryptBackup(Buffer.from('dump-body'), keys.publicKey, false);
    await expect(
      service.handleUpload(
        uploadRequest(enc.ciphertext, headers(enc, { 'x-compressed': 'maybe' })),
      ),
    ).rejects.toThrow('Invalid X-Compressed');
  });

  it('rejects a missing upload header', async () => {
    const enc = encryptBackup(Buffer.from('dump-body'), keys.publicKey, false);
    const incomplete = headers(enc);
    delete incomplete['x-db-name'];
    await expect(service.handleUpload(uploadRequest(enc.ciphertext, incomplete))).rejects.toThrow(
      'Missing header x-db-name',
    );
  });

  it('rejects an agent id that escapes the storage directory', async () => {
    await expect(service.listBackups('..')).rejects.toThrow('Invalid storage path');
  });

  it('returns not found for an unknown backup', async () => {
    await expect(service.getMeta(AGENT, BACKUP_ID)).rejects.toThrow('Backup not found');
  });

  it('rejects a backup whose meta belongs to another agent', async () => {
    const folder = join(dir, AGENT, BACKUP_ID);
    await mkdir(folder, { recursive: true });
    await writeFile(join(folder, 'payload.bin'), Buffer.from('x'));
    await writeFile(
      join(folder, 'meta.json'),
      JSON.stringify({
        id: BACKUP_ID,
        agentId: 'other-agent',
        dbName: 'postgres',
        createdAt: '2026-01-01T00:00:00.000Z',
        sizeBytes: 1,
        encryptionVersion: 'v1',
        compressed: false,
        ivB64: 'aa',
        authTagB64: 'bb',
        encryptedDataKeyB64: 'cc',
        ciphertextSha256Hex: 'dd',
      }),
    );
    await expect(service.getMeta(AGENT, BACKUP_ID)).rejects.toThrow(
      'Backup does not belong to this agent',
    );
  });

  it('lists only backups of the requested agent, newest first', async () => {
    const agentDir = join(dir, AGENT);
    await mkdir(join(agentDir, BACKUP_ID), { recursive: true });
    const older = '22222222-2222-4222-8222-222222222222';
    const newer = '33333333-3333-4333-8333-333333333333';
    for (const [id, createdAt] of [
      [older, '2026-01-01T00:00:00.000Z'],
      [newer, '2026-06-01T00:00:00.000Z'],
    ] as const) {
      await mkdir(join(agentDir, id), { recursive: true });
      await writeFile(
        join(agentDir, id, 'meta.json'),
        JSON.stringify({
          id,
          agentId: AGENT,
          dbName: 'postgres',
          createdAt,
          sizeBytes: 1,
          encryptionVersion: 'v1',
          compressed: false,
          ivB64: 'aa',
          authTagB64: 'bb',
          encryptedDataKeyB64: 'cc',
          ciphertextSha256Hex: 'dd',
        }),
      );
    }
    const listed = await service.listBackups(AGENT);
    expect(listed.map((item) => item.id)).toEqual([newer, older]);
  });

  it('refuses to unwrap a data key when the private key path is missing', async () => {
    const enc = encryptBackup(Buffer.from('dump-body'), keys.publicKey, false);
    const saved = await service.handleUpload(uploadRequest(enc.ciphertext, headers(enc)));
    delete process.env.BACKUP_SERVER_PRIVATE_KEY_PATH;
    await expect(service.getDataKey(AGENT, saved.backupId)).rejects.toThrow(
      'BACKUP_SERVER_PRIVATE_KEY_PATH is required',
    );
  });
});
