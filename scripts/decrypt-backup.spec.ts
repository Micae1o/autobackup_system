import { mkdtemp, readFile, rm, writeFile, mkdir } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { runCli } from './decrypt-backup';
import { encryptBackup, generateRsaPem } from '../apps/backup-server/src/testing/backup-fixture';

const AGENT = 'local-agent';
const ID_A = '11111111-1111-4111-8111-111111111111';
const ID_B = '22222222-2222-4222-8222-222222222222';

describe('decrypt-backup cli', () => {
  let dir: string;
  let storage: string;
  let exportsDir: string;
  let keyPath: string;
  const keys = generateRsaPem();
  const plain = Buffer.from('cli-dump');

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 'decrypt-cli-'));
    storage = join(dir, 'backups');
    exportsDir = join(dir, 'exports');
    keyPath = join(dir, 'private.pem');
    await writeFile(keyPath, keys.privateKey);
    process.env.BACKUP_STORAGE_DIR = storage;
    process.env.BACKUP_EXPORTS_DIR = exportsDir;
    process.env.BACKUP_SERVER_PRIVATE_KEY_PATH = keyPath;
  });

  afterEach(async () => {
    delete process.env.BACKUP_STORAGE_DIR;
    delete process.env.BACKUP_EXPORTS_DIR;
    delete process.env.BACKUP_SERVER_PRIVATE_KEY_PATH;
    await rm(dir, { recursive: true, force: true });
  });

  async function writeBackup(id: string, sha?: string) {
    const enc = encryptBackup(plain, keys.publicKey, true);
    const folder = join(storage, AGENT, id);
    await mkdir(folder, { recursive: true });
    await writeFile(join(folder, 'payload.bin'), enc.ciphertext);
    await writeFile(
      join(folder, 'meta.json'),
      JSON.stringify({
        id,
        agentId: AGENT,
        dbName: 'postgres',
        createdAt: '2026-01-01T00:00:00.000Z',
        sizeBytes: enc.ciphertext.length,
        encryptionVersion: 'v1-aes256gcm-rsaoaep-sha256',
        compressed: true,
        ivB64: enc.ivB64,
        authTagB64: enc.authTagB64,
        encryptedDataKeyB64: enc.encryptedDataKeyB64,
        ciphertextSha256Hex: sha ?? enc.ciphertextSha256Hex,
      }),
    );
    return folder;
  }

  it('prints help when no backup is given', async () => {
    const code = await runCli([]);
    expect(code).toBe(1);
  });

  it('decrypts one backup by directory', async () => {
    const folder = await writeBackup(ID_A);
    const out = join(dir, 'one.dump');
    const code = await runCli(['--dir', folder, '--out', out]);
    expect(code).toBe(0);
    expect((await readFile(out)).equals(plain)).toBe(true);
  });

  it('decrypts one backup by id', async () => {
    await writeBackup(ID_A);
    const code = await runCli(['--id', ID_A, '--agent', AGENT]);
    expect(code).toBe(0);
    expect((await readFile(join(exportsDir, AGENT, `${ID_A}.dump`))).equals(plain)).toBe(true);
  });

  it('rejects a tampered sha256 unless skip is set', async () => {
    const folder = await writeBackup(ID_A, 'ab'.repeat(32));
    await expect(runCli(['--dir', folder, '--out', join(dir, 'bad.dump')])).rejects.toThrow(
      'ciphertext SHA-256 mismatch',
    );
    const out = join(dir, 'skipped.dump');
    const code = await runCli(['--dir', folder, '--skip-sha', '--out', out]);
    expect(code).toBe(0);
    expect((await readFile(out)).equals(plain)).toBe(true);
  });

  it('decrypts every backup and skips a broken one', async () => {
    await writeBackup(ID_A);
    await writeBackup(ID_B, 'cd'.repeat(32));
    const errors: string[] = [];
    const spy = jest.spyOn(console, 'error').mockImplementation((message: unknown) => {
      errors.push(String(message));
    });
    const code = await runCli(['--all']);
    spy.mockRestore();
    expect(code).toBe(0);
    expect((await readFile(join(exportsDir, AGENT, `${ID_A}.dump`))).equals(plain)).toBe(true);
    expect(errors.some((line) => line.includes('SHA-256'))).toBe(true);
  });

  it('fails when the backup id does not exist', async () => {
    await expect(runCli([ID_A])).rejects.toThrow('Backup not found');
  });
});
