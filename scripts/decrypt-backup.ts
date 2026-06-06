import { config as loadEnv } from 'dotenv';
import { createHash } from 'crypto';
import { mkdir, readFile, readdir, writeFile } from 'fs/promises';
import { dirname, join } from 'path';
import {
  decryptBackupToPlain,
  type BackupMeta,
} from '../apps/backup-server/src/crypto/decrypt-backup.util';

loadEnv({ override: false });

type CliOptions = {
  backupId?: string;
  agentId?: string;
  all: boolean;
  out?: string;
  dir?: string;
  skipSha: boolean;
};

function parseArgs(argv: string[]): CliOptions {
  const opts: CliOptions = { all: false, skipSha: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--all') opts.all = true;
    else if (arg === '--skip-sha') opts.skipSha = true;
    else if (arg === '--id') opts.backupId = argv[++i];
    else if (arg === '--agent') opts.agentId = argv[++i];
    else if (arg === '--out' || arg === '-o') opts.out = argv[++i];
    else if (arg === '--dir') opts.dir = argv[++i];
    else if (arg === '--help' || arg === '-h') {
      printHelp();
      process.exit(0);
    } else if (!arg.startsWith('-')) {
      opts.backupId = arg;
    }
  }
  return opts;
}

function printHelp(): void {
  console.log(`Decrypt backups on the server (destination host).

Usage:
  bun run decrypt-backup <backupId>
  bun run decrypt-backup --id <backupId> [--agent local-agent] [--out path.dump]
  bun run decrypt-backup --dir data/backups/local-agent/<backupId>
  bun run decrypt-backup --all

Environment (.env):
  BACKUP_STORAGE_DIR=./data/backups
  BACKUP_SERVER_PRIVATE_KEY_PATH=./keys/backup-server-private.pem
  BACKUP_EXPORTS_DIR=./data/exports
`);
}

function storageDir(): string {
  return process.env.BACKUP_STORAGE_DIR
    ? join(process.env.BACKUP_STORAGE_DIR)
    : join(process.cwd(), 'data', 'backups');
}

function exportsDir(): string {
  return process.env.BACKUP_EXPORTS_DIR
    ? join(process.env.BACKUP_EXPORTS_DIR)
    : join(process.cwd(), 'data', 'exports');
}

function privateKeyPath(): string {
  const path = process.env.BACKUP_SERVER_PRIVATE_KEY_PATH;
  if (!path) {
    throw new Error('BACKUP_SERVER_PRIVATE_KEY_PATH is not set');
  }
  return path;
}

async function readBackupFromDir(backupDir: string): Promise<{
  meta: BackupMeta;
  ciphertext: Buffer;
}> {
  const meta = JSON.parse(
    await readFile(join(backupDir, 'meta.json'), 'utf8'),
  ) as BackupMeta;
  const ciphertext = await readFile(join(backupDir, 'payload.bin'));
  return { meta, ciphertext };
}

function defaultOutPath(meta: BackupMeta): string {
  return join(exportsDir(), meta.agentId, `${meta.id}.dump`);
}

async function writePlain(
  plain: Buffer,
  meta: BackupMeta,
  outPath?: string,
): Promise<string> {
  const target = outPath ?? defaultOutPath(meta);
  await mkdir(dirname(target), { recursive: true });
  await writeFile(target, plain);
  return target;
}

async function decryptOne(
  backupDir: string,
  opts: CliOptions,
): Promise<string> {
  const privateKey = await readFile(privateKeyPath(), 'utf8');
  const { meta, ciphertext } = await readBackupFromDir(backupDir);
  const plain = decryptBackupToPlain(ciphertext, meta, privateKey, {
    verifySha256: !opts.skipSha,
  });
  const sha = createHash('sha256').update(plain).digest('hex');
  const target = await writePlain(plain, meta, opts.out);
  console.log(
    JSON.stringify(
      {
        ok: true,
        backupId: meta.id,
        agentId: meta.agentId,
        dbName: meta.dbName,
        compressed: meta.compressed !== false,
        ciphertextBytes: ciphertext.length,
        plainBytes: plain.length,
        plainSha256: sha,
        output: target,
      },
      null,
      2,
    ),
  );
  return target;
}

async function findBackupDir(
  backupId: string,
  agentId?: string,
): Promise<string> {
  const root = storageDir();
  const agents = agentId ? [join(root, agentId)] : await listDirs(root);

  for (const agentDir of agents) {
    const candidate = join(agentDir, backupId);
    try {
      await readFile(join(candidate, 'meta.json'), 'utf8');
      return candidate;
    } catch {}
  }
  throw new Error(`Backup not found: ${backupId}`);
}

async function listDirs(root: string): Promise<string[]> {
  try {
    const items = await readdir(root, { withFileTypes: true });
    return items.filter((d) => d.isDirectory()).map((d) => join(root, d.name));
  } catch {
    return [];
  }
}

async function decryptAll(opts: CliOptions): Promise<void> {
  const root = storageDir();
  const agents = await listDirs(root);
  let count = 0;

  for (const agentDir of agents) {
    const backups = await listDirs(agentDir);
    for (const backupDir of backups) {
      try {
        await decryptOne(backupDir, { ...opts, out: undefined });
        count++;
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        console.error(`SKIP ${backupDir}: ${message}`);
      }
    }
  }

  console.log(`Done. Decrypted ${count} backup(s) into ${exportsDir()}`);
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv.slice(2));

  if (opts.dir) {
    await decryptOne(opts.dir, opts);
    return;
  }

  if (opts.all) {
    await decryptAll(opts);
    return;
  }

  if (!opts.backupId) {
    printHelp();
    process.exit(1);
  }

  const backupDir = await findBackupDir(opts.backupId, opts.agentId);
  await decryptOne(backupDir, opts);
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
