import { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { mkdtemp, rm, writeFile } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import request from 'supertest';
import { HmacGuard } from '../auth/hmac.guard';
import { encryptBackup, generateRsaPem, signedHeaders } from '../testing/backup-fixture';
import { BackupsController } from './backups.controller';
import { BackupsService } from './backups.service';

const AGENT = 'local-agent';
const SECRET = 'controller-hmac-secret';

function rawBody(
  res: NodeJS.ReadableStream,
  callback: (err: Error | null, body: Buffer) => void,
) {
  const chunks: Buffer[] = [];
  res.on('data', (chunk: Buffer) => chunks.push(chunk));
  res.on('end', () => callback(null, Buffer.concat(chunks)));
}

describe('BackupsController', () => {
  let app: INestApplication;
  let dir: string;
  const keys = generateRsaPem();

  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), 'backup-http-'));
    const keyPath = join(dir, 'private.pem');
    await writeFile(keyPath, keys.privateKey);
    process.env.BACKUP_STORAGE_DIR = dir;
    process.env.BACKUP_SERVER_PRIVATE_KEY_PATH = keyPath;
    process.env.BACKUP_HMAC_SECRET = SECRET;
    process.env.BACKUP_HMAC_SKEW_MS = '300000';

    const moduleRef = await Test.createTestingModule({
      controllers: [BackupsController],
      providers: [BackupsService, HmacGuard],
    }).compile();
    app = moduleRef.createNestApplication();
    await app.init();
  });

  afterAll(async () => {
    await app.close();
    delete process.env.BACKUP_STORAGE_DIR;
    delete process.env.BACKUP_SERVER_PRIVATE_KEY_PATH;
    delete process.env.BACKUP_HMAC_SECRET;
    delete process.env.BACKUP_HMAC_SKEW_MS;
    await rm(dir, { recursive: true, force: true });
  });

  function auth(method: string, path: string, sha: string, extra?: Record<string, string>) {
    return signedHeaders({
      method,
      path,
      agentId: AGENT,
      secret: SECRET,
      ciphertextSha256: sha,
      extra,
    });
  }

  it('rejects an upload without a signature', async () => {
    await request(app.getHttpServer()).post('/backups').send(Buffer.from('nope')).expect(401);
  });

  it('uploads, lists, downloads and unwraps a backup', async () => {
    const enc = encryptBackup(Buffer.from('http-dump'), keys.publicKey, true);
    const uploadPath = '/backups';
    const uploaded = await request(app.getHttpServer())
      .post(uploadPath)
      .set(
        auth('POST', uploadPath, enc.ciphertextSha256Hex, {
          'x-db-name': 'postgres',
          'x-enc-version': 'v1-aes256gcm-rsaoaep-sha256',
          'x-compressed': 'true',
          'x-iv': enc.ivB64,
          'x-auth-tag': enc.authTagB64,
          'x-encrypted-data-key': enc.encryptedDataKeyB64,
        }),
      )
      .set('content-type', 'application/octet-stream')
      .send(enc.ciphertext)
      .expect(201);

    const backupId = uploaded.body.backupId as string;
    expect(uploaded.body.ciphertextSha256Hex).toBe(enc.ciphertextSha256Hex);

    const listPath = '/backups';
    const list = await request(app.getHttpServer())
      .get(listPath)
      .set(auth('GET', listPath, 'list'))
      .expect(200);
    expect(list.body.map((item: { id: string }) => item.id)).toContain(backupId);

    const metaPath = `/backups/${backupId}/meta`;
    const meta = await request(app.getHttpServer())
      .get(metaPath)
      .set(auth('GET', metaPath, 'meta'))
      .expect(200);
    expect(meta.body.dbName).toBe('postgres');

    const downloadPath = `/backups/${backupId}/download`;
    const downloaded = await request(app.getHttpServer())
      .get(downloadPath)
      .set(auth('GET', downloadPath, enc.ciphertextSha256Hex))
      .buffer(true)
      .parse(rawBody)
      .expect(200);
    expect(Buffer.from(downloaded.body).equals(enc.ciphertext)).toBe(true);
    expect(downloaded.headers['x-iv']).toBe(enc.ivB64);

    const keyPath = `/backups/${backupId}/data-key`;
    const key = await request(app.getHttpServer())
      .get(keyPath)
      .set(auth('GET', keyPath, 'key'))
      .expect(200);
    expect(key.body.dataKeyB64).toBe(enc.dataKey.toString('base64'));
  });

  it('rejects a second request with the same nonce', async () => {
    const nonce = 'http-replay-nonce-01';
    const path = '/backups';
    const signed = signedHeaders({
      method: 'GET',
      path,
      agentId: AGENT,
      secret: SECRET,
      ciphertextSha256: 'list',
      nonce,
    });
    await request(app.getHttpServer()).get(path).set(signed).expect(200);
    await request(app.getHttpServer()).get(path).set(signed).expect(401);
  });
});
