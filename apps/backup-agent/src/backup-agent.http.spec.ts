import { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { AgentApiGuard } from './auth/agent-api.guard';
import { BackupAgentController } from './backup-agent.controller';
import { BackupAgentService } from './backup-agent.service';

describe('BackupAgentController http', () => {
  let app: INestApplication;
  const runBackup = jest.fn();
  const runRestore = jest.fn();

  beforeAll(async () => {
    process.env.BACKUP_AGENT_API_TOKEN = 'agent-token';
    const moduleRef = await Test.createTestingModule({
      controllers: [BackupAgentController],
      providers: [
        AgentApiGuard,
        {
          provide: BackupAgentService,
          useValue: { runBackup, runRestore },
        },
      ],
    }).compile();
    app = moduleRef.createNestApplication();
    await app.init();
  });

  afterAll(async () => {
    await app.close();
    delete process.env.BACKUP_AGENT_API_TOKEN;
  });

  beforeEach(() => {
    runBackup.mockReset();
    runRestore.mockReset();
    runBackup.mockResolvedValue({
      backupId: '11111111-1111-4111-8111-111111111111',
      dbName: 'postgres',
      sizeBytes: 4,
      ciphertextSha256Hex: 'ab',
    });
    runRestore.mockResolvedValue({
      ok: true,
      backupId: '11111111-1111-4111-8111-111111111111',
      restoredTo: 'postgres',
    });
  });

  it('rejects backup without a token', async () => {
    await request(app.getHttpServer()).post('/backup/run').send({}).expect(401);
    expect(runBackup).not.toHaveBeenCalled();
  });

  it('rejects a wrong token', async () => {
    await request(app.getHttpServer())
      .post('/backup/run')
      .set('authorization', 'Bearer wrong')
      .send({})
      .expect(401);
  });

  it('runs a backup and defaults compress to true', async () => {
    const res = await request(app.getHttpServer())
      .post('/backup/run')
      .set('authorization', 'Bearer agent-token')
      .send({ dbName: 'app' })
      .expect(201);
    expect(res.body.dbName).toBe('postgres');
    expect(runBackup).toHaveBeenCalledWith({ dbName: 'app', compress: true });
  });

  it('passes compress false through', async () => {
    await request(app.getHttpServer())
      .post('/backup/run')
      .set('x-agent-api-token', 'agent-token')
      .send({ dbName: 'app', compress: false })
      .expect(201);
    expect(runBackup).toHaveBeenCalledWith({ dbName: 'app', compress: false });
  });

  it('runs a restore', async () => {
    const backupId = '11111111-1111-4111-8111-111111111111';
    const res = await request(app.getHttpServer())
      .post('/restore/run')
      .set('authorization', 'Bearer agent-token')
      .send({ backupId, targetDbName: 'restored' })
      .expect(201);
    expect(res.body.restoredTo).toBe('postgres');
    expect(runRestore).toHaveBeenCalledWith({ backupId, targetDbName: 'restored' });
  });
});
