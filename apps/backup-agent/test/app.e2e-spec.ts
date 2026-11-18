import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { BackupAgentModule } from './../src/backup-agent.module';

describe('BackupAgentController (e2e)', () => {
  let app: INestApplication;

  beforeEach(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [BackupAgentModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();
  });

  afterEach(async () => {
    await app.close();
  });

  it('GET / is not an agent route', () => {
    return request(app.getHttpServer()).get('/').expect(404);
  });

  it('POST /backup/run without a token is rejected', () => {
    return request(app.getHttpServer()).post('/backup/run').send({}).expect(401);
  });

  it('POST /restore/run without a token is rejected', () => {
    return request(app.getHttpServer())
      .post('/restore/run')
      .send({ backupId: '11111111-1111-4111-8111-111111111111' })
      .expect(401);
  });
});
