import { Test, TestingModule } from '@nestjs/testing';
import { BackupServerController } from './backup-server.controller';
import { BackupServerService } from './backup-server.service';

describe('BackupServerController', () => {
  let backupServerController: BackupServerController;

  beforeEach(async () => {
    const app: TestingModule = await Test.createTestingModule({
      controllers: [BackupServerController],
      providers: [BackupServerService],
    }).compile();

    backupServerController = app.get<BackupServerController>(BackupServerController);
  });

  describe('root', () => {
    it('should return "Hello World!"', () => {
      expect(backupServerController.getHello()).toBe('Hello World!');
    });
  });
});
