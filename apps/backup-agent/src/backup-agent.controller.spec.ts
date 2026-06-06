import { Test, TestingModule } from '@nestjs/testing';
import { AgentApiGuard } from './auth/agent-api.guard';
import { BackupAgentController } from './backup-agent.controller';
import { BackupAgentService } from './backup-agent.service';

describe('BackupAgentController', () => {
  let controller: BackupAgentController;

  beforeEach(async () => {
    const app: TestingModule = await Test.createTestingModule({
      controllers: [BackupAgentController],
      providers: [
        {
          provide: BackupAgentService,
          useValue: {
            runBackup: jest.fn(),
            runRestore: jest.fn(),
          },
        },
        {
          provide: AgentApiGuard,
          useValue: { canActivate: () => true },
        },
      ],
    })
      .overrideGuard(AgentApiGuard)
      .useValue({ canActivate: () => true })
      .compile();

    controller = app.get<BackupAgentController>(BackupAgentController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
