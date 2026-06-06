import { Module } from '@nestjs/common';
import { AgentApiGuard } from './auth/agent-api.guard';
import { BackupAgentController } from './backup-agent.controller';
import { BackupAgentService } from './backup-agent.service';

@Module({
  imports: [],
  controllers: [BackupAgentController],
  providers: [BackupAgentService, AgentApiGuard],
})
export class BackupAgentModule {}
