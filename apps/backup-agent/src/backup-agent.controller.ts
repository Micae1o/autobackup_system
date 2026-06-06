import { Body, Controller, Post, UseGuards } from '@nestjs/common';
import { AgentApiGuard } from './auth/agent-api.guard';
import { BackupAgentService } from './backup-agent.service';

@Controller()
@UseGuards(AgentApiGuard)
export class BackupAgentController {
  constructor(private readonly backupAgentService: BackupAgentService) {}

  @Post('backup/run')
  runBackup(@Body() body: { dbName?: string; compress?: boolean }) {
    return this.backupAgentService.runBackup({
      dbName: body.dbName,
      compress: body.compress ?? true,
    });
  }

  @Post('restore/run')
  runRestore(@Body() body: { backupId: string; targetDbName?: string }) {
    return this.backupAgentService.runRestore({
      backupId: body.backupId,
      targetDbName: body.targetDbName,
    });
  }
}
