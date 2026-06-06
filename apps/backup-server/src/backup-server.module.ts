import { Module } from '@nestjs/common';
import { BackupServerController } from './backup-server.controller';
import { BackupServerService } from './backup-server.service';
import { HmacGuard } from './auth/hmac.guard';
import { BackupsController } from './backups/backups.controller';
import { BackupsService } from './backups/backups.service';

@Module({
  imports: [],
  controllers: [BackupServerController, BackupsController],
  providers: [BackupServerService, BackupsService, HmacGuard],
})
export class BackupServerModule {}
