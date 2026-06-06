import { Controller, Get } from '@nestjs/common';
import { BackupServerService } from './backup-server.service';

@Controller()
export class BackupServerController {
  constructor(private readonly backupServerService: BackupServerService) {}

  @Get()
  getHello(): string {
    return this.backupServerService.getHello();
  }
}
