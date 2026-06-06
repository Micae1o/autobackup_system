import { Injectable } from '@nestjs/common';

@Injectable()
export class BackupServerService {
  getHello(): string {
    return 'Hello World!';
  }
}
