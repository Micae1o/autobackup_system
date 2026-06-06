import { NestFactory } from '@nestjs/core';
import { BackupServerModule } from './backup-server.module';
import { config as loadEnv } from 'dotenv';

async function bootstrap() {
  (loadEnv as unknown as (opts?: { override?: boolean }) => unknown)({
    override: false,
  });
  const app = await NestFactory.create(BackupServerModule);
  const port = Number(
    process.env.BACKUP_SERVER_PORT ?? process.env.PORT ?? 3002,
  );
  await app.listen(port);
}
void bootstrap();
