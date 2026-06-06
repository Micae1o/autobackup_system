import { NestFactory } from '@nestjs/core';
import { BackupAgentModule } from './backup-agent.module';
import { config as loadEnv } from 'dotenv';

async function bootstrap() {
  loadEnv({ override: false });
  const app = await NestFactory.create(BackupAgentModule);
  const port = Number(
    process.env.BACKUP_AGENT_PORT ?? process.env.PORT ?? 3001,
  );
  const host = process.env.BACKUP_AGENT_HOST ?? '127.0.0.1';
  await app.listen(port, host);
}
void bootstrap();
