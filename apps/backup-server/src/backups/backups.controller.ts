import {
  Controller,
  Get,
  Param,
  Post,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { validateAgentId } from '../auth/agent-id.util';
import { HmacGuard } from '../auth/hmac.guard';
import { BackupsService } from './backups.service';

@Controller('backups')
export class BackupsController {
  constructor(private readonly backups: BackupsService) {}

  @UseGuards(HmacGuard)
  @Post()
  async upload(@Req() req: Request, @Res() res: Response): Promise<void> {
    const result = await this.backups.handleUpload(req);
    res.status(201).json(result);
  }

  @UseGuards(HmacGuard)
  @Get()
  async list(@Req() req: Request) {
    const agentId = this.getAgentId(req);
    return this.backups.listBackups(agentId);
  }

  @UseGuards(HmacGuard)
  @Get(':id/meta')
  async meta(@Req() req: Request, @Param('id') id: string) {
    return this.backups.getMeta(this.getAgentId(req), id);
  }

  @UseGuards(HmacGuard)
  @Get(':id/download')
  async download(
    @Req() req: Request,
    @Param('id') id: string,
    @Res() res: Response,
  ): Promise<void> {
    const { stream, meta } = await this.backups.openPayloadStream(
      this.getAgentId(req),
      id,
    );
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('X-Iv', meta.ivB64);
    res.setHeader('X-Auth-Tag', meta.authTagB64);
    res.setHeader('X-Encrypted-Data-Key', meta.encryptedDataKeyB64);
    res.setHeader('X-Ciphertext-Sha256', meta.ciphertextSha256Hex);
    stream.pipe(res);
  }

  @UseGuards(HmacGuard)
  @Get(':id/data-key')
  async dataKey(@Req() req: Request, @Param('id') id: string) {
    return this.backups.getDataKey(this.getAgentId(req), id);
  }

  private getAgentId(req: Request): string {
    const raw = req.headers['x-agent-id'];
    const value = Array.isArray(raw) ? raw[0] : raw;
    if (!value) throw new Error('Missing X-Agent-Id');
    return validateAgentId(String(value));
  }
}
