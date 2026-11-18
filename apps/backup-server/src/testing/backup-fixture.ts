import {
  constants,
  createCipheriv,
  createHash,
  createHmac,
  generateKeyPairSync,
  publicEncrypt,
  randomBytes,
} from 'crypto';
import { gzipSync } from 'zlib';

export type RsaPem = { publicKey: string; privateKey: string };

export function generateRsaPem(): RsaPem {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  return { publicKey, privateKey };
}

export type EncryptedBackup = {
  plain: Buffer;
  ciphertext: Buffer;
  dataKey: Buffer;
  compressed: boolean;
  ivB64: string;
  authTagB64: string;
  encryptedDataKeyB64: string;
  ciphertextSha256Hex: string;
};

export function encryptBackup(
  plain: Buffer,
  publicKey: string,
  compressed = true,
): EncryptedBackup {
  const dataKey = randomBytes(32);
  const iv = randomBytes(12);
  const payload = compressed ? gzipSync(plain) : plain;
  const cipher = createCipheriv('aes-256-gcm', dataKey, iv);
  const ciphertext = Buffer.concat([cipher.update(payload), cipher.final()]);
  const authTag = cipher.getAuthTag();
  const encryptedDataKey = publicEncrypt(
    {
      key: publicKey,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    dataKey,
  );
  return {
    plain,
    ciphertext,
    dataKey,
    compressed,
    ivB64: iv.toString('base64'),
    authTagB64: authTag.toString('base64'),
    encryptedDataKeyB64: encryptedDataKey.toString('base64'),
    ciphertextSha256Hex: createHash('sha256').update(ciphertext).digest('hex'),
  };
}

export function signRequest(input: {
  method: string;
  path: string;
  agentId: string;
  secret: string;
  ciphertextSha256: string;
  timestamp?: string;
  nonce?: string;
  encoding?: 'base64' | 'hex';
}): { timestamp: string; nonce: string; signature: string } {
  const timestamp = input.timestamp ?? String(Date.now());
  const nonce = input.nonce ?? randomBytes(16).toString('hex');
  const digest = createHmac('sha256', input.secret)
    .update(
      [
        input.method.toUpperCase(),
        input.path,
        timestamp,
        nonce,
        input.agentId,
        input.ciphertextSha256,
      ].join('\n'),
    )
    .digest();
  const encoding = input.encoding ?? 'base64';
  return {
    timestamp,
    nonce,
    signature: digest.toString(encoding),
  };
}

export function signedHeaders(input: {
  method: string;
  path: string;
  agentId: string;
  secret: string;
  ciphertextSha256: string;
  extra?: Record<string, string>;
  timestamp?: string;
  nonce?: string;
  encoding?: 'base64' | 'hex';
}): Record<string, string> {
  const signed = signRequest(input);
  return {
    'x-agent-id': input.agentId,
    'x-timestamp': signed.timestamp,
    'x-nonce': signed.nonce,
    'x-signature': signed.signature,
    'x-ciphertext-sha256': input.ciphertextSha256,
    ...input.extra,
  };
}
