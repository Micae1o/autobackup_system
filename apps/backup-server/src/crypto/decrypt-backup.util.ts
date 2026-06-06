import {
  constants,
  createDecipheriv,
  createHash,
  privateDecrypt,
  timingSafeEqual,
} from 'crypto';
import { gunzipSync } from 'zlib';

export type BackupMeta = {
  id: string;
  agentId: string;
  dbName: string;
  createdAt: string;
  sizeBytes: number;
  encryptionVersion: string;
  compressed?: boolean;
  ivB64: string;
  authTagB64: string;
  encryptedDataKeyB64: string;
  ciphertextSha256Hex: string;
};

export function unwrapDataKey(meta: BackupMeta, privateKeyPem: string): Buffer {
  const encryptedDataKey = Buffer.from(meta.encryptedDataKeyB64, 'base64');
  return privateDecrypt(
    {
      key: privateKeyPem,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    encryptedDataKey,
  );
}

export function decryptCiphertext(
  ciphertext: Buffer,
  meta: BackupMeta,
  dataKey: Buffer,
): Buffer {
  const decipher = createDecipheriv(
    'aes-256-gcm',
    dataKey,
    Buffer.from(meta.ivB64, 'base64'),
  );
  decipher.setAuthTag(Buffer.from(meta.authTagB64, 'base64'));
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

export function decompressIfNeeded(plain: Buffer, meta: BackupMeta): Buffer {
  const compressed = meta.compressed !== false;
  return compressed ? gunzipSync(plain) : plain;
}

export function assertCiphertextSha256(
  ciphertext: Buffer,
  expectedHex: string,
): void {
  const actual = createHash('sha256').update(ciphertext).digest('hex');
  const a = Buffer.from(actual, 'utf8');
  const b = Buffer.from(expectedHex.trim().toLowerCase(), 'utf8');
  if (a.length !== b.length || !timingSafeEqual(a, b)) {
    throw new Error('ciphertext SHA-256 mismatch');
  }
}

export function decryptBackupToPlain(
  ciphertext: Buffer,
  meta: BackupMeta,
  privateKeyPem: string,
  options?: { verifySha256?: boolean },
): Buffer {
  if (options?.verifySha256 !== false) {
    assertCiphertextSha256(ciphertext, meta.ciphertextSha256Hex);
  }
  const dataKey = unwrapDataKey(meta, privateKeyPem);
  const plain = decryptCiphertext(ciphertext, meta, dataKey);
  return decompressIfNeeded(plain, meta);
}
