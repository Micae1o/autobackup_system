import { generateKeyPairSync } from 'crypto';
import { gzipSync } from 'zlib';
import {
  decryptBackupToPlain,
  type BackupMeta,
  assertCiphertextSha256,
} from './decrypt-backup.util';
import { encryptBackup, generateRsaPem } from '../testing/backup-fixture';

function metaOf(
  enc: ReturnType<typeof encryptBackup>,
  patch: Partial<BackupMeta> = {},
): BackupMeta {
  return {
    id: '11111111-1111-4111-8111-111111111111',
    agentId: 'local-agent',
    dbName: 'postgres',
    createdAt: '2026-01-01T00:00:00.000Z',
    sizeBytes: enc.ciphertext.length,
    encryptionVersion: 'v1-aes256gcm-rsaoaep-sha256',
    compressed: enc.compressed,
    ivB64: enc.ivB64,
    authTagB64: enc.authTagB64,
    encryptedDataKeyB64: enc.encryptedDataKeyB64,
    ciphertextSha256Hex: enc.ciphertextSha256Hex,
    ...patch,
  };
}

describe('decrypt backup', () => {
  const keys = generateRsaPem();

  it('decrypts a gzip payload with the server private key', () => {
    const plain = Buffer.from('postgres custom dump');
    const enc = encryptBackup(plain, keys.publicKey, true);
    const out = decryptBackupToPlain(enc.ciphertext, metaOf(enc), keys.privateKey);
    expect(out.equals(plain)).toBe(true);
  });

  it('decrypts an uncompressed payload', () => {
    const plain = Buffer.from('raw-dump');
    const enc = encryptBackup(plain, keys.publicKey, false);
    const out = decryptBackupToPlain(enc.ciphertext, metaOf(enc), keys.privateKey);
    expect(out.equals(plain)).toBe(true);
  });

  it('treats a missing compressed flag as gzip', () => {
    const plain = Buffer.from('gzip-by-default');
    const enc = encryptBackup(plain, keys.publicKey, true);
    const meta = metaOf(enc);
    delete meta.compressed;
    const out = decryptBackupToPlain(enc.ciphertext, meta, keys.privateKey);
    expect(out.equals(plain)).toBe(true);
  });

  it('rejects a ciphertext whose sha256 does not match', () => {
    const enc = encryptBackup(Buffer.from('x'), keys.publicKey, false);
    const meta = metaOf(enc, {
      ciphertextSha256Hex: 'ab'.repeat(32),
    });
    expect(() => decryptBackupToPlain(enc.ciphertext, meta, keys.privateKey)).toThrow(
      'ciphertext SHA-256 mismatch',
    );
  });

  it('accepts an uppercase sha256 hex', () => {
    const plain = Buffer.from('case');
    const enc = encryptBackup(plain, keys.publicKey, false);
    const meta = metaOf(enc, {
      ciphertextSha256Hex: enc.ciphertextSha256Hex.toUpperCase(),
    });
    const out = decryptBackupToPlain(enc.ciphertext, meta, keys.privateKey);
    expect(out.equals(plain)).toBe(true);
  });

  it('can skip the sha256 check', () => {
    const plain = Buffer.from('skip-sha');
    const enc = encryptBackup(plain, keys.publicKey, false);
    const meta = metaOf(enc, { ciphertextSha256Hex: 'nope' });
    const out = decryptBackupToPlain(enc.ciphertext, meta, keys.privateKey, {
      verifySha256: false,
    });
    expect(out.equals(plain)).toBe(true);
  });

  it('rejects a tampered ciphertext', () => {
    const enc = encryptBackup(Buffer.from('secret'), keys.publicKey, false);
    const tampered = Buffer.from(enc.ciphertext);
    tampered[0] ^= 0xff;
    expect(() =>
      decryptBackupToPlain(tampered, metaOf(enc), keys.privateKey, {
        verifySha256: false,
      }),
    ).toThrow();
  });

  it('rejects the wrong private key', () => {
    const enc = encryptBackup(Buffer.from('secret'), keys.publicKey, false);
    const other = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    expect(() =>
      decryptBackupToPlain(enc.ciphertext, metaOf(enc), other.privateKey),
    ).toThrow();
  });

  it('rejects a gzip flag on data that is not gzip', () => {
    const enc = encryptBackup(Buffer.from('not-gzip'), keys.publicKey, false);
    const meta = metaOf(enc, { compressed: true });
    expect(() => decryptBackupToPlain(enc.ciphertext, meta, keys.privateKey)).toThrow();
  });

  it('compares sha256 in constant length', () => {
    const enc = encryptBackup(gzipSync(Buffer.from('a')), keys.publicKey, false);
    expect(() => assertCiphertextSha256(enc.ciphertext, 'abc')).toThrow(
      'ciphertext SHA-256 mismatch',
    );
  });
});
