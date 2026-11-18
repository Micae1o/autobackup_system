import { join } from 'path';
import { tmpdir } from 'os';
import {
  assertPathWithinStorage,
  validateAgentId,
  validateBackupId,
} from './agent-id.util';

describe('agent id', () => {
  it('accepts a normal agent id', () => {
    expect(validateAgentId(' local-agent ')).toBe('local-agent');
  });

  it.each(['', ' ', 'bad id', 'a/b', 'a'.repeat(65)])(
    'rejects %j',
    (value) => {
      expect(() => validateAgentId(value)).toThrow('Invalid X-Agent-Id');
    },
  );

  it('accepts a uuid backup id in any letter case', () => {
    const id = '11111111-1111-4111-8111-111111111111';
    expect(validateBackupId(id.toUpperCase())).toBe(id.toUpperCase());
  });

  it.each(['1', '../etc', '11111111-1111-4111-8111-11111111111'])(
    'rejects backup id %j',
    (value) => {
      expect(() => validateBackupId(value)).toThrow('Invalid backupId');
    },
  );
});

describe('storage path', () => {
  const base = join(tmpdir(), 'autobackup-storage-root');

  it('allows a path inside storage', () => {
    expect(() => assertPathWithinStorage(base, join(base, 'agent', 'id'))).not.toThrow();
  });

  it('allows the storage directory itself', () => {
    expect(() => assertPathWithinStorage(base, base)).not.toThrow();
  });

  it('rejects a parent path', () => {
    expect(() => assertPathWithinStorage(base, join(base, '..', 'etc'))).toThrow(
      'Invalid storage path',
    );
  });

  it('rejects a directory whose name only starts with the storage name', () => {
    expect(() => assertPathWithinStorage(base, `${base}-evil`)).toThrow(
      'Invalid storage path',
    );
  });
});
