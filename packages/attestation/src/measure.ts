import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

/**
 * Mock code measurement: SHA-384 over every file in a source folder, in sorted order.
 * In a real enclave PCR0 is the hash of the enclave image file (EIF), which
 * `nitro-cli build-enclave` prints. A changed source file gives a different hash.
 */
export function measureSource(dir: string, extra = ''): string {
  const h = createHash('sha384');
  for (const file of listFiles(dir)) {
    h.update(relative(dir, file));
    h.update(readFileSync(file));
  }
  h.update(extra);
  return h.digest('hex');
}

function listFiles(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir).sort()) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...listFiles(p));
    else out.push(p);
  }
  return out;
}

/** SHA-256 over canonical JSON of the enclave's public keys. This goes in user_data. */
export function keysHash(keys: Record<string, string>): Uint8Array {
  const canonical = JSON.stringify(Object.keys(keys).sort().map((k) => [k, keys[k]]));
  return new Uint8Array(createHash('sha256').update(canonical).digest());
}

export function randomNonce(): Uint8Array {
  return new Uint8Array(createHash('sha256').update(crypto.getRandomValues(new Uint8Array(32))).digest());
}
