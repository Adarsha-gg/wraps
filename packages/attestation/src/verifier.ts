// Verifies a Nitro-format attestation document. The same code checks real AWS documents
// (trust root = AWS Nitro Root-G1) and mock documents (trust root = a local mock root).
import { X509Certificate, createHash, verify as cryptoVerify } from 'node:crypto';
import { AWS_NITRO_ROOT_PEM, AWS_NITRO_ROOT_SHA256 } from './aws-root';
import { COSE_ALG_ES384, decodeAttestationDoc, decodeCoseSign1, sigStructure } from './cose';
import type { AttestationVerifier, Expectations, VerifiedAttestation } from './types';
import { AttestationError } from './types';

export interface VerifierOptions {
  rootCertPem: string;
  /** Optional hand-checked SHA-256 fingerprint of the root, hex, no colons. */
  rootSha256?: string;
  now?: () => number;
  defaultMaxAgeMs?: number;
}

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');

export class NitroAttestationVerifier implements AttestationVerifier {
  private readonly root: X509Certificate;
  private readonly seenNonces = new Set<string>();
  private readonly now: () => number;

  constructor(private readonly opts: VerifierOptions) {
    this.root = new X509Certificate(opts.rootCertPem);
    this.now = opts.now ?? Date.now;
    if (opts.rootSha256) {
      const fp = createHash('sha256').update(this.root.raw).digest('hex');
      if (fp !== opts.rootSha256.toLowerCase()) throw new AttestationError('bad_root', 'root fingerprint mismatch');
    }
  }

  async verify(document: Uint8Array, expect: Expectations): Promise<VerifiedAttestation> {
    const cose = decodeCoseSign1(document);
    if (cose.alg !== COSE_ALG_ES384) throw new AttestationError('bad_alg', `expected ES384, got ${cose.alg}`);
    const doc = decodeAttestationDoc(cose.payload);
    if (doc.digest !== 'SHA384') throw new AttestationError('bad_doc', `unexpected digest ${doc.digest}`);

    // 1. Certificate chain: cabundle[0] must be our trusted root, then each cert signs the next.
    const leaf = this.checkChain(doc.cabundle, doc.certificate);

    // 2. COSE signature by the leaf key over the document.
    const ok = cryptoVerify(
      'sha384',
      sigStructure(cose.protectedHeader, cose.payload),
      { key: leaf.publicKey, dsaEncoding: 'ieee-p1363' },
      cose.signature,
    );
    if (!ok) throw new AttestationError('bad_signature', 'COSE signature does not verify');

    // 3. PCRs: refuse debug mode (all zeros), then compare PCR0 with the published build.
    for (const i of [0, 1, 2]) {
      const pcr = doc.pcrs.get(i);
      if (!pcr) throw new AttestationError('missing_pcr', `PCR${i} missing`);
      if (pcr.every((b) => b === 0)) throw new AttestationError('debug_mode', `PCR${i} is all zeros (debug enclave)`);
    }
    const pcr0 = hex(doc.pcrs.get(0)!);
    if (pcr0 !== expect.pcr0.toLowerCase()) {
      throw new AttestationError('pcr0_mismatch', `code hash ${pcr0.slice(0, 16)}... is not the published build ${expect.pcr0.slice(0, 16)}...`);
    }

    // 4. Freshness: our nonce, never seen before, recent timestamp.
    if (!doc.nonce || hex(doc.nonce) !== hex(expect.nonce)) throw new AttestationError('nonce_mismatch', 'document nonce is not ours');
    const nonceHex = hex(doc.nonce);
    if (this.seenNonces.has(nonceHex)) throw new AttestationError('replay', 'nonce already used');
    const maxAge = expect.maxAgeMs ?? this.opts.defaultMaxAgeMs ?? 5 * 60_000;
    if (Math.abs(this.now() - doc.timestamp) > maxAge) throw new AttestationError('stale', 'document timestamp too old');

    // 5. Keys: the public keys the enclave presented must be the ones it attested.
    if (!doc.userData || hex(doc.userData) !== hex(expect.userData)) {
      throw new AttestationError('key_mismatch', 'presented keys do not match the attested key hash');
    }

    this.seenNonces.add(nonceHex);
    return { doc, pcr0 };
  }

  private checkChain(cabundle: Uint8Array[], certificate: Uint8Array): X509Certificate {
    if (cabundle.length === 0) throw new AttestationError('bad_chain', 'empty cabundle');
    const first = new X509Certificate(Buffer.from(cabundle[0]));
    if (!first.raw.equals(this.root.raw)) throw new AttestationError('untrusted_root', 'chain does not start at the trusted root');
    const now = new Date(this.now());
    let parent = first;
    checkValidity(parent, now);
    for (const der of [...cabundle.slice(1), certificate]) {
      const cert = new X509Certificate(Buffer.from(der));
      if (!parent.ca) throw new AttestationError('bad_chain', `${parent.subject} is not a CA`);
      if (!cert.checkIssued(parent) || !cert.verify(parent.publicKey)) {
        throw new AttestationError('bad_chain', `${cert.subject} is not signed by ${parent.subject}`);
      }
      checkValidity(cert, now);
      parent = cert;
    }
    return parent;
  }
}

function checkValidity(cert: X509Certificate, now: Date) {
  if (now < new Date(cert.validFrom) || now > new Date(cert.validTo)) {
    throw new AttestationError('cert_expired', `${cert.subject} is outside its validity period`);
  }
}

/** Verifier for real AWS Nitro documents. */
export function nitroVerifier(opts: Partial<VerifierOptions> = {}): NitroAttestationVerifier {
  return new NitroAttestationVerifier({ rootCertPem: AWS_NITRO_ROOT_PEM, rootSha256: AWS_NITRO_ROOT_SHA256, ...opts });
}
