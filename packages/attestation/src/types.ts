/** Parsed AWS Nitro attestation document (the COSE_Sign1 payload). */
export interface AttestationDoc {
  moduleId: string;
  digest: string;
  timestamp: number;
  pcrs: Map<number, Uint8Array>;
  certificate: Uint8Array;
  cabundle: Uint8Array[];
  publicKey?: Uint8Array;
  userData?: Uint8Array;
  nonce?: Uint8Array;
}

export interface AttestRequest {
  /** Fresh client nonce. Stops replay of old documents. */
  nonce: Uint8Array;
  /** We put SHA-256 of the enclave's public keys here. */
  userData: Uint8Array;
  publicKey?: Uint8Array;
}

/** Produces a COSE_Sign1 attestation document. Real: the Nitro Secure Module (/dev/nsm). */
export interface AttestationProvider {
  readonly kind: 'mock' | 'nitro';
  attest(req: AttestRequest): Promise<Uint8Array>;
}

export interface Expectations {
  /** Hex SHA-384 of the published enclave image (PCR0). */
  pcr0: string;
  nonce: Uint8Array;
  /** SHA-256 of the public keys the enclave presented. */
  userData: Uint8Array;
  maxAgeMs?: number;
}

export interface VerifiedAttestation {
  doc: AttestationDoc;
  pcr0: string;
}

export interface AttestationVerifier {
  verify(document: Uint8Array, expect: Expectations): Promise<VerifiedAttestation>;
}

export class AttestationError extends Error {
  constructor(readonly code: string, message: string) {
    super(`${code}: ${message}`);
    this.name = 'AttestationError';
  }
}
