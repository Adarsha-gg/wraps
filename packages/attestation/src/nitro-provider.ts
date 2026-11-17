import type { AttestRequest, AttestationProvider } from './types';

/**
 * Real provider: asks the Nitro Secure Module (/dev/nsm) for a document.
 * It only works inside an enclave. See docs/INTEGRATION.md section 2.
 *
 * TODO(nitro): call NSM's Attestation request with { user_data, nonce, public_key }.
 * Options: the `aws-nitro-enclaves-nsm-api` Rust crate behind a small N-API module,
 * or a tiny helper binary in the enclave image that reads stdin and prints the CBOR document.
 */
export class NitroNsmProvider implements AttestationProvider {
  readonly kind = 'nitro' as const;
  async attest(_req: AttestRequest): Promise<Uint8Array> {
    throw new Error('NitroNsmProvider runs only inside a Nitro Enclave. Wire /dev/nsm here (docs/INTEGRATION.md section 2).');
  }
}
