// Mock Nitro Secure Module. It produces documents in the real Nitro format
// (COSE_Sign1, ES384, cert chain, PCRs) but the chain ends at a local mock root key.
// The verifier runs the same checks on it as on a real AWS document.
import * as x509 from '@peculiar/x509';
import { webcrypto } from 'node:crypto';
import { encodeAttestationDoc, encodeCoseSign1, es384ProtectedHeader, sigStructure } from './cose';
import type { AttestRequest, AttestationProvider } from './types';

x509.cryptoProvider.set(webcrypto as unknown as Crypto);

const ALG = { name: 'ECDSA', namedCurve: 'P-384' } as const;
const SIGN = { name: 'ECDSA', hash: 'SHA-384' } as const;

export interface MockRoot {
  certPem: string;
  certDer: Uint8Array;
  keys: CryptoKeyPair;
}

/** A local stand-in for the AWS Nitro root CA. Generate once per demo run. */
export async function createMockRoot(): Promise<MockRoot> {
  const keys = (await webcrypto.subtle.generateKey(ALG, true, ['sign', 'verify'])) as CryptoKeyPair;
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: randomSerial(),
    name: 'CN=mock.nitro-enclaves, O=Wraps Mock, C=US',
    notBefore: new Date(Date.now() - 60_000),
    notAfter: new Date(Date.now() + 30 * 24 * 3600_000),
    signingAlgorithm: SIGN,
    keys,
    extensions: [
      new x509.BasicConstraintsExtension(true, 2, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
    ],
  });
  return { certPem: cert.toString('pem'), certDer: new Uint8Array(cert.rawData), keys };
}

export interface MockProviderOptions {
  root: MockRoot;
  /** Hex SHA-384 code measurement. In a real enclave the hardware sets this. */
  pcr0: string;
  moduleId?: string;
  /** Simulate a debug-mode enclave: all PCRs are zero. */
  debug?: boolean;
}

export class MockNitroProvider implements AttestationProvider {
  readonly kind = 'mock' as const;
  private leaf?: { cert: Uint8Array; key: CryptoKey };

  constructor(private readonly opts: MockProviderOptions) {}

  async attest(req: AttestRequest): Promise<Uint8Array> {
    const leaf = await this.leafCert();
    const zero = new Uint8Array(48);
    const pcr0 = this.opts.debug ? zero : Buffer.from(this.opts.pcr0, 'hex');
    // PCR1 (kernel) and PCR2 (application) are fixed fake values in the mock.
    const pcr1 = this.opts.debug ? zero : new Uint8Array(48).fill(0x11);
    const pcr2 = this.opts.debug ? zero : new Uint8Array(48).fill(0x22);
    const payload = encodeAttestationDoc({
      moduleId: this.opts.moduleId ?? 'i-mock-enc0123456789',
      digest: 'SHA384',
      timestamp: Date.now(),
      pcrs: new Map([
        [0, pcr0],
        [1, pcr1],
        [2, pcr2],
        [3, zero],
        [4, zero],
      ]),
      certificate: leaf.cert,
      cabundle: [this.opts.root.certDer],
      publicKey: req.publicKey,
      userData: req.userData,
      nonce: req.nonce,
    });
    const protectedHeader = es384ProtectedHeader();
    const sig = await webcrypto.subtle.sign(SIGN, leaf.key, sigStructure(protectedHeader, payload));
    return encodeCoseSign1(protectedHeader, payload, new Uint8Array(sig));
  }

  private async leafCert() {
    if (this.leaf) return this.leaf;
    const keys = (await webcrypto.subtle.generateKey(ALG, true, ['sign', 'verify'])) as CryptoKeyPair;
    const cert = await x509.X509CertificateGenerator.create({
      serialNumber: randomSerial(),
      subject: `CN=${this.opts.moduleId ?? 'i-mock-enc0123456789'}.mock.nitro-enclaves`,
      issuer: new x509.X509Certificate(this.opts.root.certDer).subject,
      notBefore: new Date(Date.now() - 60_000),
      notAfter: new Date(Date.now() + 24 * 3600_000),
      signingAlgorithm: SIGN,
      publicKey: keys.publicKey,
      signingKey: this.opts.root.keys.privateKey,
      extensions: [new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true)],
    });
    this.leaf = { cert: new Uint8Array(cert.rawData), key: keys.privateKey };
    return this.leaf;
  }
}

function randomSerial(): string {
  const b = webcrypto.getRandomValues(new Uint8Array(12));
  b[0] &= 0x7f;
  return Buffer.from(b).toString('hex');
}
