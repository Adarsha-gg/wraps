import { randomBytes, timingSafeEqual, X509Certificate } from 'node:crypto';
import { checkServerIdentity, type PeerCertificate } from 'node:tls';
import { ProxyAgent, fetch as undiciFetch } from 'undici';
import { AttestationError, hashPublicKeys, fromB64u, type AttestationVerifier, type VerifiedAttestation } from '@wraps/attestation';
import type { Transport } from '@wraps/issuer';

export interface RelayAttestationResponse {
  format: string;
  publicKeys: { tunnel: string };
  /** Self-signed relay TLS certificate whose SPKI is the attested tunnel key. */
  tlsCertificate: string;
  attestation: string;
}

export interface AttestedRelay {
  url: string;
  tunnelKey: Uint8Array;
  tlsCertificate: string;
  attestation: VerifiedAttestation;
}

export interface PinnedRelayTransport extends Transport {
  readonly relay: AttestedRelay;
  close(): Promise<void>;
}

export interface RelayTransportOptions {
  /** HTTPS URL of the relay's CONNECT proxy. */
  relayUrl: string;
  verifier: AttestationVerifier;
  /** Optional untrusted URL used only to fetch a fresh, nonce-bound receipt. */
  attestationUrl?: string;
  fetchImpl?: typeof fetch;
}

/** Fetch and verify a fresh relay receipt before creating any tunneled requests. */
export async function createPinnedRelayTransport(opts: RelayTransportOptions): Promise<PinnedRelayTransport> {
  const relayUrl = new URL(opts.relayUrl);
  if (relayUrl.protocol !== 'https:' || relayUrl.username || relayUrl.password || relayUrl.hash) {
    throw new TypeError('relayUrl must be an HTTPS URL without credentials or a fragment');
  }
  relayUrl.pathname = '/';
  relayUrl.search = '';

  const attestationUrl = opts.attestationUrl ? new URL(opts.attestationUrl) : new URL(relayUrl);
  if (!opts.attestationUrl) attestationUrl.protocol = 'http:';
  if (attestationUrl.protocol !== 'http:' && attestationUrl.protocol !== 'https:') {
    throw new TypeError('attestationUrl must use HTTP or HTTPS');
  }
  attestationUrl.pathname = '/attestation';
  attestationUrl.search = '';
  attestationUrl.hash = '';

  const attested = await fetchAttestedRelay(
    relayUrl,
    attestationUrl,
    opts.verifier,
    opts.fetchImpl ?? fetch,
  );
  const agent = new ProxyAgent({
    uri: relayUrl.origin,
    proxyTls: {
      // Trust the self-signed certificate only after verifying its key against
      // the nonce-bound Nitro receipt. The callback also pins every connection.
      ca: attested.tlsCertificate,
      checkServerIdentity: (hostname, peer) => checkPinnedIdentity(hostname, peer, attested.tunnelKey),
    },
  });

  const transport: PinnedRelayTransport = Object.assign(
    (input: string, init?: RequestInit) => {
      const target = new URL(input);
      if (target.protocol !== 'https:') throw new TypeError('relay transport only allows HTTPS destinations');
      // Keep the attested dispatcher last so callers cannot replace it with a
      // direct dispatcher and silently bypass the relay.
      return undiciFetch(target, { ...init, dispatcher: agent });
    },
    {
      relay: attested,
      close: () => agent.close(),
    },
  );
  return transport;
}

async function fetchAttestedRelay(
  relayUrl: URL,
  attestationUrl: URL,
  verifier: AttestationVerifier,
  fetchImpl: typeof fetch,
): Promise<AttestedRelay> {
  const nonce = randomBytes(32);
  const requestUrl = new URL(attestationUrl);
  requestUrl.searchParams.set('nonce', nonce.toString('hex'));

  let res: Response;
  try {
    res = await fetchImpl(requestUrl);
  } catch (err) {
    throw new AttestationError('MALFORMED', `relay attestation request failed: ${String(err)}`);
  }
  if (!res.ok) throw new AttestationError('MALFORMED', `relay returned HTTP ${res.status}`);

  let body: RelayAttestationResponse;
  try {
    body = (await res.json()) as RelayAttestationResponse;
  } catch {
    throw new AttestationError('MALFORMED', 'relay returned invalid attestation JSON');
  }
  if (!body?.format || body.format !== verifier.format || !body.attestation || !body.tlsCertificate || !body.publicKeys?.tunnel) {
    throw new AttestationError('MALFORMED', 'relay attestation response is missing required fields or has the wrong format');
  }

  const tunnelKey = fromB64u(body.publicKeys.tunnel);
  let certificate: X509Certificate;
  try {
    certificate = new X509Certificate(body.tlsCertificate);
  } catch {
    throw new AttestationError('MALFORMED', 'relay TLS certificate is invalid');
  }
  if (!sameBytes(certificate.publicKey.export({ type: 'spki', format: 'der' }) as Uint8Array, tunnelKey)) {
    throw new AttestationError('KEY_MISMATCH', 'relay TLS certificate key does not match its attested tunnel key');
  }

  const attestation = await verifier.verify(body.attestation, {
    nonce,
    publicKeysHash: hashPublicKeys({ tunnel: tunnelKey }),
  });
  return {
    url: relayUrl.origin,
    tunnelKey,
    tlsCertificate: body.tlsCertificate,
    attestation,
  };
}

function checkPinnedIdentity(hostname: string, peer: PeerCertificate, expectedKey: Uint8Array): Error | undefined {
  const hostnameError = checkServerIdentity(hostname, peer);
  if (hostnameError) return hostnameError;
  if (!peer.raw) return new Error('relay did not provide a TLS certificate');
  try {
    const cert = new X509Certificate(peer.raw);
    const actualKey = cert.publicKey.export({ type: 'spki', format: 'der' }) as Uint8Array;
    if (!sameBytes(actualKey, expectedKey)) return new Error('relay TLS key does not match the verified attestation');
  } catch {
    return new Error('relay TLS certificate could not be parsed');
  }
  return undefined;
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.byteLength === b.byteLength && timingSafeEqual(a, b);
}
