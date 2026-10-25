import { randomBytes, timingSafeEqual, X509Certificate } from 'node:crypto';
import { checkServerIdentity, type PeerCertificate } from 'node:tls';
import { ProxyAgent, fetch as undiciFetch } from 'undici';
import { AttestationError, hashPublicKeys, fromB64u, type AttestationVerifier, type VerifiedAttestation } from '@wraps/attestation';
import { encodeAuthorization, type Token } from '@wraps/tokens';

const DEFAULT_ATTESTATION_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_ATTESTATION_BYTES = 64 * 1024;
const pinnedFetch = undiciFetch as unknown as (input: URL, init: RequestInit) => Promise<Response>;

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

export interface PinnedRelayTransport {
  readonly relay: AttestedRelay;
  /** Opens a fresh CONNECT tunnel and puts these tokens only in its proxy authorization header. */
  fetchWithTokens(input: string, init: RequestInit | undefined, proxyTokens: Token[]): Promise<Response>;
  close(): Promise<void>;
}

export interface RelayTransportOptions {
  /** HTTPS URL of the relay's CONNECT proxy. */
  relayUrl: string;
  verifier: AttestationVerifier;
  /** Optional untrusted URL used only to fetch a fresh, nonce-bound receipt. */
  attestationUrl?: string;
  fetchImpl?: typeof fetch;
  /** Bootstrap request deadline. Defaults to 10 seconds. */
  attestationTimeoutMs?: number;
  /** Maximum bootstrap JSON size. Defaults to 64 KiB. */
  maxAttestationResponseBytes?: number;
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
  if (!opts.attestationUrl) {
    attestationUrl.protocol = 'http:';
    attestationUrl.port = '8080';
  }
  if (attestationUrl.protocol !== 'http:' && attestationUrl.protocol !== 'https:') {
    throw new TypeError('attestationUrl must use HTTP or HTTPS');
  }
  attestationUrl.pathname = '/attestation';
  attestationUrl.search = '';
  attestationUrl.hash = '';

  const timeoutMs = opts.attestationTimeoutMs ?? DEFAULT_ATTESTATION_TIMEOUT_MS;
  const maxResponseBytes = opts.maxAttestationResponseBytes ?? DEFAULT_MAX_ATTESTATION_BYTES;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) throw new TypeError('attestationTimeoutMs must be a positive integer');
  if (!Number.isSafeInteger(maxResponseBytes) || maxResponseBytes < 1) throw new TypeError('maxAttestationResponseBytes must be a positive integer');

  const attested = await fetchAttestedRelay(
    relayUrl,
    attestationUrl,
    opts.verifier,
    opts.fetchImpl ?? fetch,
    timeoutMs,
    maxResponseBytes,
  );
  const agents = new Set<ProxyAgent>();
  let closed = false;

  const request = async (input: string, init: RequestInit | undefined, proxyTokens: Token[]): Promise<Response> => {
    if (closed) throw new TypeError('pinned relay transport is closed');
    const target = new URL(input);
    if (target.protocol !== 'https:') throw new TypeError('relay transport only allows HTTPS destinations');
    if (proxyTokens.length === 0) throw new TypeError('a blind-token batch is required for every relay tunnel');

    const headers = new Headers(init?.headers);
    // Proxy credentials belong to CONNECT only; callers cannot inject them into
    // the tunneled origin request.
    headers.delete('proxy-authorization');
    const agent = new ProxyAgent({
      uri: relayUrl.origin,
      token: encodeAuthorization(proxyTokens),
      proxyTls: {
        ca: attested.tlsCertificate,
        checkServerIdentity: (hostname, peer) => checkPinnedIdentity(hostname, peer, attested.tunnelKey),
      },
    });
    agents.add(agent);
    const cleanup = async () => {
      if (!agents.delete(agent)) return;
      await agent.close();
    };

    let response: Response;
    try {
      // A fresh dispatcher binds this token batch to one CONNECT. Applying it
      // after RequestInit prevents callers from replacing the pinned dispatcher.
      response = await pinnedFetch(target, { ...init, headers, dispatcher: agent } as RequestInit & { dispatcher: ProxyAgent });
    } catch (error) {
      await cleanup().catch(() => {});
      throw error;
    }
    return responseWithCleanup(response, cleanup);
  };

  const transport: PinnedRelayTransport = {
    relay: attested,
    fetchWithTokens: request,
    close: async () => {
      closed = true;
      await Promise.all([...agents].map(async (agent) => {
        agents.delete(agent);
        await agent.close();
      }));
    },
  };
  return transport;
}

async function fetchAttestedRelay(
  relayUrl: URL,
  attestationUrl: URL,
  verifier: AttestationVerifier,
  fetchImpl: typeof fetch,
  timeoutMs: number,
  maxResponseBytes: number,
): Promise<AttestedRelay> {
  const nonce = randomBytes(32);
  const requestUrl = new URL(attestationUrl);
  requestUrl.searchParams.set('nonce', nonce.toString('hex'));

  let res: Response;
  try {
    res = await fetchImpl(requestUrl, { signal: AbortSignal.timeout(timeoutMs) });
  } catch (err) {
    throw new AttestationError('MALFORMED', `relay attestation request failed: ${String(err)}`);
  }
  if (!res.ok) {
    await res.body?.cancel().catch(() => {});
    throw new AttestationError('MALFORMED', `relay returned HTTP ${res.status}`);
  }

  let body: RelayAttestationResponse;
  try {
    const bytes = await readLimitedBody(res, maxResponseBytes);
    body = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as RelayAttestationResponse;
  } catch (error) {
    throw new AttestationError('MALFORMED', error instanceof Error ? error.message : 'relay returned invalid attestation JSON');
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

async function readLimitedBody(response: Response, limit: number): Promise<Uint8Array> {
  const declared = Number(response.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > limit) {
    await response.body?.cancel().catch(() => {});
    throw new Error(`relay attestation response exceeds ${limit} bytes`);
  }
  if (!response.body) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limit) {
        await reader.cancel();
        throw new Error(`relay attestation response exceeds ${limit} bytes`);
      }
      chunks.push(value);
    }
  } catch (error) {
    await reader.cancel().catch(() => {});
    throw error;
  }
  const result = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return result;
}

function responseWithCleanup(response: Response, cleanup: () => Promise<void>): Response {
  if (!response.body) {
    void cleanup();
    return response;
  }
  const reader = response.body.getReader();
  let cleaned = false;
  const finish = async () => {
    if (cleaned) return;
    cleaned = true;
    await cleanup();
  };
  const body = new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        const { done, value } = await reader.read();
        if (done) {
          controller.close();
          await finish();
        } else controller.enqueue(value);
      } catch (error) {
        controller.error(error);
        await finish().catch(() => {});
      }
    },
    async cancel(reason) {
      await reader.cancel(reason).catch(() => {});
      await finish();
    },
  });
  return new Response(body, { status: response.status, statusText: response.statusText, headers: response.headers });
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
