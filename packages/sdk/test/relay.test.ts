import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer as createTlsServer, type Server as TlsServer } from 'node:tls';
import { connect as tcpConnect } from 'node:net';
import { once } from 'node:events';
import { X509Certificate } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  AttestationError,
  MockAttestationProvider,
  MockAttestationVerifier,
  b64u,
  hashPublicKeys,
  mockPcrs,
} from '@wraps/attestation';
import { Merchant } from '@wraps/merchant';
import { MockTopUpWallet, PrivatePayClient, type Caps, type PinnedRelayTransport } from '../src/index';
import { createPinnedRelayTransport } from '../src/relay';
import {
  TokenIssuer,
  blindTokens,
  encodeAuthorization,
  finalizeTokens,
  generateIssuerKeys,
  tokenId,
  type Token,
} from '@wraps/tokens';
import { startIssuer, type Transport } from '@wraps/issuer';

const caps: Caps = { perCallTokens: 5, dailyTokens: 20, maxTopUpTokens: 20 };
const quiet = () => {};

interface TlsIdentity {
  cert: string;
  key: string;
  spki: Uint8Array;
}

describe('pinned relay transport', () => {
  let certDir: string;
  let relayIdentity: TlsIdentity;
  let otherIdentity: TlsIdentity;
  let proxy: TlsServer;
  let issuerServer: TlsServer;
  let proxyUrl: string;
  let issuerServerPort: number;
  let issuerRequests = 0;
  const connectHeaders: string[] = [];
  const verifier = () => new MockAttestationVerifier({ expectedPcrs: mockPcrs('relay') });

  beforeAll(async () => {
    certDir = await mkdtemp(join(tmpdir(), 'wraps-sdk-relay-'));
    relayIdentity = await generateTlsIdentity(certDir, 'relay');
    otherIdentity = await generateTlsIdentity(certDir, 'other');
    issuerServer = createTlsServer({ key: relayIdentity.key, cert: relayIdentity.cert }, (socket) => {
      let buffered = Buffer.alloc(0);
      const onData = (chunk: Buffer) => {
        buffered = Buffer.concat([buffered, chunk]);
        if (!buffered.includes('\r\n\r\n')) return;
        socket.off('data', onData);
        issuerRequests++;
        socket.end('HTTP/1.1 200 OK\r\nContent-Length: 15\r\nConnection: close\r\n\r\nissuer response');
      };
      socket.on('data', onData);
    });
    issuerServer.listen(0);
    await once(issuerServer, 'listening');
    const issuerAddress = issuerServer.address();
    if (!issuerAddress || typeof issuerAddress === 'string') throw new Error('issuer test server did not bind');
    issuerServerPort = issuerAddress.port;

    proxy = createTlsServer({ key: relayIdentity.key, cert: relayIdentity.cert }, (socket) => {
      let buffered = Buffer.alloc(0);
      const onData = (chunk: Buffer) => {
        buffered = Buffer.concat([buffered, chunk]);
        const end = buffered.indexOf('\r\n\r\n');
        if (end < 0) return;
        socket.off('data', onData);
        const headers = buffered.subarray(0, end).toString('latin1');
        connectHeaders.push(headers);
        if (headers.startsWith('CONNECT issuer.example:443 ')) {
          socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
          const upstream = tcpConnect(issuerServerPort, '127.0.0.1');
          upstream.once('connect', () => {
            socket.pipe(upstream);
            upstream.pipe(socket);
          });
        } else {
          socket.end('HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');
        }
      };
      socket.on('data', onData);
    });
    proxy.listen(0);
    await once(proxy, 'listening');
    const address = proxy.address();
    if (!address || typeof address === 'string') throw new Error('proxy did not bind');
    proxyUrl = `https://localhost:${address.port}`;
  });

  afterAll(async () => {
    proxy?.close();
    issuerServer?.close();
    if (proxy?.listening) await once(proxy, 'close');
    if (issuerServer?.listening) await once(issuerServer, 'close');
    if (certDir) await rm(certDir, { recursive: true, force: true });
  });

  function fetchAttestation(cert = relayIdentity.cert) {
    const provider = new MockAttestationProvider({ buildName: 'relay' });
    const spki = new Uint8Array(new X509Certificate(cert).publicKey.export({ type: 'spki', format: 'der' }));
    const requested: string[] = [];
    const fetchImpl: typeof fetch = async (input, init) => {
      const url = new URL(String(input));
      requested.push(url.toString());
      const nonce = Buffer.from(url.searchParams.get('nonce') ?? '', 'hex');
      const hash = hashPublicKeys({ tunnel: spki });
      const attestation = await provider.attest(nonce, hash);
      const body = { format: provider.format, publicKeys: { tunnel: b64u(spki) }, tlsCertificate: cert, attestation };
      return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
    };
    return { fetchImpl, requested };
  }

  async function relayTransport(options: { cert?: string; attestationUrl?: string } = {}) {
    const fake = fetchAttestation(options.cert);
    const transport = await createPinnedRelayTransport({
      relayUrl: proxyUrl,
      issuerUrl: 'https://issuer.example',
      verifier: verifier(),
      attestationUrl: options.attestationUrl,
      fetchImpl: fake.fetchImpl,
    });
    return { transport, requested: fake.requested };
  }

  it('defaults to the HTTP attestation listener on port 8080 and accepts a custom port', async () => {
    const defaultResult = await relayTransport();
    expect(new URL(defaultResult.requested[0]).port).toBe('8080');
    expect(new URL(defaultResult.requested[0]).pathname).toBe('/attestation');
    await defaultResult.transport.close();

    const customResult = await relayTransport({ attestationUrl: 'http://127.0.0.1:18080/custom/path?old=yes' });
    expect(new URL(customResult.requested[0]).port).toBe('18080');
    expect(new URL(customResult.requested[0]).pathname).toBe('/attestation');
    expect(new URL(customResult.requested[0]).searchParams.has('old')).toBe(false);
    await customResult.transport.close();
  });

  it('sends the RFC9577 batch only on CONNECT and cannot be overridden by caller headers or dispatcher', async () => {
    connectHeaders.length = 0;
    const { transport } = await relayTransport();
    const tokens = await issueTokens(2);
    let bypassCalled = false;
    const bypass = { dispatch: () => { bypassCalled = true; return true; } };
    const originAuthorization = 'origin-secret';
    const error = await transport.fetchWithTokens('https://merchant.example/data', {
      headers: { authorization: originAuthorization, 'proxy-authorization': 'attacker-controlled' },
      dispatcher: bypass,
    } as RequestInit, tokens).then(() => undefined, (caught) => caught);
    expect(error).toBeInstanceOf(Error);
    await transport.close();

    expect(connectHeaders).toHaveLength(1);
    expect(connectHeaders[0]).toContain(`proxy-authorization: ${encodeAuthorization(tokens)}`);
    expect(connectHeaders[0]).not.toContain('attacker-controlled');
    expect(connectHeaders[0]).not.toContain(originAuthorization);
    expect(bypassCalled).toBe(false);
  });

  it('uses a new CONNECT authorization batch for each tunnel and refuses HTTP destinations', async () => {
    connectHeaders.length = 0;
    const { transport } = await relayTransport();
    const batches = [await issueTokens(1), await issueTokens(1)];
    await expect(transport.fetchWithTokens('https://merchant.example/one', {}, batches[0])).rejects.toThrow();
    await expect(transport.fetchWithTokens('https://merchant.example/two', {}, batches[1])).rejects.toThrow();
    await expect(transport.fetchWithTokens('http://merchant.example/data', {}, batches[1])).rejects.toThrow(/HTTPS/);
    await transport.close();

    expect(connectHeaders).toHaveLength(2);
    expect(connectHeaders[0]).toContain(encodeAuthorization(batches[0]));
    expect(connectHeaders[1]).toContain(encodeAuthorization(batches[1]));
    expect(tokenId(batches[0][0])).not.toBe(tokenId(batches[1][0]));
  });

  it('opens an unauthenticated CONNECT only to the configured issuer and pins its TLS peer', async () => {
    connectHeaders.length = 0;
    const { transport } = await relayTransport();
    const bootstrap = await transport.fetchIssuerWithPeer('https://issuer.example/attestation?nonce=test');
    expect(Buffer.from(bootstrap.peerSpki)).toEqual(Buffer.from(relayIdentity.spki));
    expect(await bootstrap.response.text()).toBe('issuer response');

    const pinned = await transport.fetchIssuer('https://issuer.example/issue', {}, relayIdentity.spki);
    expect(pinned.status).toBe(200);
    expect(await pinned.text()).toBe('issuer response');

    await expect(transport.fetchIssuerWithPeer('https://attacker.example/attestation')).rejects.toThrow(/restricted/);
    const beforeWrongPin = issuerRequests;
    await expect(transport.fetchIssuer('https://issuer.example/issue', {}, otherIdentity.spki)).rejects.toThrow();
    expect(issuerRequests).toBe(beforeWrongPin);
    await transport.close();

    expect(connectHeaders).toHaveLength(3);
    for (const headers of connectHeaders) expect(headers.toLowerCase()).not.toContain('proxy-authorization:');
  });

  it('restricts tokenless issuer CONNECT to credential-free port 443 origins', async () => {
    connectHeaders.length = 0;
    const fake = fetchAttestation();
    await expect(createPinnedRelayTransport({
      relayUrl: proxyUrl,
      issuerUrl: 'https://issuer.example:8443',
      verifier: verifier(),
      fetchImpl: fake.fetchImpl,
    })).rejects.toThrow(/port 443/);

    const { transport } = await relayTransport();
    await expect(transport.fetchIssuerWithPeer('https://user@issuer.example/attestation')).rejects.toThrow(/restricted/);
    await expect(transport.fetchIssuerWithPeer('https://issuer.example/attestation#fragment')).rejects.toThrow(/restricted/);
    await transport.close();
    expect(connectHeaders).toHaveLength(0);
  });

  it('pins the TLS public key and rejects a different proxy key', async () => {
    const { transport } = await relayTransport({ cert: otherIdentity.cert });
    const tokens = await issueTokens(1);
    await expect(transport.fetchWithTokens('https://merchant.example/data', {}, tokens)).rejects.toThrow();
    await transport.close();
  });

  it('bounds bootstrap requests by timeout and response size', async () => {
    const slowFetch: typeof fetch = async (_input, init) => new Promise((_resolve, reject) => {
      const signal = init?.signal;
      if (!signal) return reject(new Error('timeout signal missing'));
      signal.addEventListener('abort', () => reject(signal.reason), { once: true });
    });
    await expect(createPinnedRelayTransport({
      relayUrl: proxyUrl,
      issuerUrl: 'https://issuer.example',
      verifier: verifier(),
      fetchImpl: slowFetch,
      attestationTimeoutMs: 10,
    })).rejects.toMatchObject({ code: 'MALFORMED' });

    await expect(createPinnedRelayTransport({
      relayUrl: proxyUrl,
      issuerUrl: 'https://issuer.example',
      verifier: verifier(),
      fetchImpl: async () => new Response('x'.repeat(100)),
      maxAttestationResponseBytes: 32,
    })).rejects.toThrow(/exceeds 32 bytes/);
  });
});

describe('PrivatePayClient with a pinned relay', () => {
  let issuer: Awaited<ReturnType<typeof startIssuer>>;
  let merchant: Merchant;
  let merchantUrl: string;

  beforeAll(async () => {
    issuer = await startIssuer({ log: quiet, payoutIntervalMs: 3_600_000 });
    merchant = new Merchant({
      merchantId: 'relay-sdk-test',
      issuerUrl: issuer.url,
      verifier: new MockAttestationVerifier({ expectedPcrs: mockPcrs('issuer') }),
      log: quiet,
    });
    merchantUrl = await merchant.start();
  });

  afterAll(async () => {
    await merchant?.close();
    await issuer?.close();
  });

  function fakeRelay(
    issuerUrl: string,
    onFetch: (url: string, init: RequestInit | undefined, tokens: Token[]) => Promise<Response>,
    onIssuer: (url: string, init: RequestInit | undefined) => Promise<Response> = (url, init) => fetch(url, init),
  ) {
    return {
      relay: {} as PinnedRelayTransport['relay'],
      issuerOrigin: new URL(issuerUrl).origin,
      fetchWithTokens: onFetch,
      fetchIssuer: (url: string, init: RequestInit | undefined) => {
        if (new URL(url).origin !== new URL(issuerUrl).origin) throw new TypeError('issuer origin restricted');
        return onIssuer(url, init);
      },
      fetchIssuerWithPeer: async () => { throw new Error('HTTP issuer should not need peer bootstrap'); },
      close: async () => {},
    } satisfies PinnedRelayTransport;
  }

  function client(opts: { relayTransport: PinnedRelayTransport; relayTokensPerTunnel?: number; caps?: Partial<Caps>; transport?: Transport }) {
    return new PrivatePayClient({
      issuerUrl: issuer.url,
      verifier: new MockAttestationVerifier({ expectedPcrs: mockPcrs('issuer') }),
      wallet: new MockTopUpWallet(),
      caps: { ...caps, ...opts.caps },
      transport: opts.transport,
      relayTransport: opts.relayTransport,
      relayTokensPerTunnel: opts.relayTokensPerTunnel,
    });
  }

  it('bootstraps and tops up through the restricted issuer route, then reserves two meter batches', async () => {
    const directUrls: string[] = [];
    const issuerUrls: string[] = [];
    const direct: Transport = async (url, init) => {
      directUrls.push(url);
      return fetch(url, init);
    };
    const calls: Array<{ tokens: Token[]; originAuthorization: string | null }> = [];
    const relay = fakeRelay(issuer.url, async (url, init, tokens) => {
      calls.push({ tokens, originAuthorization: new Headers(init?.headers).get('authorization') });
      return fetch(url, init);
    }, async (url, init) => {
      issuerUrls.push(url);
      return fetch(url, init);
    });
    const sdk = client({ relayTransport: relay, transport: direct });
    await sdk.connect();
    await expect(sdk.fetch(`${merchantUrl}/analytics`)).rejects.toMatchObject({
      needed: 1,
      have: 0,
      message: expect.stringContaining('call topUp() first'),
    });
    expect(calls).toHaveLength(0);

    await sdk.topUp(4);
    expect(directUrls).toHaveLength(0);
    expect(issuerUrls.some((url) => url.includes('/attestation'))).toBe(true);
    expect(issuerUrls.some((url) => url.includes('/issue'))).toBe(true);
    const response = await sdk.fetch(`${merchantUrl}/analytics`);
    expect(response.status).toBe(200);
    expect(calls).toHaveLength(2);
    expect(calls[0].originAuthorization).toBeNull();
    expect(calls[1].originAuthorization).toMatch(/^PrivateToken token=/);
    expect(tokenId(calls[0].tokens[0])).not.toBe(tokenId(calls[1].tokens[0]));
    expect(sdk.balance).toBe(0);
    expect(sdk.spentToday).toBe(4); // Two tunnel tokens plus the merchant's two tokens.
  });

  it('charges the whole configured meter batch and counts it against daily caps', async () => {
    const batches: Token[][] = [];
    const relay = fakeRelay(issuer.url, async (url, _init, tokens) => {
      batches.push(tokens);
      return new Response(JSON.stringify({
        scheme: 'blindtoken',
        price: 2,
        service: 'relay test',
        issuerName: issuer.core.name,
      }), {
        status: 402,
        headers: { 'www-authenticate': `PrivateToken challenge; token-key=${Buffer.from(issuer.core.publicKeys.token).toString('base64url')}` },
      });
    });
    const sdk = client({ relayTransport: relay, relayTokensPerTunnel: 2 });
    await sdk.connect();
    await sdk.topUp(5);
    const quote = await sdk.quote(`${merchantUrl}/analytics`);
    expect(quote?.price).toBe(2);
    expect(batches[0]).toHaveLength(2);
    expect(sdk.balance).toBe(3);
    expect(sdk.spentToday).toBe(2);
  });

  it('includes the retry meter batch in the daily cap before consuming merchant tokens', async () => {
    let requests = 0;
    const relay = fakeRelay(issuer.url, async (url, init) => {
      requests++;
      return fetch(url, init);
    });
    const sdk = client({ relayTransport: relay, caps: { dailyTokens: 3 } });
    await sdk.connect();
    await sdk.topUp(4);
    await expect(sdk.fetch(`${merchantUrl}/analytics`)).rejects.toMatchObject({ code: 'DAILY_CAP' });
    expect(requests).toBe(1);
    expect(sdk.balance).toBe(3);
    expect(sdk.spentToday).toBe(1);
  });

  it('consumes a reserved batch and does not retry after an ambiguous transport failure', async () => {
    let captured: Token[] = [];
    let requests = 0;
    const relay = fakeRelay(issuer.url, async (_url, _init, tokens) => {
      requests++;
      captured = tokens;
      throw new Error('ambiguous CONNECT timeout');
    });
    const sdk = client({ relayTransport: relay });
    await sdk.connect();
    await sdk.topUp(2);
    await expect(sdk.quote(`${merchantUrl}/analytics`)).rejects.toThrow('ambiguous CONNECT timeout');
    expect(requests).toBe(1);
    expect(captured).toHaveLength(1);
    expect(sdk.balance).toBe(1);
    expect(sdk.spentToday).toBe(1);
  });
});

async function issueTokens(count: number): Promise<Token[]> {
  const keys = await generateIssuerKeys();
  const pending = await blindTokens(keys.publicKeyBytes, count);
  const responses = await new TokenIssuer(keys).issue(pending.map((item) => item.request));
  return finalizeTokens(pending, responses);
}

async function generateTlsIdentity(directory: string, name: string): Promise<TlsIdentity> {
  const keyPath = join(directory, `${name}.key`);
  const certPath = join(directory, `${name}.crt`);
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
    '-keyout', keyPath, '-out', certPath, '-days', '1', '-subj', `/CN=${name}`,
    '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost',
  ]);
  const [key, cert] = await Promise.all([readFile(keyPath, 'utf8'), readFile(certPath, 'utf8')]);
  const spki = new Uint8Array(new X509Certificate(cert).publicKey.export({ type: 'spki', format: 'der' }));
  return { key, cert, spki };
}
