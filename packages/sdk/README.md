# Agent SDK

## Pinned relay transport

`createPinnedRelayTransport()` fetches a fresh relay attestation, verifies the receipt with the configured `AttestationVerifier`, checks that the relay certificate's public key matches the attested `tunnel` key, and then makes HTTPS requests through an Undici `ProxyAgent`. Each TLS connection to the relay is checked against that same key. The agent's HTTPS destination TLS remains end to end through the CONNECT tunnel.

The relay attestation endpoint returns JSON in this shape:

```json
{
  "format": "<attestation format>",
  "publicKeys": { "tunnel": "<base64url DER SubjectPublicKeyInfo>" },
  "tlsCertificate": "<PEM certificate>",
  "attestation": "<base64url attestation document>"
}
```

The attestation's `user_data` must bind `hashPublicKeys({ tunnel })` and the request nonce. By default, the receipt is fetched from `http://<relay-host>:8080/attestation`; that response is treated as untrusted until the verifier accepts the nonce-bound receipt. Bootstrap has a 10-second deadline and a 64 KiB response limit. Only HTTPS destination requests are accepted by the returned transport.

```ts
const relayTransport = await createPinnedRelayTransport({
  relayUrl: 'https://relay.example:8443',
  issuerUrl,
  verifier,
});

const sdk = new PrivatePayClient({ issuerUrl, verifier, wallet, caps, relayTransport });
try {
  await sdk.connect();
  await sdk.topUp(10); // issuer calls also travel through the relay
  await sdk.fetch('https://merchant.example/data');
  // issuer calls, quote(), and merchant fetches use the relay.
} finally {
  await relayTransport.close();
}
```

Relay mode requires a pre-top-up before the first merchant request because the relay needs a blind-token batch in `Proxy-Authorization` before it opens CONNECT and the merchant can issue its 402 challenge. The default is one dedicated relay token per tunnel, covering up to 10 MB. A paid fetch uses one relay batch for the initial challenge request, one for the retry, and the merchant's quoted price in separate origin `Authorization` credentials. `quote()` uses one relay batch. All reserved relay batches count against the daily cap and are removed before dispatch, even if the relay later reports an ambiguous failure. Set `relayTokensPerTunnel` between 1 and 100 to reserve a larger batch; the full batch is conservatively charged even when fewer metering blocks are settled.

The issuer bootstrap and top-up requests are tunneled through the relay without meter tokens. This exception is restricted to the exact HTTPS issuer origin configured in `createPinnedRelayTransport`; the issuer's first TLS peer key is checked against its attestation, then pinned for later calls. The relay server must permit unauthenticated CONNECT only to that issuer host and port. Merchant CONNECT requests still require meter tokens in `Proxy-Authorization`; the merchant's `Authorization` header remains end-to-end inside TLS. Without `relayTransport`, `transport` and all direct behavior stay unchanged.
