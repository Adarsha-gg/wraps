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

The attestation's `user_data` must bind `hashPublicKeys({ tunnel })` and the request nonce. By default, the receipt is fetched from `http://<relay-host>/attestation`; that response is treated as untrusted until the verifier accepts the nonce-bound receipt. Only HTTPS destination requests are accepted by the returned transport.

```ts
const transport = await createPinnedRelayTransport({
  relayUrl: 'https://relay.example:8443',
  verifier,
});

const sdk = new PrivatePayClient({ issuerUrl, verifier, wallet, caps, transport });
try {
  await sdk.connect();
  // use sdk.fetch(), sdk.quote(), and sdk.topUp() through the relay
} finally {
  await transport.close();
}
```

The relay service must expose the TLS endpoint and attestation response described above. The current CONNECT server and enclave wiring are tracked separately in RLY-01 through RLY-03.
