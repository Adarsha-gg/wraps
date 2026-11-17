// Minimal COSE_Sign1 (RFC 9052) encode/decode for Nitro attestation documents.
import { Decoder, Encoder, Tag } from 'cbor-x';
import type { AttestationDoc } from './types';
import { AttestationError } from './types';

const encoder = new Encoder({ useRecords: false, mapsAsObjects: false, tagUint8Array: false });
const decoder = new Decoder({ useRecords: false, mapsAsObjects: false });

export const COSE_ALG_ES384 = -35;
const COSE_SIGN1_TAG = 18;

export function cborEncode(value: unknown): Uint8Array {
  return new Uint8Array(encoder.encode(value));
}

export function cborDecode(bytes: Uint8Array): unknown {
  return decoder.decode(Buffer.from(bytes));
}

const buf = (b: Uint8Array) => Buffer.from(b.buffer, b.byteOffset, b.byteLength);

export interface CoseSign1 {
  protectedHeader: Uint8Array;
  payload: Uint8Array;
  signature: Uint8Array;
  alg: number;
}

export function decodeCoseSign1(bytes: Uint8Array): CoseSign1 {
  let value: unknown;
  try {
    value = cborDecode(bytes);
  } catch (e) {
    throw new AttestationError('bad_cbor', `not CBOR: ${(e as Error).message}`);
  }
  if (value instanceof Tag) {
    if (value.tag !== COSE_SIGN1_TAG) throw new AttestationError('bad_cose', `unexpected tag ${value.tag}`);
    value = value.value;
  }
  if (!Array.isArray(value) || value.length !== 4) throw new AttestationError('bad_cose', 'COSE_Sign1 must be a 4-item array');
  const [protectedHeader, , payload, signature] = value as [Uint8Array, unknown, Uint8Array, Uint8Array];
  if (!isBytes(protectedHeader) || !isBytes(payload) || !isBytes(signature)) {
    throw new AttestationError('bad_cose', 'COSE_Sign1 fields must be byte strings');
  }
  const header = protectedHeader.length ? cborDecode(protectedHeader) : new Map();
  const alg = header instanceof Map ? header.get(1) : undefined;
  return { protectedHeader, payload, signature, alg: Number(alg) };
}

/** Sig_structure = ["Signature1", protected, external_aad, payload]. */
export function sigStructure(protectedHeader: Uint8Array, payload: Uint8Array): Uint8Array {
  return cborEncode(['Signature1', buf(protectedHeader), Buffer.alloc(0), buf(payload)]);
}

export function encodeCoseSign1(protectedHeader: Uint8Array, payload: Uint8Array, signature: Uint8Array): Uint8Array {
  return cborEncode([buf(protectedHeader), new Map(), buf(payload), buf(signature)]);
}

export function es384ProtectedHeader(): Uint8Array {
  return cborEncode(new Map([[1, COSE_ALG_ES384]]));
}

export function encodeAttestationDoc(doc: AttestationDoc): Uint8Array {
  const m = new Map<string, unknown>([
    ['module_id', doc.moduleId],
    ['digest', doc.digest],
    ['timestamp', doc.timestamp],
    ['pcrs', new Map([...doc.pcrs].map(([k, v]) => [k, buf(v)]))],
    ['certificate', buf(doc.certificate)],
    ['cabundle', doc.cabundle.map(buf)],
    ['public_key', doc.publicKey ? buf(doc.publicKey) : null],
    ['user_data', doc.userData ? buf(doc.userData) : null],
    ['nonce', doc.nonce ? buf(doc.nonce) : null],
  ]);
  return cborEncode(m);
}

export function decodeAttestationDoc(payload: Uint8Array): AttestationDoc {
  const m = cborDecode(payload);
  if (!(m instanceof Map)) throw new AttestationError('bad_doc', 'payload is not a CBOR map');
  const pcrsRaw = m.get('pcrs');
  if (!(pcrsRaw instanceof Map)) throw new AttestationError('bad_doc', 'missing pcrs');
  const pcrs = new Map<number, Uint8Array>();
  for (const [k, v] of pcrsRaw) {
    if (!isBytes(v)) throw new AttestationError('bad_doc', `pcr ${k} is not bytes`);
    pcrs.set(Number(k), new Uint8Array(v));
  }
  const certificate = m.get('certificate');
  const cabundle = m.get('cabundle');
  if (!isBytes(certificate)) throw new AttestationError('bad_doc', 'missing certificate');
  if (!Array.isArray(cabundle) || !cabundle.every(isBytes)) throw new AttestationError('bad_doc', 'missing cabundle');
  const opt = (k: string) => {
    const v = m.get(k);
    return isBytes(v) ? new Uint8Array(v) : undefined;
  };
  return {
    moduleId: String(m.get('module_id') ?? ''),
    digest: String(m.get('digest') ?? ''),
    timestamp: Number(m.get('timestamp') ?? 0),
    pcrs,
    certificate: new Uint8Array(certificate),
    cabundle: cabundle.map((c: Uint8Array) => new Uint8Array(c)),
    publicKey: opt('public_key'),
    userData: opt('user_data'),
    nonce: opt('nonce'),
  };
}

function isBytes(v: unknown): v is Uint8Array {
  return v instanceof Uint8Array;
}
