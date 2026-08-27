// Pure-TS decoders for the ABI signature envelopes the wasm sign entry
// points return. No wasm dependency, so BOTH package entries re-export
// them: dist/index.js (node) and dist/loader.browser.js (browser — the
// `browser` exports condition swaps the entry, and a value exported only
// from index.js would silently be missing in browser bundles).

/** `SHRINCS.PublicKey`, field-decomposed. */
export interface StatefulEnvelopePublicKey {
  /** 68 bytes: `pkSeed ‖ root ‖ maxSignatures(u32 BE)`. */
  statefulPublicKey: Uint8Array;
  /** The 32-byte installed-key commitment. */
  publicKeyCommitment: Uint8Array;
  pkSeed: Uint8Array;
  hypertreeRoot: Uint8Array;
}

/** `SHRINCS.Signature`, field-decomposed. `authPath.length` is the leaf index. */
export interface StatefulSignatureParts {
  randomizer: Uint8Array;
  counter: number;
  chains: Uint8Array[];
  authPath: Uint8Array[];
}

/** `decodeStatefulEnvelope`'s return shape. */
export interface StatefulEnvelopeParts {
  publicKey: StatefulEnvelopePublicKey;
  signature: StatefulSignatureParts;
}

/** A WOTS-C signature inside a hypertree layer, field-decomposed. */
export interface WotsCSignatureParts {
  randomizer: Uint8Array;
  counter: number;
  chains: Uint8Array[];
}

/** `SPHINCSPlusC.Signature`, field-decomposed. */
export interface StatelessSignatureParts {
  fors: {
    randomizer: Uint8Array;
    counter: number;
    entries: { secretLeaf: Uint8Array; authPath: Uint8Array[] }[];
  };
  hypertree: {
    wotsCPkHash: Uint8Array;
    wotsCSignature: WotsCSignatureParts;
    authPath: Uint8Array[];
  }[];
}

/** The `Error` (with `code: "ERR_ENVELOPE_MALFORMED"`) every decoder throws. */
function envelopeError(detail: string): Error {
  const error = new Error(`signature envelope could not be decoded: ${detail}`);
  (error as Error & { code: string }).code = "ERR_ENVELOPE_MALFORMED";
  return error;
}

/** Read one 32-byte ABI word at `at`, checking bounds. */
function abiWord(data: Uint8Array, at: number): Uint8Array {
  if (at < 0 || at + 32 > data.length) throw envelopeError(`word out of range at ${at}`);
  return data.slice(at, at + 32);
}

/** Read an ABI word at `at` as a JS number, rejecting values beyond 2^32. */
function abiU32(data: Uint8Array, at: number): number {
  const word = abiWord(data, at);
  for (let i = 0; i < 28; i++) {
    if (word[i] !== 0) throw envelopeError(`oversized uint at ${at}`);
  }
  return new DataView(word.buffer, word.byteOffset + 28, 4).getUint32(0, false);
}

/** Resolve the offset word at `headPos` against tuple/array base `base`. */
function abiOffset(data: Uint8Array, base: number, headPos: number): number {
  return base + abiU32(data, headPos);
}

/** Read a dynamic `bytes` field located at `at` (length word + payload). */
function abiBytes(data: Uint8Array, at: number): Uint8Array {
  const length = abiU32(data, at);
  if (at + 32 + length > data.length) throw envelopeError(`bytes out of range at ${at}`);
  return data.slice(at + 32, at + 32 + length);
}

/** Read a static `bytes32[]` located at `at` (length word + inline words). */
function abiBytes32Array(data: Uint8Array, at: number): Uint8Array[] {
  const length = abiU32(data, at);
  const out: Uint8Array[] = [];
  for (let i = 0; i < length; i++) out.push(abiWord(data, at + 32 + i * 32));
  return out;
}

/**
 * Read a dynamic array of dynamic elements located at `at`: length word,
 * then per-element offsets relative to just past the length word.
 */
function abiDynamicArray<T>(
  data: Uint8Array,
  at: number,
  decodeElement: (elementBase: number) => T,
): T[] {
  const length = abiU32(data, at);
  const out: T[] = [];
  for (let i = 0; i < length; i++) {
    out.push(decodeElement(abiOffset(data, at + 32, at + 32 + i * 32)));
  }
  return out;
}

/** Read a dynamic `bytes` field expected to hold exactly 32 bytes. */
function abiBytes32AsBytes(data: Uint8Array, at: number): Uint8Array {
  const bytes = abiBytes(data, at);
  if (bytes.length !== 32) throw envelopeError(`expected 32-byte field, got ${bytes.length}`);
  return bytes;
}

/**
 * Decode a stateful envelope (`shrincs.sign` / `signAtLeaf` /
 * `signStatefulRawAt` output) into its `PublicKey` and `Signature` fields.
 * Throws an `Error` with `code: "ERR_ENVELOPE_MALFORMED"` on any
 * out-of-range offset or truncated field.
 */
export function decodeStatefulEnvelope(envelope: Uint8Array): StatefulEnvelopeParts {
  const publicKeyBase = abiOffset(envelope, 0, 0);
  const signatureBase = abiOffset(envelope, 0, 32);
  return {
    publicKey: {
      statefulPublicKey: abiBytes(envelope, abiOffset(envelope, publicKeyBase, publicKeyBase)),
      publicKeyCommitment: abiBytes32AsBytes(
        envelope,
        abiOffset(envelope, publicKeyBase, publicKeyBase + 32),
      ),
      pkSeed: abiBytes32AsBytes(envelope, abiOffset(envelope, publicKeyBase, publicKeyBase + 64)),
      hypertreeRoot: abiBytes32AsBytes(
        envelope,
        abiOffset(envelope, publicKeyBase, publicKeyBase + 96),
      ),
    },
    signature: {
      randomizer: abiWord(envelope, signatureBase),
      counter: abiU32(envelope, signatureBase + 32),
      chains: abiBytes32Array(envelope, abiOffset(envelope, signatureBase, signatureBase + 64)),
      authPath: abiBytes32Array(envelope, abiOffset(envelope, signatureBase, signatureBase + 96)),
    },
  };
}

/** Decode a WOTS-C signature tuple located at `base`. */
function decodeWotsCSignature(data: Uint8Array, base: number): WotsCSignatureParts {
  return {
    randomizer: abiBytes32AsBytes(data, abiOffset(data, base, base)),
    counter: abiU32(data, base + 32),
    chains: abiDynamicArray(data, abiOffset(data, base, base + 64), (chainBase) =>
      abiBytes32AsBytes(data, chainBase),
    ),
  };
}

/**
 * Decode a stateless signature (`shrincs.signStateless` /
 * `sphincsPlusC.sign` output) into its FORS-C and hypertree-layer fields.
 * Throws an `Error` with `code: "ERR_ENVELOPE_MALFORMED"` on any
 * out-of-range offset or truncated field.
 */
export function decodeStatelessSignature(signature: Uint8Array): StatelessSignatureParts {
  const base = abiOffset(signature, 0, 0);
  const forsBase = abiOffset(signature, base, base);
  return {
    fors: {
      randomizer: abiBytes32AsBytes(signature, abiOffset(signature, forsBase, forsBase)),
      counter: abiU32(signature, forsBase + 32),
      entries: abiDynamicArray(signature, abiOffset(signature, forsBase, forsBase + 64), (entryBase) => ({
        secretLeaf: abiBytes32AsBytes(signature, abiOffset(signature, entryBase, entryBase)),
        authPath: abiDynamicArray(
          signature,
          abiOffset(signature, entryBase, entryBase + 32),
          (nodeBase) => abiBytes32AsBytes(signature, nodeBase),
        ),
      })),
    },
    hypertree: abiDynamicArray(signature, abiOffset(signature, base, base + 32), (layerBase) => ({
      wotsCPkHash: abiBytes32AsBytes(signature, abiOffset(signature, layerBase, layerBase)),
      wotsCSignature: decodeWotsCSignature(signature, abiOffset(signature, layerBase, layerBase + 32)),
      authPath: abiDynamicArray(
        signature,
        abiOffset(signature, layerBase, layerBase + 64),
        (nodeBase) => abiBytes32AsBytes(signature, nodeBase),
      ),
    })),
  };
}

