// https://github.com/paulmillr/scure-bip32/blob/7d86c349622fe747f0b87c04ccf45f50e978918a/index.ts#L15

import { bytesToHex, hexToBytes, lpad } from "$lib/mnemonic.js";
import { base58, utf8 } from "$lib/utils/encoding.js";
import { sha256Uint8Array } from "$lib/utils/sha256.js";
import { hmac } from "@stablelib/hmac";
import { SHA512 } from "@stablelib/sha512";
import * as secp from '@noble/secp256k1';
import { Buffer } from 'buffer/index.js';

function bytesToNumber(bytes: Uint8Array): bigint {
  return BigInt(`0x${bytesToHex(bytes)}`);
}

function numberToBytes(num: bigint | number): Uint8Array {
  return hexToBytes(num.toString(16))
}

export const toExtended = (chain: Uint8Array, priv: Uint8Array, depth: Uint8Array, parentFingerprint: Uint8Array, index: Uint8Array) => {
  const bytes = Buffer.concat([
    hexToBytes('0488ade4'), // version
    depth,
    parentFingerprint,
    index,
    chain,
    hexToBytes('00'),
    priv
  ])
  const checksum = sha256Uint8Array(sha256Uint8Array(bytes));
  return base58.encode(Buffer.concat([bytes, checksum], bytes.length + 4))
}

export const seedToHD = (seed: string) => {
  const masterKey = hmac(SHA512, utf8.encode('Bitcoin seed'), hexToBytes(seed));
  const privKey = masterKey.slice(0, 32);
  const chainCode = masterKey.slice(32, 64);
  const depth = hexToBytes('00');
  const fingerprint = hexToBytes('00000000');
  const index = hexToBytes('00000000');
  return toExtended(chainCode, privKey, depth, fingerprint, index)
}

export const deriveKeyAtPathFromMaster = (masterKey: string, path: string) => {
  const levels = path.split('/');
  if (levels.length === 0 || levels[0] !== 'm') {
    throw new Error(`Invalid derivation path: ${path}`)
  }
  const keyBytes = base58.decode(masterKey)
  let chain = new Uint8Array(32);
  let key = new Uint8Array(32);
  let depth = hexToBytes('00');
  let fingerprint = hexToBytes('00000000');
  let index = hexToBytes('00000000');
  let i = 0;
  for(const level of levels) {
    if (level === 'm') {
      chain = keyBytes.slice(13, 45)
      key = keyBytes.slice(46, 78)
    } else {
      const derived = deriveChild(key, chain, +level)
      depth = hexToBytes(lpad(i.toString(16), '0', 2));
      // fingerprint = hexToBytes(lpad(i.toString(16), '0', 8));
      // TODO FINGERPRINT!!!
      index = hexToBytes(lpad((+level).toString(16), '0', 8));
      chain = derived.chainCode;
      key = derived.key
    }
    i++;
  }
  if (!key) {
    throw new Error('key failed to derive')
  }
  return toExtended(chain, key)
}

export const deriveChild = (parentPrivateKey: Uint8Array, parentChainCode: Uint8Array, index: number) => {
  const I = hmac(
    SHA512,
    parentChainCode,
    Buffer.concat([
      hexToBytes('00'),
      parentPrivateKey,
      new Uint8Array([
        0xff & index,
        0xff & (index >> 8),
        0xff & (index >> 16),
        0xff & (index >> 24)
      ])
    ]));
  const childTweak = bytesToNumber(I.slice(0, 32))
  const parentInt = bytesToNumber(parentPrivateKey)
  if (!secp.utils.isValidPrivateKey(childTweak)) {
    throw new Error('Tweak bigger than curve order')
  }
  const key = secp.utils.mod(childTweak + parentInt, secp.CURVE.n);
  if (!secp.utils.isValidPrivateKey(key)) {
    throw new Error('The tweak was out of range or the resulted private key is invalid');
  }
  return { chainCode: I.slice(32), key: numberToBytes(key) }
}