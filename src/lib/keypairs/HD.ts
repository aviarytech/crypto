import { hexToBytes } from "$lib/mnemonic.js"
import { base58, utf8 } from "$lib/utils/encoding.js"
import { sha256Uint8Array } from "$lib/utils/sha256.js";
import { hmac } from "@stablelib/hmac"
import { SHA512 } from "@stablelib/sha512"
// import { Buffer } from 'buffer/index.js';

const N = BigInt(115792089237316195423570985008687907852837564279074904382605163141518161494337n)

export const toExtended = (chain: Uint8Array, priv: Uint8Array) => {
  const bytes = Buffer.concat([
    hexToBytes('0488ade4'), // version
    hexToBytes('00'), // depth
    hexToBytes('00000000'), // parent fingerprint
    hexToBytes('00000000'), // child index
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
  return toExtended(chainCode, privKey)
}

export const deriveKeyAtPathFromMaster =  (masterKey: string, path: string) => {
  const levels = path.split('/');
  const keyBytes = base58.decode(masterKey)
  let chain = keyBytes.slice(13, 45);
  let key = keyBytes.slice(46, 78);
  for(const level of levels) {
    console.error(level)
    if (level === 'm') {
      // skip
    } else {
      const derived = deriveChild(key, chain, parseInt(level))
      console.log(derived)
      chain = derived.chainCode;
      key = derived.key
    }
  }
  if (!key) {
    throw new Error('key failed to derive')
  }
  return toExtended(chain, key)
}

export const deriveChild = (parentPrivateKey: Uint8Array, parentChainCode: Uint8Array, index: number) => {
  const masterKey = hmac(
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
  const masterInt: bigint = Buffer.from(masterKey.slice(0, 32)).readBigUInt64BE(0)
  const parentInt: bigint = Buffer.from(parentPrivateKey).readBigUInt64BE(0)
  const res = masterInt + parentInt % N;
  console.log(masterInt, parentInt, res)
  const bytes = Buffer.alloc(8)
  console.log(new Uint8Array(bytes.buffer))
  // bytes.writeUIntBE(res, 0, 8)
  return { chainCode: masterKey.slice(32), key: new Uint8Array(Buffer.concat([masterKey.slice(0, 32), parentPrivateKey]).buffer) }
}