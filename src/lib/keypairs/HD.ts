import { hexToBytes } from "$lib/mnemonic.js"
import { base58, utf8 } from "$lib/utils/encoding.js"
import { sha256Uint8Array } from "$lib/utils/sha256.js";
import { hmac } from "@stablelib/hmac"
import { SHA512 } from "@stablelib/sha512"
import { Buffer } from 'buffer/index.js';

export const seedToHD = (seed: string) => {
  const masterKey = hmac(SHA512, utf8.encode('Bitcoin seed'), hexToBytes(seed));
  const privKey = masterKey.slice(0, 32);
  const chainCode = masterKey.slice(32, 64);
  const bytes = Buffer.concat([
    hexToBytes('0488ade4'), // version
    hexToBytes('00'), // depth
    hexToBytes('00000000'), // parent fingerprint
    hexToBytes('00000000'), // child index
    chainCode,
    hexToBytes('00'),
    privKey
  ])
  const checksum = sha256Uint8Array(sha256Uint8Array(bytes));
  return base58.encode(Buffer.concat([bytes, checksum], bytes.length + 4))
}