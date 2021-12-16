/**
 * z represents the multibase encoding scheme of base58 encoding
 * @see https://github.com/multiformats/multibase/blob/master/multibase.csv#L18
 * @ignore
 */
export const MULTIBASE_ENCODED_BASE58_IDENTIFIER = "z";

/**
 * 0x01 indicates the end of the leading bytes according to variable integer spec
 * @see https://github.com/multiformats/multicodec
 * @ignore
 */
export const VARIABLE_INTEGER_TRAILING_BYTE = 0x01;

/**
 * 0xed indicates a Ed25519 public key
 *
 */
export const ED25519_MULTICODEC_IDENTIFIER = 0xed;

/**
 * 0xe7 indicates a Secp256k1 public key
 *
 */
export const SECP256K1_MULTICODEC_IDENTIFIER = 0xe7;

export type JWA_ALG =
  | "ES256K"
  | "ES256K-R"
  | "SS256K"
  | "EdDSA"
  | "ES256"
  | "ES384"
  | "ES512";
