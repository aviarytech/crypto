import { deriveKeyAtPathFromMaster, seedToHD } from "$lib/keypairs/HD";
import { describe, expect, test } from "vitest";
import hdFixtures from '../fixtures/HD.json'
import { mnemonicToSeed } from "$lib/mnemonic";
import { MULTICODEC_SECP256K1_PUB_HEADER, multibase } from "$lib";

describe('HD tests', () => {
  let i = 0;
  for (const vector of hdFixtures.secp256k1) {
    test(`${i}: can convert hex seed (${vector[0].slice(0, 12)}...) to xpriv (${vector[2].slice(0, 12)}...) with path ${vector[1]}`, () => {
        const key = seedToHD(vector[0])
        const derived = deriveKeyAtPathFromMaster(key, vector[1])
        expect(derived.privateExtendedKey).to.be.equal(vector[2])
    })
    i++
  }

	test('can recover from impervious backup', () => {
		const seedPhrase = 'flower crew machine multiply talk collect chest theory diary exit deputy ecology move twelve romance fire dial enhance decrease february bachelor dose reflect major';
		const seed = mnemonicToSeed(seedPhrase)
		const key = seedToHD(seed)
    const derived = deriveKeyAtPathFromMaster(key, "m/0")

		expect(multibase.encode(MULTICODEC_SECP256K1_PUB_HEADER, derived.publicKey!)).toEqual('zQmNhr3DC5sMwfLJrJ3bnJFgrJPxaMtXZA6213qAARp9eAs')
	})
})
