import { entropyToMnemonic, mnemonicToEntropy, mnemonicToSeed } from "$lib/mnemonic";
import { describe, expect, test } from "vitest";
import vectors from '../fixtures/mnemonic.json'

describe('mnemonic tests', () => {
  test('can generate 12 words', () => {
    for (const vector of vectors.english) {
        const mnemonic = entropyToMnemonic(vector[0])
        expect(mnemonic).to.be.equal(vector[1])
    }
  })

  test('can recover 12 words', () => {
    for (const vector of vectors.english) {
        const entropy = mnemonicToEntropy(vector[1])
        expect(entropy).to.be.equal(vector[0])
    }
  })

  test('can convert 12 words to seed hex', () => {
    for (const vector of vectors.english) {
        const seed = mnemonicToSeed(vector[1], "TREZOR")
        expect(seed).to.be.equal(vector[2])
    }
  })
})