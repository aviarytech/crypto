import { seedToHD } from "$lib/keypairs/HD";
import { entropyToMnemonic, mnemonicToEntropy, mnemonicToSeed } from "$lib/mnemonic";
import { describe, expect, test } from "vitest";
import vectors from '../fixtures/mnemonics.json'

describe('mnemonic tests', () => {
  test('can generate 12 words', () => {
    for (const vector of vectors.english) {
      if (vector[0] && vector[1]) {
        const mnemonic = entropyToMnemonic(vector[0])
        expect(mnemonic).to.be.equal(vector[1])
      }
    }
  })

  test('can recover 12 words', () => {
    for (const vector of vectors.english) {
      if (vector[0] && vector[1]) {
        const entropy = mnemonicToEntropy(vector[1])
        expect(entropy).to.be.equal(vector[0])
      }
    }
  })

  test('can convert 12 words to seed hex', () => {
    for (const vector of vectors.english) {
      if (vector[2] && vector[1]) {
        const seed = mnemonicToSeed(vector[1], "TREZOR")
        expect(seed).to.be.equal(vector[2])
      }
    }
  })

  test('can convert hex seed to xpriv', () => {
    for (const vector of vectors.english) {
      if (vector[2] && vector[3]) {
        const key = seedToHD(vector[2])
        expect(key).to.be.equal(vector[3])
      }
    }
  })
})