import { entropyToMnemonic, mnemonicToEntropy } from "$lib/mnemonic";
import { describe, expect, test } from "vitest";
import vectors from '../fixtures/mnemonics.json'

describe('mnemonic tests', () => {
  test('can generate 12 words', () => {
    for (const vector of vectors.english) {
      const mnemonic = entropyToMnemonic(vector[0])
      expect(mnemonic).to.be.equal(vector[1])
    }
  })

  test('can recover 12 words', () => {
    for (const vector of vectors.english) {
      const seed = mnemonicToEntropy(vector[1])
      expect(seed).to.be.equal(vector[0])
    }
  })
})