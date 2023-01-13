import { deriveKeyAtPathFromMaster, seedToHD } from "$lib/keypairs/HD";
import { describe, expect, test } from "vitest";
import vectors from '../fixtures/HD.json'

describe('HD tests', () => {

  // test('can convert hex seed to xpriv', () => {
  //   for (const vector of vectors) {
  //       const key = seedToHD(vector[0])
  //       expect(key).to.be.equal(vector[2])
  //   }
  // })

  test('can convert hex seed to xpriv', () => {
    for (const vector of vectors) {
        const key = seedToHD(vector[0])
        const derived = deriveKeyAtPathFromMaster(key, vector[1])
        expect(derived).to.be.equal(vector[2])
    }
  })
})


// [
//   "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
//   "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"
// ],
// [
//   "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
//   "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6"
// ],
// [
//   "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678",
//   "xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv"
// ]