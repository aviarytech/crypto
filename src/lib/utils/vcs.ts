import { Buffer } from 'buffer/index.js';
import jsonld from "jsonld";
import { sha256buffer } from "../utils/sha256.js";

export async function canonize(input: any, { documentLoader }: any) {
  return await jsonld.canonize(input, {
    algorithm: 'URDNA2015',
    format: 'application/n-quads',
    documentLoader,
    useNative: false
  });
}

export async function canonizeProof(proof: any, { documentLoader }: any) {
  // `jws`,`signatureValue`,`proofValue` must not be included in the proof
  const { jws, signatureValue, proofValue, ...rest } = proof;
  return await canonize(rest, {
    documentLoader
  });
}
export async function createVerifyData({ document, proof, documentLoader }: any) {
  // concatenate hash of c14n proof options and hash of c14n document
  if (!proof['@context']) {
    proof['@context'] = document['@context']
  }
  const c14nProofOptions = await canonizeProof(proof, {
    documentLoader
  });
  const c14nDocument = await canonize(document, {
    documentLoader    
  });
  return Buffer.concat([sha256buffer(c14nProofOptions), sha256buffer(c14nDocument)]);
}