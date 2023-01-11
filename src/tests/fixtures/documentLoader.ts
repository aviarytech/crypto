import jws from "./contexts/jws2020.json";
import credentialExamples from "./contexts/credentials-examples.json";
import credentials from "./contexts/credentials.json";
import ed255192020 from "./contexts/ed255192020.json"
import didDoc from "./didDocuments/ed255192020.json"
import dids from "./contexts/dids.json";
import odrl from "./contexts/odrl.json";
import controller from "./controller.json";
import vax from "./contexts/vaccination.json";
import type { DocumentLoader } from "$lib";

const documents = {
  "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json": jws,
  "https://www.w3.org/2018/credentials/examples/v1": credentialExamples,
  "https://www.w3.org/2018/credentials/v1": credentials,
  "https://www.w3.org/ns/did/v1": dids,
  "https://www.w3.org/ns/odrl.jsonld": odrl,
  "https://w3id.org/vaccination/v1": vax,
  "https://w3id.org/security/suites/ed25519-2020/v1": ed255192020
};

export const documentLoader = async (iri: string): Promise<{ document: any; documentUrl: string; contextUrl: string | null }> => {
  try {
    if (iri.startsWith("did:example:123")) {
      return {
        document: controller,
        documentUrl: "did:example:123",
        contextUrl: null,
      };
    }
    if (iri.startsWith('did:key:z6MknCCLeeHBUaHu4aHSVLDCYQW9gjVJ7a63FpMvtuVMy53T')) {
      return {
        document: didDoc,
        documentUrl: "did:key:z6MknCCLeeHBUaHu4aHSVLDCYQW9gjVJ7a63FpMvtuVMy53T",
        contextUrl: null,
      }
    }
    return {
      document: documents[iri],
      documentUrl: iri,
      contextUrl: null,
    };
  } catch (e) {
    console.error(e, iri);
    return {
      document: null,
      documentUrl: iri,
      contextUrl: null
    };
  }
};
