import jws from "./contexts/jws2020.json";
import credentialExamples from "./contexts/credentials-examples.json";
import credentials from "./contexts/credentials.json";
import dids from "./contexts/dids.json";
import odrl from "./contexts/odrl.json";
import controller from "./controller.json";
import vax from "./contexts/vaccination.json";

const documents = {
  "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json": jws,
  "https://www.w3.org/2018/credentials/examples/v1": credentialExamples,
  "https://www.w3.org/2018/credentials/v1": credentials,
  "https://www.w3.org/ns/did/v1": dids,
  "https://www.w3.org/ns/odrl.jsonld": odrl,
  "https://w3id.org/vaccination/v1": vax,
};

export const documentLoader = async (iri: string) => {
  try {
    if (iri.startsWith("did:example:123")) {
      return {
        document: controller,
        documentUrl: "did:example:123",
        contextUrl: null,
      };
    }
    return {
      document: documents[iri],
      documentUrl: iri,
      contextUrl: null,
    };
  } catch (e) {
    console.error(e, iri);
    return null;
  }
};
