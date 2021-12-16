import type { LinkedDataProof } from '$lib/LDP/proof.js';

export interface Header {
	typ?: string;
	alg: string;
	kid: string;
	apu?: string;
	apv?: string;
	epk?: IJWK;
}

export interface IJWE {
	protected: string;
	iv: string;
	ciphertext: string;
	tag: string;
	aad?: string;
	recipients?: { header: Header; encrypted_key: string }[];
}

export interface IJWS {
	header: Header;
	payload: string;
	signature: string;
	protected?: string;
}

export interface IJWK {
	alg?: string;
	crv?: string;
	d?: string;
	dp?: string;
	dq?: string;
	e?: string;
	ext?: boolean;
	k?: string;
	key_ops?: string[];
	kid?: string;
	kty?: string;
	n?: string;
	oth?: Array<{
		d?: string;
		r?: string;
		t?: string;
	}>;
	p?: string;
	q?: string;
	qi?: string;
	use?: string;
	x?: string;
	y?: string;
	x5c?: string[];
	x5t?: string;
	'x5t#S256'?: string;
	x5u?: string;
}

export interface ProofVerificationResult {
	verified: boolean;
	error?: string;
}

export type DocumentLoader = (
	uri: string
) => Promise<{ document: any; documentUrl: string; contextUrl: string }>;

export interface LinkedDataSuite {
	type: string;
	date: string;
	context: string;

	createProof: (
		document: any,
		purpose: string,
		documentLoader: DocumentLoader,
		domain?: string,
		challenge?: string
	) => Promise<LinkedDataProof>;

	verifyProof: (
		proofDocument: LinkedDataProof,
		document: any,
		documentLoader: DocumentLoader
	) => Promise<ProofVerificationResult>;
}
