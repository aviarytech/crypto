import * as vc from '@digitalbazaar/vc';

import { Ed25519VerificationKey2020, deriveKeyFromSeed } from '$lib/keypairs/Ed25519VerificationKey2020';
import { MULTICODEC_ED25519_PRIV_HEADER, MULTICODEC_ED25519_PUB_HEADER, base64url, multibase } from '$lib/utils/encoding';
import { describe, expect, test } from 'vitest';

import { HDKey } from 'micro-ed25519-hdkey';
import { bytesToHex } from '@noble/hashes/utils';
import { Ed25519VerificationKey2020 as dbKey } from '@digitalbazaar/ed25519-verification-key-2020';
import { Ed25519Signature2020 as dbSuite } from '@digitalbazaar/ed25519-signature-2020';
import { documentLoader } from '../fixtures/documentLoader';
import fixtures from "../fixtures/HD.json";

describe('HDKey', () => {
	let i = 0;
	for (const vector of fixtures.ed25519) {
		test(`${i}: can create HD Key from seed`, async () => {
			const key = deriveKeyFromSeed(vector.seed, vector.path)
			expect(bytesToHex(key.chainCode)).to.be.equal(vector.chainCode)
			expect(bytesToHex(key.privateKey)).to.be.equal(vector.privateKey)
			expect(bytesToHex(key.publicKey)).to.be.equal(vector.publicKey)
			expect(key.parentFingerprintHex).to.be.equal(vector.fingerprint)
		})
		i++
	}
})

describe('Ed25519VerificationKey2020', () => {
	test('fromBase58', async () => {
		const key = 'ByHnpUCFb1vAfh9CFZ8ZkmUZguURW8nSw889hy6rD8L7';
		const keypair = Ed25519VerificationKey2020.fromBase58({ publicKeyBase58: key })
	})
	test('resolves as JWK', async () => {
		const ed25519 = require('../fixtures/keypairs/Ed25519VerificationKey2020.json');

		const key = new Ed25519VerificationKey2020(
			ed25519.id,
			ed25519.controller,
			ed25519.publicKeyMultibase,
			ed25519.privateKeyMultibase
		);

		const jwk = await key.export({ privateKey: true, type: 'JsonWebKey2020' });
		expect(jwk.privateKeyJwk).to.deep.equal({
			crv: 'Ed25519',
			kty: 'OKP',
			x: base64url.encode(multibase.decode(MULTICODEC_ED25519_PUB_HEADER, ed25519.publicKeyMultibase)),
			d: base64url.encode(multibase.decode(MULTICODEC_ED25519_PRIV_HEADER, ed25519.privateKeyMultibase))
		});
	});

	test('w/o private key resolves as JWK', async () => {
		const ed25519 = require('../fixtures/keypairs/Ed25519VerificationKey2020.json');
		const { privateKeyMultibase, ...newKey } = ed25519;

		const key = new Ed25519VerificationKey2020(
			newKey.id,
			newKey.controller,
			newKey.publicKeyMultibase,
			newKey.privateKeyMultibase
		);

		const jwk = await key.export({ privateKey: true, type: 'JsonWebKey2020' });
		expect(jwk.publicKeyJwk).to.deep.equal({
			crv: 'Ed25519',
			kty: 'OKP',
			x: base64url.encode(multibase.decode(MULTICODEC_ED25519_PUB_HEADER, ed25519.publicKeyMultibase))
		});
	});

	test('can generate', async () => {
		const key = await Ed25519VerificationKey2020.generate()
		expect(key.publicKey.length).toEqual(32)
		expect(key).toHaveProperty('publicKey')
		expect(key).toHaveProperty('privateKey')
	})

	test('can create from hd key', async () => {
		const hd = HDKey.fromMasterSeed('fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542')
		const key = Ed25519VerificationKey2020.fromHD(hd)
		expect(key.publicKey.length).toEqual(32)
		expect(key.privateKey.length).toEqual(64)
		expect(key.controller).toEqual('did:key:z6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy')
	})

	test('can create valid proof from hd key', async () => {
		const hd = HDKey.fromMasterSeed('fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542')
		const credential = require(`../fixtures/credentials/case-1.json`);
		const key = Ed25519VerificationKey2020.fromHD(hd)
		expect(key.publicKey.length).toEqual(32)
		expect(key.privateKey.length).toEqual(64)
		expect(key.controller).toEqual('did:key:z6Mkp92myXtWkQYxhFmDxqkTwURYZAEjUm9iAuZxyjYzmfSy')
		const result = await key.createProof(
			credential,
			'assertionMethod',
			documentLoader,
			{ challenge: 'challenge123' }
		);
		const verification = await key.verifyProof(result, credential, documentLoader)
		expect(verification.verified).toBeTruthy()
	})


	test(`Can create proof w/ challenge`, async () => {
		const credential = require(`../fixtures/credentials/case-1.json`);
		const ed25519 = require('../fixtures/keypairs/Ed25519VerificationKey2020.json');
		const key = new Ed25519VerificationKey2020(
			ed25519.id,
			ed25519.controller,
			ed25519.publicKeyMultibase,
			ed25519.privateKeyMultibase
		);

		const result = await key.createProof(
			credential,
			'assertionMethod',
			documentLoader,
			{ challenge: 'challenge123' }
		);

		expect(result.challenge).to.be.equal('challenge123');
		expect(result).to.not.have.property('domain');
		expect(result).to.have.property('proofValue')
	});

	test(`Can verify proof case-1`, async () => {
		const credential = require(`../fixtures/credentials/case-1.json`);
		const ed25519 = require('../fixtures/keypairs/Ed25519VerificationKey2020.json');
		const key = new Ed25519VerificationKey2020(
			ed25519.id,
			ed25519.controller,
			ed25519.publicKeyMultibase,
			ed25519.privateKeyMultibase
		);

		const proof = await key.createProof(
			credential,
			'assertionMethod',
			documentLoader,
			{ challenge: 'challenge123' }
		);

		const result = await key.verifyProof(proof, credential, documentLoader)
		expect(result.verified).toBeTruthy()
	});

	test(`Can verify proof case-2`, async () => {
		const proof = require(`../fixtures/proofs/case-2.json`);
		const document = require(`../fixtures/documents/case-2.json`)
		const ed25519 = require('../fixtures/keypairs/case-2.json');
		const key = new Ed25519VerificationKey2020(
			ed25519.id,
			ed25519.controller,
			ed25519.publicKeyMultibase,
			ed25519.privateKeyMultibase
		);

		const result = await key.verifyProof(proof, document, documentLoader)
		console.log(result)
		expect(result.verified).toBeTruthy()
	});

	test(`debug`, async () => {
		const ed25519 = require('../fixtures/keypairs/Ed25519VerificationKey2020.json');
		const key = new Ed25519VerificationKey2020(
			ed25519.id,
			ed25519.controller,
			ed25519.publicKeyMultibase,
			ed25519.privateKeyMultibase
		);
		const p = {
			'@context': [
				'https://www.w3.org/2018/credentials/v1',
				"https://w3id.org/security/suites/ed25519-2020/v1"
			],
			holder: key.controller,
			type: ['VerifiablePresentation'],
			verifiableCredential: []
		};
		let proof = await key.createProof(p, 'authentication', documentLoader, { challenge: '72Jd0frtFmvKjQV65BFz4', domain: 'https://localhost:51433' })
		expect(proof.challenge).toBe('72Jd0frtFmvKjQV65BFz4')
		let verify = await key.verifyProof(proof, p, documentLoader)
		expect(verify.verified).toBeTruthy()
		// {
		// 	type: 'vc-ld',
		// 	suite: key,
		// 	challenge: 'challenge',
		// 	domain: 'domain',
		// 	documentLoader
		// });
	})

	test(`Can create proof that verifies with digital bazaar`, async () => {
		const ed25519 = { ...require('../fixtures/keypairs/Ed25519VerificationKey2020.json') };
		const credential = { ...require(`../fixtures/credentials/case-1.json`), issuer: { id: ed25519.controller } };
		const key = new Ed25519VerificationKey2020(
			ed25519.id,
			ed25519.controller,
			ed25519.publicKeyMultibase,
			ed25519.privateKeyMultibase
		);

		const result = await key.createProof(
			credential,
			'assertionMethod',
			documentLoader,
			{ challenge: 'challenge123', domain: 'http://domain.com' }
		);

		expect(result.challenge).to.be.equal('challenge123');
		expect(result.domain).to.be.equal('http://domain.com');
		expect(result).to.have.property('proofValue');
		const keyPair = new dbKey({
			id: ed25519.id,
			controller: ed25519.controller,
			publicKeyMultibase: ed25519.publicKeyMultibase,
		});
		const suite = new dbSuite({ key: keyPair });
		const res = await vc.verifyCredential({
			credential: { ...credential, proof: result },
			challenge: 'challenge123',
			domain: 'http://domain.com',
			suite,
			documentLoader
		});
		expect(res.verified).toBeTruthy()
	});
});
