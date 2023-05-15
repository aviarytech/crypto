import { describe, expect, test } from 'vitest';

import { Buffer } from 'buffer';
import { JsonWebKeyPair } from '$lib/keypairs/JsonWebKey2020';
import { documentLoader } from '../fixtures/documentLoader';
import { JsonWebSignature2020Suite } from '$lib/JWS/Suite';

const plaintext = require('../fixtures/plaintext.json');
const jwk2020 = require('../fixtures/keypairs/JsonWebKey2020.json');
const jws = require('../fixtures/jws.json');

describe('JWS', () => {
	test('Can sign data', async () => {
		const key = await JsonWebKeyPair.fromJWK(jwk2020);
		const suite = new JsonWebSignature2020Suite({
			key,
			date: new Date().toISOString()
		});

		const result = await suite.sign(Buffer.from(plaintext.body, 'utf-8'));

		expect(result).to.equal(jws.jws);
		expect(result).to.contain('..');
	});

	test('Can verify data', async () => {
		const key = await JsonWebKeyPair.fromJWK(jwk2020);
		const suite = new JsonWebSignature2020Suite({
			key,
			date: new Date().toISOString()
		});

		const result = await suite.verify(Buffer.from(plaintext.body, 'utf-8'), key, jws);

		expect(result).to.be.true;
	});

	test(`Can create proof w/ challenge`, async () => {
		const credential = require(`../fixtures/credentials/case-1.json`);
		const key = await JsonWebKeyPair.fromJWK(jwk2020);
		const suite = new JsonWebSignature2020Suite({
			key,
			date: new Date().toISOString()
		});

		const result = await suite.createProof(
			credential,
			'assertionMethod',
			documentLoader,
			{challenge: 'challenge123'}
		);

		expect(result.challenge).to.be.equal('challenge123');
		expect(result).to.not.have.property('domain');
	});

	test(`Can create proof w/ domain`, async () => {
		const credential = require(`../fixtures/credentials/case-1.json`);
		const key = await JsonWebKeyPair.fromJWK(jwk2020);
		const suite = new JsonWebSignature2020Suite({
			key,
			date: new Date().toISOString()
		});

		const result = await suite.createProof(
			credential,
			'assertionMethod',
			documentLoader,{domain: 'domain123'}
		);

		expect(result.domain).to.be.equal('domain123');
		expect(result).to.not.have.property('challenge');
	});

	test(`Can create proof w/ challenge & domain`, async () => {
		const credential = require(`../fixtures/credentials/case-1.json`);
		const key = await JsonWebKeyPair.fromJWK(jwk2020);
		const suite = new JsonWebSignature2020Suite({
			key,
			date: new Date().toISOString()
		});

		const result = await suite.createProof(
			credential,
			'assertionMethod',
			documentLoader,
			{
				domain: 'domain123',
				challenge: 'challenge123'
			}
		);

		expect(result.domain).to.be.equal('domain123');
		expect(result.challenge).to.be.equal('challenge123');
	});

	test(`Can verify proof w/ challenge & domain`, async () => {
		const credential = require(`../fixtures/credentials/case-1.json`);
		const proof = require('../fixtures/proofs/with-challenge-and-domain.json');
		const key = await JsonWebKeyPair.fromJWK(jwk2020);
		const suite = new JsonWebSignature2020Suite({
			key,
			date: new Date().toISOString()
		});

		const result = await suite.verifyProof(proof, credential, documentLoader);

		expect(result.verified).to.be.true;
	});

	// cases
	['1', '10'].forEach((v) => {
		test(`Can create proof: case-${v}`, async () => {
			const credential = require(`../fixtures/credentials/case-${v}.json`);
			const key = await JsonWebKeyPair.fromJWK(jwk2020);
			const suite = new JsonWebSignature2020Suite({
				key,
				date: new Date().toISOString()
			});

			const result = await suite.createProof(credential, 'assertionMethod', documentLoader);

			expect(result.proofPurpose).to.be.equal('assertionMethod');
			expect(result.type).to.be.equal('JsonWebSignature2020');
			expect(result).to.have.property('created');
			expect(result.verificationMethod).to.be.equal(jwk2020.id);
			expect(result).to.have.property('jws');
			expect(result.jws).to.contain('..');
			expect(result).to.not.have.property('@context');
		});

		test(`Can verify proof: case-${v}`, async () => {
			const credential = require(`../fixtures/credentials/case-${v}.json`);
			const proof = require(`../fixtures/proofs/case-${v}.json`);
			const key = await JsonWebKeyPair.fromJWK(jwk2020);
			const suite = new JsonWebSignature2020Suite({
				key,
				date: new Date().toISOString()
			});

			const result = await suite.verifyProof(proof, credential, documentLoader);

			expect(result.verified).to.be.true;
		});

		test(`Can create and verify proof: case-${v}`, async () => {
			const credential = require(`../fixtures/credentials/case-${v}.json`);
			const key = await JsonWebKeyPair.fromJWK(jwk2020);
			const suite = new JsonWebSignature2020Suite({
				key,
				date: new Date().toISOString()
			});

			const proof = await suite.createProof(credential, 'assertionMethod', documentLoader);
			const result = await suite.verifyProof(proof, credential, documentLoader);

			expect(result.verified).to.be.true;
		});
	});
});
