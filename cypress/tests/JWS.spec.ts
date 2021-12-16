import { expect } from 'chai';
import { JsonWebKey, JsonWebSignature2020Suite } from '../../src/lib';
import { Buffer } from 'buffer/index.js';
import { documentLoader } from '../fixtures/documentLoader';

const plaintext = require('../fixtures/plaintext.json');
const jwk2020 = require('../fixtures/JsonWebKey2020.json');
const jws = require('../fixtures/jws.json');

describe('JWS', () => {
	it('Can sign data', async () => {
		const key = await JsonWebKey.fromJWK(jwk2020);
		const suite = new JsonWebSignature2020Suite({
			key,
			date: new Date().toISOString()
		});

		const result = await suite.sign(Buffer.from(plaintext.body, 'utf-8'));

		expect(result).to.equal(jws.jws);
		expect(result).to.contain('..');
	});

	it('Can verify data', async () => {
		const key = await JsonWebKey.fromJWK(jwk2020);
		const suite = new JsonWebSignature2020Suite({
			key,
			date: new Date().toISOString()
		});

		const result = await suite.verify(Buffer.from(plaintext.body, 'utf-8'), key, jws);

		expect(result).to.be.true;
	});

	it(`Can create proof w/ challenge`, async () => {
		const credential = require(`../fixtures/credentials/case-1.json`);
		const key = await JsonWebKey.fromJWK(jwk2020);
		const suite = new JsonWebSignature2020Suite({
			key,
			date: new Date().toISOString()
		});

		const result = await suite.createProof(
			credential,
			'assertionMethod',
			documentLoader,
			null,
			'challenge123'
		);

		expect(result.challenge).to.be.equal('challenge123');
		expect(result).to.not.have.property('domain');
	});

	it(`Can create proof w/ domain`, async () => {
		const credential = require(`../fixtures/credentials/case-1.json`);
		const key = await JsonWebKey.fromJWK(jwk2020);
		const suite = new JsonWebSignature2020Suite({
			key,
			date: new Date().toISOString()
		});

		const result = await suite.createProof(
			credential,
			'assertionMethod',
			documentLoader,
			'domain123'
		);

		expect(result.domain).to.be.equal('domain123');
		expect(result).to.not.have.property('challenge');
	});

	it(`Can create proof w/ challenge & domain`, async () => {
		const credential = require(`../fixtures/credentials/case-1.json`);
		const key = await JsonWebKey.fromJWK(jwk2020);
		const suite = new JsonWebSignature2020Suite({
			key,
			date: new Date().toISOString()
		});

		const result = await suite.createProof(
			credential,
			'assertionMethod',
			documentLoader,
			'domain123',
			'challenge123'
		);

		expect(result.domain).to.be.equal('domain123');
		expect(result.challenge).to.be.equal('challenge123');
	});

	it(`Can verify proof w/ challenge & domain`, async () => {
		const credential = require(`../fixtures/credentials/case-1.json`);
		const proof = require('../fixtures/proofs/with-challenge-and-domain.json');
		const key = await JsonWebKey.fromJWK(jwk2020);
		const suite = new JsonWebSignature2020Suite({
			key,
			date: new Date().toISOString()
		});

		const result = await suite.verifyProof(proof, credential, documentLoader);

		expect(result.verified).to.be.true;
	});

	// cases
	['1', '10'].forEach((v) => {
		it(`Can create proof: case-${v}`, async () => {
			const credential = require(`../fixtures/credentials/case-${v}.json`);
			const key = await JsonWebKey.fromJWK(jwk2020);
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

		it(`Can verify proof: case-${v}`, async () => {
			const credential = require(`../fixtures/credentials/case-${v}.json`);
			const proof = require(`../fixtures/proofs/case-${v}.json`);
			const key = await JsonWebKey.fromJWK(jwk2020);
			const suite = new JsonWebSignature2020Suite({
				key,
				date: new Date().toISOString()
			});

			const result = await suite.verifyProof(proof, credential, documentLoader);

			expect(result.verified).to.be.true;
		});

		it(`Can create and verify proof: case-${v}`, async () => {
			const credential = require(`../fixtures/credentials/case-${v}.json`);
			const key = await JsonWebKey.fromJWK(jwk2020);
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
