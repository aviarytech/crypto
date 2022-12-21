import { Ed25519VerificationKey2018 } from '$lib/keypairs/Ed25519VerificationKey2018';
import { base58, base64url } from '$lib/utils/encoding';
import { describe, expect, test } from 'vitest';
import { documentLoader } from '../fixtures/documentLoader';

describe('Ed25519VerificationKey2018', () => {
	test('resolves as JWK', async () => {
		const ed25519 = require('../fixtures/keypairs/Ed25519VerificationKey2018.json');

		const key = new Ed25519VerificationKey2018(
			ed25519.id,
			ed25519.controller,
			ed25519.publicKeyBase58,
			ed25519.privateKeyBase58
		);

		const jwk = await key.export({ privateKey: true, type: 'JsonWebKey2020' });
		expect(jwk.privateKeyJwk).to.deep.equal({
			crv: 'Ed25519',
			kty: 'OKP',
			x: base64url.encode(base58.decode(ed25519.publicKeyBase58)),
			d: base64url.encode(base58.decode(ed25519.privateKeyBase58))
		});
	});

	test('w/o private key resolves as JWK', async () => {
		const ed25519 = require('../fixtures/keypairs/Ed25519VerificationKey2018.json');
		const { privateKeyBase58, ...newKey } = ed25519

		const key = new Ed25519VerificationKey2018(
			newKey.id,
			newKey.controller,
			newKey.publicKeyBase58,
			newKey.privateKeyBase58
		);

		const jwk = await key.export({ privateKey: true, type: 'JsonWebKey2020' });
		expect(jwk.publicKeyJwk).to.deep.equal({
			crv: 'Ed25519',
			kty: 'OKP',
			x: base64url.encode(base58.decode(ed25519.publicKeyBase58))
		});
	});

	test(`Can create proof w/ challenge`, async () => {
		const credential = require(`../fixtures/credentials/case-1.json`);
		const ed25519 = require('../fixtures/keypairs/Ed25519VerificationKey2018.json');
		const key = new Ed25519VerificationKey2018(
			ed25519.id,
			ed25519.controller,
			ed25519.publicKeyBase58,
			ed25519.privateKeyBase58
		);

		const result = await key.createProof(
			credential,
			'assertionMethod',
			documentLoader,
			{challenge: 'challenge123'}
		);

		expect(result.challenge).to.be.equal('challenge123');
		expect(result).to.not.have.property('domain');
		expect(result).to.have.property('jws')
	});
});
