import { X25519KeyAgreementKey2020 } from '$lib/keypairs/X25519KeyAgreementKey2020';
import { base64url } from '$lib/utils/encoding';
import { base58btc as base58 } from 'multiformats/bases/base58';
import { describe, expect, test } from 'vitest';

describe('X25519KeyAgreementKey2020', () => {
	test('resolves as JWK', async () => {
		const x25519key = require('../fixtures/keypairs/X25519KeyAgreementKey2020.json');

		const key = new X25519KeyAgreementKey2020(
			x25519key.id,
			x25519key.controller,
			x25519key.publicKeyMultibase,
			x25519key.privateKeyMultibase
		);

		const jwk = await key.export({ privateKey: true, type: 'JsonWebKey2020' });
		expect(jwk.privateKeyJwk).to.deep.equal({
			crv: 'X25519',
			kty: 'OKP',
			x: base64url.encode(base58.decode(x25519key.publicKeyMultibase)),
			d: base64url.encode(base58.decode(x25519key.privateKeyMultibase))
		});
	});

	test('w/o private key resolves as JWK', async () => {
		let x25519key = require('../fixtures/keypairs/X25519KeyAgreementKey2020.json');
		delete x25519key['privateKeyMultibase'];

		const key = new X25519KeyAgreementKey2020(
			x25519key.id,
			x25519key.controller,
			x25519key.publicKeyMultibase,
			x25519key.privateKeyMultibase
		);

		const jwk = await key.export({ privateKey: true, type: 'JsonWebKey2020' });
		expect(jwk.publicKeyJwk).to.deep.equal({
			crv: 'X25519',
			kty: 'OKP',
			x: base64url.encode(base58.decode(x25519key.publicKeyMultibase))
		});
	});
});
