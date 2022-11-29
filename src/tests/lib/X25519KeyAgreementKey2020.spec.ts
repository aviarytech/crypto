import { X25519KeyAgreementKey2020 } from '$lib/keypairs/X25519KeyAgreementKey2020';
import { base64url, multibase, MULTICODEC_X25519_PRIV_HEADER, MULTICODEC_X25519_PUB_HEADER } from '$lib/utils/encoding';
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
			x: base64url.encode(multibase.decode(MULTICODEC_X25519_PUB_HEADER, x25519key.publicKeyMultibase)),
			d: base64url.encode(multibase.decode(MULTICODEC_X25519_PRIV_HEADER, x25519key.privateKeyMultibase))
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
			x: base64url.encode(multibase.decode(MULTICODEC_X25519_PUB_HEADER, x25519key.publicKeyMultibase))
		});
	});

	test('can generate', async () => {
		const key = await X25519KeyAgreementKey2020.generate()
		expect(key).toHaveProperty('publicKey')
		expect(key).toHaveProperty('privateKey')
	})
});
