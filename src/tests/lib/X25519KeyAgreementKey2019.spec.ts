import { X25519KeyPair } from '$lib/keypairs/X25519KeyAgreementKey2019';
import { base58, base64url } from '$lib/utils/encoding';
import { describe, expect, test } from 'vitest';

describe('X25519KeyAgreementKey2019', () => {
	test('resolves as JWK', async () => {
		const x25519key = require('./fixtures/X25519KeyAgreementKey2019.json');

		const key = new X25519KeyPair(
			x25519key.id,
			x25519key.controller,
			x25519key.publicKeyBase58,
			x25519key.privateKeyBase58
		);

		const jwk = await key.export({ privateKey: true, type: 'JsonWebKey2020' });
		expect(jwk.privateKeyJwk).to.deep.equal({
			crv: 'X25519',
			kty: 'OKP',
			x: base64url.encode(base58.decode(x25519key.publicKeyBase58)),
			d: base64url.encode(base58.decode(x25519key.privateKeyBase58))
		});
	});

	test('w/o private key resolves as JWK', async () => {
		let x25519key = require('./fixtures/X25519KeyAgreementKey2019.json');
		delete x25519key['privateKeyBase58'];

		const key = new X25519KeyPair(
			x25519key.id,
			x25519key.controller,
			x25519key.publicKeyBase58,
			x25519key.privateKeyBase58
		);

		const jwk = await key.export({ privateKey: true, type: 'JsonWebKey2020' });
		expect(jwk.publicKeyJwk).to.deep.equal({
			crv: 'X25519',
			kty: 'OKP',
			x: base64url.encode(base58.decode(x25519key.publicKeyBase58))
		});
	});
});
