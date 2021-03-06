import { JsonWebKey } from '../../src/lib';

let jwk2020;

describe('JsonWebKey2020', () => {
	beforeEach(() => {
		jwk2020 = require('../fixtures/JsonWebKey2020.json');
	});
	it('resolves as JWK', async () => {
		const jwk = new JsonWebKey(
			jwk2020.id,
			jwk2020.controller,
			jwk2020.publicKeyJwk,
			jwk2020.privateKeyJwk
		);

		expect(jwk.id).to.equal(jwk2020.id);
		expect(jwk.controller).to.equal(jwk2020.controller);
		expect(jwk.publicKeyJwk).to.equal(jwk2020.publicKeyJwk);
		expect(jwk.privateKeyJwk).to.equal(jwk2020.privateKeyJwk);
	});

	it('w/o private key resolves as JWK', async () => {
		const { privateKeyJwk, ...newjwk } = jwk2020;

		const jwk = new JsonWebKey(
			newjwk.id,
			newjwk.controller,
			newjwk.publicKeyJwk,
			newjwk.privateKeyJwk
		);

		expect(jwk.id).to.equal(newjwk.id);
		expect(jwk.controller).to.equal(newjwk.controller);
		expect(jwk.publicKeyJwk).to.equal(newjwk.publicKeyJwk);
		expect(jwk.privateKeyJwk).to.equal(newjwk.privateKeyJwk);
	});

	it('exports as LD', async () => {
		const jwk = new JsonWebKey(
			jwk2020.id,
			jwk2020.controller,
			jwk2020.publicKeyJwk,
			jwk2020.privateKeyJwk
		);

		const keypair = await jwk.exportAsLD({
			privateKey: true
		});

		expect(keypair.type).to.equal('EcdsaSecp256k1VerificationKey2019');
		expect(keypair.id).to.equal(jwk2020.id);
		expect(keypair).to.have.property('publicKeyBase58');
		expect(keypair).to.have.property('privateKeyBase58');
	});

	it('generates as X25519KeyPair', async () => {
		const keypair = await JsonWebKey.generate({ kty: 'OKP', crv: 'X25519' });

		expect(keypair.type).to.equal('X25519KeyAgreementKey2019');
		expect(keypair).to.have.property('publicKeyBase58');
		expect(keypair).to.have.property('privateKeyBase58');
	});
});
