import { EcdsaSecp256k1KeyPair } from "$lib";
import { describe, expect, test } from "vitest"

const key = require('../fixtures/keypairs/EcdsaSecp256k1VerificationKey2019.json');

describe('Secp256k1 KeyPair tests', () => {
	test('should construct from object', async () => {
		const keypair = await EcdsaSecp256k1KeyPair.from(key);

		expect(keypair.id).to.equal(key.id);
		expect(keypair.privateKeyBase58).to.equal(key.privateKeyBase58);
		expect(keypair.publicKeyBase58).to.equal(key.publicKeyBase58);
		expect(keypair.type).to.equal(key.type);
		expect(keypair.controller).to.equal(key.controller);
	});

	test('should sign and verify', async () => {
		const msg = 'hello tester';
		const encoder = new TextEncoder();
		const encodedMsg = encoder.encode(msg);
		const keypair = await EcdsaSecp256k1KeyPair.from(key);

		const signature = await keypair.sign({ data: encodedMsg });
		const verified = await keypair.verify({ data: encodedMsg, signature });

		expect(verified).to.be.true;
	});

	test('generates', async () => {
		let keypair = await EcdsaSecp256k1KeyPair.generate();
		expect(keypair).to.have.property('privateKey');
		expect(keypair).to.have.property('publicKey');
	});

	test('exports as JWK', async () => {
		const keypair = await EcdsaSecp256k1KeyPair.generate();
		const jwk = await keypair.export({
			privateKey: true,
			type: 'JsonWebKey2020'
		});
		expect(jwk).to.have.property('privateKeyJwk');
		expect(jwk.privateKeyJwk).to.have.property('d');
		expect(jwk).to.have.property('publicKeyJwk');
		expect(jwk.publicKeyJwk).to.have.property('x');
		expect(jwk.publicKeyJwk).to.have.property('y');
	});
	
	test('exports as JWK w/o private key', async () => {
		const keypair = await EcdsaSecp256k1KeyPair.generate();
		const jwkJustPub = await keypair.export();
		expect(jwkJustPub).to.have.property('publicKeyJwk');
		expect(jwkJustPub.publicKeyJwk).to.have.property('x');
		expect(jwkJustPub.publicKeyJwk).to.have.property('y');
		expect(jwkJustPub.privateKeyJwk).toBeUndefined();
	});

	test('from xpub', async () => {
		const xpub = 'xpub6CUGRUonZSQ4TWtTMmzXdrXDtypWKiKrhko4egpiMZbpiaQL2jkwSB1icqYh2cfDfVxdx4df189oLKnC5fSwqPfgyP3hooxujYzAu3fDVmz';
		const keypair = await EcdsaSecp256k1KeyPair.fromXpub(xpub);
		expect(keypair.id).toContain('zQ3shizorZPFPkPVctdMRanf441efDPxWhPu9e4fq5ZwtHN5D')
	})
});
