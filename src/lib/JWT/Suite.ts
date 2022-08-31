import type { JWA_ALG } from "$lib/constants";
import type { JWTPayload, VerificationResult } from "$lib/interfaces";
import type { JsonWebKey2020 } from "$lib/keypairs/JsonWebKey2020";
import { SignJWT, jwtVerify, importJWK } from "jose"

export class JWTSuite {
    public key: JsonWebKey2020;
    public alg: string;

    constructor(options: {key: JsonWebKey2020, alg?: JWA_ALG}) {
        if (options.key) {
            this.key = options.key;
        } else {
            throw new Error('`key` is required')
        }
        if (options.alg) {
            this.alg = options.alg
        } else {
            throw new Error('`alg` is required')
        }
    }

    async sign(payload: JWTPayload): Promise<string> {
        try {
			const { privateKeyJwk } = await this.key.export({ privateKey: true });
            if (!privateKeyJwk) {
                throw new Error(`key not found`)
            }
            const key = await importJWK(privateKeyJwk, this.alg)
            return await new SignJWT(payload).setProtectedHeader({alg: this.alg}).sign(key);
		} catch (e) {
			console.error('Failed to sign.', e);
			throw e;
		}
	}

	async verify(jwt: string): Promise<VerificationResult> {
		try {
			const { publicKeyJwk } = await this.key.export({ privateKey: true });
            if (!publicKeyJwk) {
                throw new Error(`key not found`)
            }
            const key = await importJWK(publicKeyJwk, this.alg)
            const { payload, protectedHeader } = await jwtVerify(jwt, key);
            return {
                verified: true,
                errors: []
            }
		} catch (e: any) {
			console.error(e.message);
			return {verified: false, errors: [e.message]};
		}
	}
}