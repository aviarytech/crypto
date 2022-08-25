import { beforeEach, describe, expect, test } from 'vitest'
import { JWTSuite } from '$lib/JWT/Suite';
import { JsonWebKey } from '$lib';

let jwk2020: any;

describe('JWT', () => {
    beforeEach(() => {
		jwk2020 = require('../fixtures/JsonWebKey2020.json');
	})
    test('createJWT will create a JWT', async () => {
        const key = await JsonWebKey.fromJWK(jwk2020)
        const suite = new JWTSuite({key, alg: 'ES256K'})
        const signed = await suite.sign({claim: 'yes'})
        expect(signed.split('.').length).toBe(3)
    })

    test('verifyJWT will verify a JWT', async () => {
        const key = await JsonWebKey.fromJWK(jwk2020)
        const suite = new JWTSuite({key, alg: 'ES256K'})
        const verified = await suite.verify('eyJhbGciOiJFUzI1NksifQ.eyJjbGFpbSI6InllcyJ9.UBrdog1WyHoxypKro1w3MqcGWepYqusL0IJMART7cw_yFfLNWC9Vk3pv_Fa-KZcJdSj65Ip3XkC1UP5gWeReRQ')
        expect(verified.verified).toBeTruthy()
        expect(verified.errors).toHaveLength(0)
    })

    test('verifyJWT will error on malformed JWT', async () => {
        const key = await JsonWebKey.fromJWK(jwk2020)
        const suite = new JWTSuite({key, alg: 'ES256K'})
        const verified = await suite.verify('a51eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0Ijoib2siLCJpYXQiOjE2NTc3NTIzMDB9._E8d8OA7OPxQcEigW-neaF2lVju9OpjqryiVL8OZA7I')
        expect(verified.errors[0]).toBe('JWS Protected Header is invalid')
        expect(verified.verified).toBeFalsy()
    })
})