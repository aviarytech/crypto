/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
import * as cipher from '$lib/JWE/xc20p.js';

import { base64url, utf8 } from '$lib/utils/encoding.js';

const CIPHER_ALGORITHMS: any = {
	[cipher.JWE_ENC]: cipher
};

// 1 MiB = 1048576
const DEFAULT_CHUNK_SIZE = 1048576;

export class EncryptTransformer {
	public recipients: any;
	public encodedProtectedHeader: any;
	public additionalData: any;
	public cek: any;
	public chunkSize: any;
	public offset: any;
	public totalOffset: any;
	public index: any;
	public buffer: any;

	constructor({
		recipients,
		encodedProtectedHeader,
		additionalData,
		cek,
		chunkSize = DEFAULT_CHUNK_SIZE
	}: any = {}) {
		this.recipients = recipients;
		this.encodedProtectedHeader = encodedProtectedHeader;
		this.additionalData = additionalData;
		this.cek = cek;
		this.chunkSize = chunkSize;
		this.offset = 0;
		this.totalOffset = 0;
		this.index = 0;
	}

	start() {
		this.buffer = new Uint8Array(this.chunkSize);
	}

	async transform(chunk: any, controller: any) {
		const { buffer } = this;

		// assumes `chunk` is a Uint8Array...
		if (!(chunk instanceof Uint8Array)) {
			throw new TypeError('"chunk" must be an object.');
		}
		while (chunk) {
			const space = buffer.length - this.offset;
			if (chunk.length <= space) {
				buffer.set(chunk, this.offset);
				this.offset += chunk.byteLength;
				this.totalOffset += chunk.byteLength;
				chunk = null;
			} else {
				const partial = new Uint8Array(chunk.buffer, chunk.byteOffset, space);
				chunk = new Uint8Array(chunk.buffer, chunk.byteOffset + space, chunk.length - space);
				buffer.set(partial, this.offset);
				this.offset += space;
				this.totalOffset += space;
			}

			// flush if buffer is full and more data remains
			if (chunk) {
				await this.flush(controller);
			}
		}
	}

	async flush(controller: any) {
		if (this.offset === 0) {
			// nothing to flush
			return;
		}

		// encrypt data
		const { buffer } = this;
		const data = new Uint8Array(buffer.buffer, buffer.byteOffset, this.offset);
		const jwe = await this.encrypt(data);

		// clear buffer
		this.offset = 0;

		controller.enqueue({
			index: this.index++,
			offset: this.totalOffset,
			jwe
		});
	}

	async encrypt(data: any) {
		const { additionalData, cek, encodedProtectedHeader } = this;
		const protectedHeader = JSON.parse(utf8.decode(base64url.decode(encodedProtectedHeader)))
		const suite = CIPHER_ALGORITHMS[protectedHeader.enc];

		const { ciphertext, iv, tag } = await suite.encrypt({
			data,
			additionalData,
			cek
		});

		// represent encrypted data as JWE
		const jwe = {
			protected: this.encodedProtectedHeader,
			recipients: this.recipients,
			iv: base64url.encode(iv),
			ciphertext: base64url.encode(ciphertext),
			tag: base64url.encode(tag)
		};
		return jwe;
	}
}
