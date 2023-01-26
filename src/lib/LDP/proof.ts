export class LinkedDataProof {
	public type?: string;
	public proofPurpose?: string;
	public created?: string;
	public verificationMethod?: string;
	public challenge?: string;
	public domain?: string;

	constructor(
		type: string,
		proofPurpose: string,
		verificationMethod: string,
		challenge?: string,
		domain?: string,
		created?: string
	) {
		this.type = type;
		this.proofPurpose = proofPurpose;
		if (!created) {
			let date = new Date().toISOString();
			this.created = date.slice(0, date.length - 5) + 'Z';
		} else {
			this.created = created;
		}
		if (typeof challenge !== 'undefined') {
			this.challenge = challenge;
		}
		if (typeof domain !== 'undefined') {
			this.domain = domain;
		}

		this.verificationMethod = verificationMethod;
	}

	validate(maxTimestampDelta?: number) {
		if (maxTimestampDelta && maxTimestampDelta !== Infinity) {
			const expected = new Date().getTime();
			const delta = maxTimestampDelta * 1000;
			const created = new Date(this.created).getTime();
			// comparing this way handles NaN case where `created` is invalid
			if (!(created >= expected - delta && created <= expected + delta)) {
				console.error("The proof's created timestamp is out of range.");
				return false;
			}
		}
		return true;
	}

	toJSON() {
		return JSON.parse(JSON.stringify(this));
	}
}
