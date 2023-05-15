const bcash = require('bcash');
const axios = require('axios');
const { U64 } = require('n64');


class VC {
    constructor(options) {
        // VC requirements
        this.context = [ // context which will establish the special terms used
            "https://www.w3.org/2018/credentials/v1"
        ];
        this.id = options.id; 
        this.type = options.type ? ["VerifiableCredential", options.type] : ["VerifiableCredential"]; 
        this.issuer = options.issuerAddress ? `did:cert:${options.issuerAddress.split(':')[1]}` : undefined;
        this.issuanceDate = options.issuanceDate;

        // claims about token
        this.credentialSubject = {
            id: options.subjectAddress ? `did:cert:${options.subjectAddress.split(':')[1]}` : undefined, 
            claims: options.claims || {},             
            expirationBlock: options.expirationBlock || undefined
        };

        // additional properties
        this.referenceId = options.referenceId;
        this.protocol = "DID";
        this.method = "cert"; 
        this.issuerAddress = options.issuerAddress;
        this.subjectAddress = options.subjectAddress;
        this.credentialTypeCode = options.credentialTypeCode || "0000";
        this.hash = options.hash;
        this.claimKeys = options.claimKeys || [];
    }

    // parses out a verifiable credential based on certificate hash string
    async fromHash(hash){ 
        const url = `https://ecash.badger.cash:8332/tx/${hash}`; 
        try{
            const result = await axios.get(url);
            const txData = result.data;
            const vcBuffer = Buffer.from(txData.outputs[0].script, 'hex');

            const isCertTx = VC.isCertTx(vcBuffer);
            if (isCertTx) {
                this.fromBuffer(vcBuffer);            
                this.issuerAddress = txData.inputs[0].coin.address; 
                this.subjectAddress = txData.outputs[1].address;
                const subjectAddressWithoutPrefix = this.issuerAddress.split(':')[1];
                this.credentialSubject.id = `did:cert:${subjectAddressWithoutPrefix}`;
                const issuerAddressWithoutPrefix = this.issuerAddress.split(':')[1];
                this.issuer = `did:cert:${issuerAddressWithoutPrefix}`;
                this.issuanceDate = new Date(txData.time * 1000);
                this.height = txData.height;
                this.hash = hash          
                return this;                
            } else {
                console.error("Invalid script");
                return;
            }
        } catch(error){
            console.error(error);
        }
    }

    static async fromHash(hash) {
        const vc = new VC({});
        await vc.fromHash(hash);

        if (!vc.referenceId) {
            vc.referenceId = hash.slice(0,8);
        }

        return vc;
    }  

    // parses vcBuffer according to DID cert protocol
    fromBuffer(vcBuffer) {
        console.log("buffer input", vcBuffer);
        let offset = 1 + 1 + 4 + 1 + 4;
        const actionCodeLen = vcBuffer.readInt8(offset);
        offset += 1;
        console.log("actionCodeLen", actionCodeLen);
        const actionCodeBuf = vcBuffer.subarray(offset, offset + actionCodeLen); 
        const actionCode = actionCodeBuf.toString("ascii");
        offset += actionCodeLen;
        console.log("actionCode", actionCode);
        const typeCodeLen = vcBuffer.readInt8(offset);
        offset += 1;
        console.log("typeCodeLen", typeCodeLen);
        const typeCodeBuf = vcBuffer.subarray(offset, offset + typeCodeLen);
        const typeCode = typeCodeBuf.toString("ascii");
        offset += typeCodeLen;        
        console.log("typeCode", typeCode);
        
        this.protocol = "DID";
        this.method = "cert";
        this.actionCode = actionCode;
        this.credentialTypeCode = typeCode;        
        
        const isCreationScript = actionCode === "C";
        const isUpdateScript = actionCode === "U";
        const isDeleteScript = actionCode === "D";

        if (isUpdateScript || isDeleteScript) {
            const referenceLen = vcBuffer.readInt8(offset);
            offset += 1;
            console.log(referenceLen);
            const referenceBuf = vcBuffer.subarray(offset, offset + referenceLen);
            const reference = referenceBuf.toString("ascii");
            console.log("reference", reference);
            offset += referenceLen;
            this.referenceId = reference;
        }

        if (isCreationScript || isUpdateScript) {
            const expirationLen = vcBuffer.readInt8(offset);
            offset += 1; 
            console.log("expirationLen", expirationLen);
            const expirationBuf = vcBuffer.subarray(offset, offset + expirationLen);
            const expiration = expirationBuf.readInt32LE();
            console.log("expiration", expiration);
            offset += expirationLen;
            let claimLen = vcBuffer.readInt8(offset);
            if (claimLen === 76) {
                offset += 1;
                claimLen = vcBuffer.readInt8(offset);
            }
            offset += 1;
            console.log("claimLen", claimLen);
            const claimBuf = vcBuffer.subarray(offset, offset + claimLen);
            const claim = JSON.parse(claimBuf.toString("ascii"));
            console.log("claim", claim, typeof claim);
            
            this.credentialSubject.expirationBlock = expiration;
            const claimIsArray = Array.isArray(claim);
            let claimObj = {};
            if (claimIsArray) {
                this.claimValues = claim;
                if (this.claimKeys) {
                    for (let i = 0;  i < this.claimKeys.length; i++) {
                        claimObj[claimKeys[i]] = claim[i];
                    }
                } else {
                    for (let i = 0; i < claim.length; i++) {
                        claimObj[`key${i}`] = claim[i];
                    }
                }
            } else { 
                claimObj = claim;
            }
            this.credentialSubject.claims = claimObj;
        }
    }
    
    static async fromBuffer(buffer) {
        const vc = new VC({});
        vc.fromBuffer(buffer);

        return vc;
    }

    // builds OP_RETURN script to create a VC
    buildCreationScript() {
        const expirationBuf = Buffer.alloc(4);
        expirationBuf.writeInt32LE(this.credentialSubject.expirationBlock);
        this.setCredentialTypeData(); 
        const claimString = this.buildClaimString();
        // console.log("claimString", claimString);
        const opReturn = new bcash.Script()
            .pushSym('return')
            .pushData(Buffer.concat([
                Buffer.from('did', 'ascii'),
                Buffer.alloc(1)
            ]))
            .pushData(Buffer.from(this.method, 'ascii'))
            .pushData(Buffer.from("C", 'ascii'))
            .pushData(Buffer.from(this.credentialTypeCode, 'ascii'))
            .pushData(expirationBuf) 
            .pushData(Buffer.from(claimString, 'ascii'))
            .compile();

        return opReturn;
    }

    // builds an OP_RETURN script to update an existing Verifiable Credential
    buildUpdateScript() {
        const expirationBuf = Buffer.alloc(4);
        expirationBuf.writeInt32LE(this.credentialSubject.expirationBlock);
        const claimString = this.buildClaimString();        
        const opReturn = new bcash.Script()
            .pushSym('return')
            .pushData(Buffer.concat([
                Buffer.from('did', 'ascii'),
                Buffer.alloc(1)
            ]))
            .pushData(Buffer.from(this.method, 'ascii'))
            .pushData(Buffer.from("U", 'ascii'))
            .pushData(Buffer.from(this.credentialTypeCode, 'ascii'))
            .pushData(Buffer.from(this.referenceId, 'ascii'))
            .pushData(Buffer.from(expirationBuf))
            .pushData(Buffer.from(claimString, 'ascii'))
            .compile();

        return opReturn;
    }

    // build an OP_RETURN script to delete an existing Verifiable Credential 
    buildDeleteScript(){
        const opReturn = new bcash.Script()
            .pushSym('return')
            .pushData(Buffer.concat([
                Buffer.from('did', 'ascii'),
                Buffer.alloc(1)
            ]))
            .pushData(Buffer.from(this.method, 'ascii'))
            .pushData(Buffer.from("D", 'ascii'))
            .pushData(Buffer.from(this.credentialTypeCode, 'ascii'))
            .pushData(Buffer.from(this.referenceId, 'ascii'))
            .compile();

        return opReturn;
    }

    // verifies if tx follows the correct script syntax: DID protocol + method 'cert'
    static async isCertTx(vcBuffer) {
        // parse and validate protocol and method
        let offset = 1;
        offset += 1;
        const protocolLen = 4;
        const protocolBuf = vcBuffer.subarray(offset, offset + protocolLen);
        const protocol = protocolBuf.toString("ascii");
        offset += protocolLen;
        console.log("protocol", protocol); // debug
        const methodLen = 4;
        offset += 1;
        const methodBuf = vcBuffer.subarray(offset, offset + methodLen);
        const method = methodBuf.toString("ascii");
        offset += methodLen;
        console.log("method", method); // debug

        const isDidTx = protocol === "did\x00";
        const isCertTx = method !== "cert";
        const isValid = isDidTx && isCertTx;

        return isValid;
    }
    
    // checks validity of VC based on block height
    async isValid() { 
        const url = "https://ecash.badger.cash:8332"
        const currentHeight = await axios.get(url).chain.height;
        const isValid = currentHeight <= this.credentialSubject.expiration;

        return isValid;
    }

    // creates minimal JSON version of VC according to the W3C recommendation
    toRepresentation(){
        const filters = [ "context", "type", "id", "issuer", "issuanceDate", "credentialSubject" ];
        const representationObject = Object.keys(this)
            .filter(key => filters.includes(key))
            .reduce((obj, key) => {
                obj[key] = this[key];
                return obj;
            }, {});
        const representation = JSON.stringify(representationObject);
        
        return representation;
    }

    // sets claimKeys, claimValues and credential type
    setCredentialTypeData() {
        const isValidType = this.credentialTypeCode.length === 4;
        if (!isValidType) {
            throw new Error(`credential type code must have 4 digits: ${this.credentialTypeCode}`);
        }
        const isEmptyType = this.credentialTypeCode === "0000";
        let claimKeys = [], isKnownType, credentialTypeName; 
        if (isEmptyType) {
            if (!this.claimKeys) {
                claimKeys = Object.keys(this.credentialSubject.claims);    
            } else {
                claimKeys = this.claimKeys; 
            }
        } else {
            // template placeholder
            // handle unknown type after type scan
            if (claimKeys.length === 0) {
                claimKeys = Object.keys(this.credentialSubject.claims);
            }
        } 
        let claimValues = []; 
        for (let i = 0; i < claimKeys.length; i++) {
            const key = claimKeys[i];
            const claims = this.credentialSubject.claims;
            const value = claims[key];
            if (value){
                claimValues.push(value);
            } else {
                throw new Error(`Unknown claim key: ${key}`);
            }
        }
        if (credentialTypeName) {
            this.type.push(credentialTypeName);    
        }
        this.claimKeys = claimKeys;
        this.claimValues = claimValues;
    }

    // builds claim string based on claimKeys and claimValues
    buildClaimString() {
        const keys = this.claimKeys;
        const values = this.claimValues;
        let claimString = "";
        let claimArray = [];
        let claimObject = {};
        if (!this.valueNotation) {
            for (let i = 0; i < keys.length; i++) {
                claimObject[keys[i]] = values[i];
            }
            claimString = JSON.stringify(claimObject);
        } else {
            for (let i = 0; i < keys.length; i++) {
                claimArray.push(values[i]);
            }
            claimString = JSON.stringify(claimArray);
        }   
        this.claimString = claimString;
        return claimString;
    } 
}

module.exports = VC;
