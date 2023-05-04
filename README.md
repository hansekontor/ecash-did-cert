# ecash-did-cert
Tools for using DIDs on eCash, following the did-cert-protocol.

# Install

```bash
$ npm install ecash-did-cert
```

# Usage

Example:

```js
const VC = require('ecash-did-cert');

(async() => {
    const usernameOptions = {
        issuerAddress: "ecash:qzwaq0yyqc3t6zqm75eqtjz5h3jrzztka5e7ne58nx",
        subjectAddress: "ecash:qpr9erjh78uct7lc7m2f0ueq2dmnd535du54fvmttx",
        credentialTypeCode: "usnm",
        claims: {
            username: "paul4"
        },
        expirationBlock: 987654
    };
    const usernameVC = new VC(usernameOptions);
    console.log("usernameVC", usernameVC);

    const usernameScript = usernameVC.buildCreationScript();
    console.log("OP_RETURN script", usernameScript.raw.toString('hex'));
    
    const parsedUsernameVC = await VC.fromBuffer(usernameScript.raw);
    console.log("parsedUsernameVC", parsedUsernameVC);
})();

```

