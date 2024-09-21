const X509 = require("./x509.js");

function createPrivateKey(keyOptions) {
    let privateKey = X509.generatePrivateKey(keyOptions);
    return privateKey;
}

module.exports = createPrivateKey;