const ACME = require("./acme.js");

async function createAccount(accountKey, directoryUrl) {
    let acme = new ACME();
    await acme.init(directoryUrl);
    
    let kid = await acme.createAccount(accountKey);
    return kid
}

module.exports = createAccount;