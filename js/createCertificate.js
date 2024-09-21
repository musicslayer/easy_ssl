const ACME = require("./acme.js");

async function createCertificate(accountKey, serverKey, kid, directoryUrl, domains, challengePlugins) {
    let acme = new ACME();
    await acme.init(directoryUrl);

    let certificateOptions = {
        kid: kid,
        accountKey: accountKey,
        serverKey: serverKey,
        domains: domains,
        challengePlugins: challengePlugins
    };
    let pems = await acme.createCertificate(certificateOptions);
    return pems;
}

module.exports.createCertificate = createCertificate;