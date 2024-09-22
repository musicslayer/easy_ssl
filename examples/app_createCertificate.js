const fs = require("fs");
const {createCertificate} = require("@musicslayer/easy_ssl");

// This is NOT included in this package and must be installed separately i.e. npm install acme-dns-01-cloudflare
const plugin_cloudflare = require("acme-dns-01-cloudflare");

// Change these values based on your workflow.
const IS_STAGING = true; // Set to true for testing. Set to false when you wish to create certificates for your real domains.
const DOMAINS = ["a.yourdomain.com", "*.b.yourdomain.com"]; // Wildcards are permitted.
const COULDFLARE_API_KEY = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // This API Key needs "Zone:Zone:Read" and "Zone:DNS:Edit" permissions.

async function init() {
    let accountData = JSON.parse(fs.readFileSync("account_info.txt"));
    let accountKey = JSON.parse(accountData.accountKey);
    let kid = JSON.parse(accountData.kid);

    let serverData = JSON.parse(fs.readFileSync("server_info.txt"));
    let serverKey = JSON.parse(serverData.serverKey);

    let directoryUrl = IS_STAGING ? "https://acme-staging-v02.api.letsencrypt.org/directory" : "https://acme-v02.api.letsencrypt.org/directory";

    let challengePlugins = {
        "dns-01": plugin_cloudflare.create({
            token: COULDFLARE_API_KEY,
            verifyPropagation: true,
            verbose: true
        })
    };
    
    let certificate = await createCertificate(accountKey, serverKey, kid, directoryUrl, DOMAINS, challengePlugins);
    
    // Write SSL certificate and private key, both in PEM format.
    fs.writeFileSync("certificate.pem", certificate.certificatePEM);
    fs.writeFileSync("private-key.pem", certificate.privateKeyPEM);

    console.log("SSL Certificate Creation Complete!");
}
init();