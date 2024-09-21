const fs = require("fs");
const {createAccount, createPrivateKey} = require("@musicslayer/easy_ssl");

const IS_STAGING = true;

async function init() {
    let directoryUrl = IS_STAGING ? "https://acme-staging-v02.api.letsencrypt.org/directory" : "https://acme-v02.api.letsencrypt.org/directory";

    let accountKey = createPrivateKey({
        shaBits: 256,
        kty: "EC",
        crv: "P-256"
    });
    let kid = await createAccount(accountKey, directoryUrl);

    let data = {
        accountKey: JSON.stringify(accountKey),
        kid: JSON.stringify(kid)
    };
    fs.writeFileSync("account_info.txt", JSON.stringify(data));

    console.log("Account Key Creation Complete!");
}
init();
