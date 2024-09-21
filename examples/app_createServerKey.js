const fs = require("fs");
const {createPrivateKey} = require("@musicslayer/easy_ssl");

async function init() {
    let serverKey = createPrivateKey({
        shaBits: 256,
        kty: "EC",
        crv: "P-256"
    });

    let data = {
        serverKey: JSON.stringify(serverKey)
    };
    fs.writeFileSync("server_info.txt", JSON.stringify(data));

    console.log("Server Key Creation Complete!");
}
init();
