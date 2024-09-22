const crypto = require("crypto");

const ASN1 = require("./asn1.js");

// Object IDs
const OBJ_ID_EC_PUBLIC_KEY = "2a8648ce3d0201"                       // 1.2.840.10045.2.1 ecPublicKey
const OBJ_ID_P256 = "2a8648ce3d030107";                             // 1.2.840.10045.3.1.7 P-256 Elliptic Curve
const OBJ_ID_ECDSA_WITH_SHA224 = "2a8648ce3d040301";                // 1.2.840.10045.4.3.1 ecdsaWithSHA224 (ANSI X9.62 ECDSA algorithm with SHA224)
const OBJ_ID_ECDSA_WITH_SHA256 = "2a8648ce3d040302";                // 1.2.840.10045.4.3.2 ecdsaWithSHA256 (ANSI X9.62 ECDSA algorithm with SHA256)
const OBJ_ID_ECDSA_WITH_SHA384 = "2a8648ce3d040303";                // 1.2.840.10045.4.3.3 ecdsaWithSHA384 (ANSI X9.62 ECDSA algorithm with SHA384)
const OBJ_ID_ECDSA_WITH_SHA512 = "2a8648ce3d040304";                // 1.2.840.10045.4.3.4 ecdsaWithSHA512 (ANSI X9.62 ECDSA algorithm with SHA512)
const OBJ_ID_RSA_ENCRYPTION = "2a864886f70d010101";                 // 1.2.840.113549.1.1.1 rsaEncryption
const OBJ_ID_SHA256_WITH_RSA_ENCRYPTION = "2a864886f70d01010b";     // 1.2.840.113549.1.1.11 sha256WithRSAEncryption (PKCS #1)
const OBJ_ID_SHA384_WITH_RSA_ENCRYPTION = "2a864886f70d01010c";     // 1.2.840.113549.1.1.12 sha384WithRSAEncryption (PKCS #1)
const OBJ_ID_SHA512_WITH_RSA_ENCRYPTION = "2a864886f70d01010d";     // 1.2.840.113549.1.1.13 sha512WithRSAEncryption (PKCS #1)
const OBJ_ID_SHA224_WITH_RSA_ENCRYPTION = "2a864886f70d01010e";     // 1.2.840.113549.1.1.14 sha224WithRSAEncryption (PKCS #1)
const OBJ_ID_EXTENSION_REQUEST = "2a864886f70d01090e";              // 1.2.840.113549.1.9.14 extensionRequest (PKCS #9 via CRMF)
const OBJ_ID_P224 = "2b81040021";                                   // 1.3.132.0.33 P-224 Elliptic Curve
const OBJ_ID_P384 = "2b81040022";                                   // 1.3.132.0.34 secp384r1 P-384 Elliptic Curve
const OBJ_ID_P521 = "2b81040023";                                   // 1.3.132.0.35 secp521r1 P-521 Elliptic Curve
const OBJ_ID_COMMON_NAME = "550403";                                // 2.5.4.3 commonName (X.520 DN component)
const OBJ_ID_SUBJECT_ALT_NAME = "551d11";                           // 2.5.29.17 subjectAltName (X.509 extension)

// Mapping of SHA information
const shaMap = {
    224: {alg: "sha224", ecdsa_id: OBJ_ID_ECDSA_WITH_SHA224, rsa_id: OBJ_ID_SHA224_WITH_RSA_ENCRYPTION},
    256: {alg: "sha256", ecdsa_id: OBJ_ID_ECDSA_WITH_SHA256, rsa_id: OBJ_ID_SHA256_WITH_RSA_ENCRYPTION},
    384: {alg: "sha384", ecdsa_id: OBJ_ID_ECDSA_WITH_SHA384, rsa_id: OBJ_ID_SHA384_WITH_RSA_ENCRYPTION},
    512: {alg: "sha512", ecdsa_id: OBJ_ID_ECDSA_WITH_SHA512, rsa_id: OBJ_ID_SHA512_WITH_RSA_ENCRYPTION}
}

// Mapping of elliptic curve information
const crvMap = {
    "P-224": {crv_id: OBJ_ID_P224},
    "P-256": {crv_id: OBJ_ID_P256},
    "P-384": {crv_id: OBJ_ID_P384},
    "P-521": {crv_id: OBJ_ID_P521} // Not a typo! It really is called P-521 and not P-512.
}

function generatePrivateKey(jwk) {
    let privateKey;
    if("EC" === jwk.kty) {
        let keypair = crypto.generateKeyPairSync("ec", {
            namedCurve: jwk.crv,
            privateKeyEncoding: { type: "sec1", format: "der" },
            publicKeyEncoding: { type: "spki", format: "der" }
        });

        privateKey = parseSec1(keypair.privateKey);
        privateKey.kty = jwk.kty;
        privateKey.shaBits = jwk.shaBits;
        privateKey.crv = jwk.crv;

        thumbInfo = {
            crv: privateKey.crv,
            kty: privateKey.kty,
            x: privateKey.x,
            y: privateKey.y
        };
    }
    else if("RSA" === jwk.kty) {
        let keypair = crypto.generateKeyPairSync("rsa", {
            modulusLength: jwk.modulusLength,
            publicExponent: jwk.publicExponent,
            privateKeyEncoding: { type: "pkcs1", format: "der" },
            publicKeyEncoding: { type: "pkcs1", format: "der" }
        });

        privateKey = parsePkcs1(keypair.privateKey);
        privateKey.kty = jwk.kty;
        privateKey.shaBits = jwk.shaBits;
        privateKey.modulusLength = jwk.modulusLength;
        privateKey.publicExponent = jwk.publicExponent;

        thumbInfo = {
            e: privateKey.e,
            kty: privateKey.kty,
            n: privateKey.n
        };
    }
    else {
        throw new Error("Unsupported key type: " + jwk.kty);
    }

    // Create a thumbprint based on the key.
    let payload = JSON.stringify(thumbInfo);
    let hash = shaDigest(strToBuf(payload), privateKey.shaBits);
    let thumb = bufToUrlBase64(hash);

    privateKey.thumb = thumb;

    return privateKey;
}

function convertPrivateKey(privateKeyDER) {
    // Converts a private key from DER to PEM.
    let type;
    let key;
    if("EC" === privateKeyDER.kty) {
        type = "sec1"
        key = packSec1(privateKeyDER);
    }
    else if("RSA" === privateKeyDER.kty) {
        type = "pkcs1"
        key = packPkcs1(privateKeyDER);
    }
    else {
        throw new Error("Unsupported key type: " + privateKeyDER.kty);
    }

    let privateKeyPEM = crypto.createPrivateKey({ key: key, type: type, format: "der" }).export({ type: type, format: "pem" });
    return privateKeyPEM;
}

function createCSR(jwk, domains) {
    let key;
    if("EC" === jwk.kty) {
        key = packSec1(jwk);
    }
    else if("RSA" === jwk.kty) {
        key = packPkcs1(jwk);
    }
    else {
        throw new Error("Unsupported key type: " + jwk.kty);
    }

    let sty = packSty(jwk);
    let request = packCSR(jwk, domains);
    let signature = shaSign(hexToBuf(request), jwk.shaBits, key, jwk.kty);

    let csr = ASN1.packGroup(
        { type: "30", values: [
            request,
            sty,
            { type: "03", values: [bufToHex(signature)]}
        ]}
    );

    return csr;
}

function createJWS(jwk, msg) {
    let key;
    let signature;
    if("EC" === jwk.kty) {
        key = packSec1(jwk);
        signature = shaSign(strToBuf(msg), jwk.shaBits, key, jwk.kty);
        signature = ecdsaAsn1SigToJoseSig(signature);
    }
    else if("RSA" === jwk.kty) {
        key = packPkcs1(jwk);
        signature = shaSign(strToBuf(msg), jwk.shaBits, key, jwk.kty);
    }
    else {
        throw new Error("Unsupported key type: " + jwk.kty);
    }

    return signature;
}

function ecdsaAsn1SigToJoseSig(binsig) {
    // Parse signature to extract two UInt values.
    let parsedData = ASN1.parseGroup(binsig, {
        type: "30", children: [
            { type: "02", children: [] },
            { type: "02", children: [] }
        ]
    });

    return Buffer.concat([parsedData[0], parsedData[1]]);
};

function packCSR(jwk, domains) {
    let S;
    if("EC" === jwk.kty) {
        S = { type: "30", values: [
                { type: "30", values: [
                    { type: "06", values: [OBJ_ID_EC_PUBLIC_KEY]},
                    { type: "06", values: [getCurveID(jwk.crv)]}
                ]},
                { type: "03", values: ["04", base64ToHex(jwk.x), base64ToHex(jwk.y)] }
        ]}
    }
    else if("RSA" === jwk.kty) {
        S = { type: "30", values: [
                { type: "30", values: [
                    { type: "06", values: [OBJ_ID_RSA_ENCRYPTION] },
                    { type: "05", values: [] }
                ]},
                { type: "03", values: [
                    { type: "30", values: [
                        { type: "02", values: [base64ToHex(jwk.n)] },
                        { type: "02", values: [base64ToHex(jwk.e)] }
                    ]}
                ]}
        ]}
    }
    else {
        throw new Error("Unsupported key type: " + jwk.kty);
    }

    return ASN1.packGroup(
        { type: "30", values: [
            // Version (0)
            { type: "02", values: ["00"] },

            // Common Name
            { type: "30", values: [
                { type: "31", values: [
                    { type: "30", values: [
                        { type: "06", values: [OBJ_ID_COMMON_NAME] },
                        { type: "0c", values: [strToHex(domains[0])] }
                    ]}
                ]}
            ]},
            
            // Public Key (RSA or EC)
            S,

            // Request Body
            { type: "a0", values: [
                { type: "30", values: [
                    { type: "06", values: [OBJ_ID_EXTENSION_REQUEST] },
                    { type: "31", values: [
                        { type: "30", values: [
                            { type: "30", values: [
                                { type: "06", values: [OBJ_ID_SUBJECT_ALT_NAME] },
                                { type: "04", values: [
                                    { type: "30", values: domains.map((domain) => ({ type: "82", values: [strToHex(domain)]})) }
                                ]}
                            ] }
                        ] }
                    ]}
                ] }
            ]}
        ]}
    );
};

function packSty(jwk) {
    let sty;
    if("EC" === jwk.kty) {
        sty = ASN1.packGroup(
            { type: "30", values: [
                { type: "06", values: [getECDSAID(jwk.shaBits)] }
            ]}
        );
    }
    else if("RSA" === jwk.kty) {
        sty = ASN1.packGroup(
            { type: "30", values: [
                { type: "06", values: [getRSAID(jwk.shaBits)] },
                { type: "05", values: [] }
            ]}
        );
    }
    else {
        throw new Error("Unsupported key type: " + jwk.kty);
    }
    return sty;
}

function packPkcs1(jwk) {
    return hexToBuf(ASN1.packGroup(
        { type: "30", values: [
            { type: "02", values: ["00"] },
            { type: "02", values: [base64ToHex(jwk.n)] },
            { type: "02", values: [base64ToHex(jwk.e)] },
            { type: "02", values: [base64ToHex(jwk.d)] },
            { type: "02", values: [base64ToHex(jwk.p)] },
            { type: "02", values: [base64ToHex(jwk.q)] },
            { type: "02", values: [base64ToHex(jwk.dp)] },
            { type: "02", values: [base64ToHex(jwk.dq)] },
            { type: "02", values: [base64ToHex(jwk.qi)] },
        ]}
    ));
}

function packSec1(jwk) {
    let key = hexToBuf(ASN1.packGroup(
        { type: "30", values: [
            { type: "02", values: ["01"] },
            { type: "04", values: [base64ToHex(jwk.d)] },
            { type: "a0", values: [
                { type: "06", values: [getCurveID(jwk.crv)]}
            ]},
            { type: "a1", values: [
                { type: "03", values: ["04", base64ToHex(jwk.x), base64ToHex(jwk.y)] }
            ]}
        ]}
    ));

    return key;
}

function parsePkcs1(bytes) {
    let parsedData = ASN1.parseGroup(bytes,
        { type: "30", children: [
            { type: "02", children: [] },
            { type: "02", children: [] },
            { type: "02", children: [] },
            { type: "02", children: [] },
            { type: "02", children: [] },
            { type: "02", children: [] },
            { type: "02", children: [] },
            { type: "02", children: [] },
            { type: "02", children: [] }
        ]}
    );

    return {
        n: bufToUrlBase64(parsedData[1]),
        e: bufToUrlBase64(parsedData[2]),
        d: bufToUrlBase64(parsedData[3]),
        p: bufToUrlBase64(parsedData[4]),
        q: bufToUrlBase64(parsedData[5]),
        dp: bufToUrlBase64(parsedData[6]),
        dq: bufToUrlBase64(parsedData[7]),
        qi: bufToUrlBase64(parsedData[8])
    }
};

function parseSec1(bytes) {
    let parsedData = ASN1.parseGroup(bytes,
        { type: "30", children: [
            { type: "02", children: [] },
            { type: "04", children: [] },
            { type: "a0", children: [] },
            { type: "a1", children: [
                { type: "03", children: [] }
            ]}
        ]}
    );

    let d = parsedData[1];

    // This part is not packed like an ASN.1 value, so we must manually parse it.
    let xy = parsedData[3][0];
    xy = xy.slice(1);
    let xyLen = xy.byteLength / 2;
    let x = xy.slice(0, xyLen);
    let y = xy.slice(xyLen);

    return {
        d: bufToUrlBase64(d),
        x: bufToUrlBase64(x),
        y: bufToUrlBase64(y)
    }
};

function getCurveID(crv) {
    let curveID = crvMap[crv]?.crv_id;
    if(curveID === undefined) {
        throw new Error("Unsupported named curve: " + crv);
    }
    return curveID;
}

function getECDSAID(shaBits) {
    let ecdsaID = shaMap[shaBits]?.ecdsa_id;
    if(ecdsaID === undefined) {
        throw new Error("Unsupported number of SHA bits: " + shaBits);
    }
    return ecdsaID;
}

function getRSAID(shaBits) {
    let rsaID = shaMap[shaBits]?.rsa_id;
    if(rsaID === undefined) {
        throw new Error("Unsupported number of SHA bits: " + shaBits);
    }
    return rsaID;
}

function shaDigest(buf, shaBits) {
    let alg = shaMap[shaBits]?.alg;
    if(alg === undefined) {
        throw new Error("Unsupported number of SHA bits: " + shaBits);
    }
    return crypto.createHash(alg).update(buf).digest();
};

function shaSign(buf, shaBits, key, kty) {
    let alg = shaMap[shaBits]?.alg;
    if(alg === undefined) {
        throw new Error("Unsupported number of SHA bits: " + shaBits);
    }

    let type;
    if("EC" === kty) {
        type = "sec1";
    }
    else if("RSA" === kty) {
        type = "pkcs1";
    }
    else {
        throw new Error("Unsupported key type: " + kty);
    }

    return crypto.createSign(alg).update(buf).sign({
        key: key,
        format: "der",
        type: type
    });
};

function base64ToHex(b64) {
    return Buffer.from(b64, "base64").toString("hex");
};

function base64ToUrlBase64(b64) {
    return b64
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");
};

function bufToBase64(buf) {
    return buf.toString("base64");
}

function bufToHex(buf) {
    return buf.toString("hex");
}

function bufToUrlBase64(buf) {
    return base64ToUrlBase64(bufToBase64(buf));
};

function hexToBuf(hex) {
    return Buffer.from(hex, "hex");
}

function strToBuf(str) {
    // default is "utf8"
    return Buffer.from(str);
};

function strToHex(str) {
    return Buffer.from(str).toString("hex");
};

module.exports.generatePrivateKey = generatePrivateKey;
module.exports.convertPrivateKey = convertPrivateKey;
module.exports.createCSR = createCSR;
module.exports.createJWS = createJWS;
module.exports.shaDigest = shaDigest;
module.exports.shaSign = shaSign;