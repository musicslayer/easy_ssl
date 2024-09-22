const REQUEST = require("./request.js");
const X509 = require("./x509.js");

const RETRY_INTERVAL = 1000; // ms
const MAX_POLL_ATTEMPTS = 8;

class ACME {
    directoryUrl
    _newAccountUrl
    _newNonceUrl
    _newOrderUrl

    // The types of challenges we support, sorted for efficiency as follows:
    // * http-01 is the fasest
    // * dns-01 is the slowest (due to DNS propagation), but is required for private networks and wildcards
    challengeTypes = ["http-01", "dns-01"];

    // The types of challenges we support and are actually able to be handled by a challenge plugin provided during execution.
    _challengeTypes = [];

    // A mapping of extra text used during challenges.
    challengeText = {
        "http-01": "/.well-known/acme-challenge", // http-01: GET https://example.org/.well-known/acme-challenge/{{token}} => {{keyAuth}}
        "dns-01": "_acme-challenge" // dns-01: TXT _acme-challenge.example.org. => "{{urlSafeBase64(sha(keyAuth))}}"
    };

    async init(directoryUrl) {
        this.directoryUrl = directoryUrl;

        // Find the urls for all of the required operations.
        let directoryResponse = await REQUEST.request({
            headers: {
                "Accept": "application/json",
                "User-Agent": "fake_user_agent"
            },
            method: "GET",
            url: directoryUrl,
        });
        let directoryUrls = JSON.parse(directoryResponse.body);
        
        this._newAccountUrl = directoryUrls.newAccount;
        this._newNonceUrl = directoryUrls.newNonce;
        this._newOrderUrl = directoryUrls.newOrder;
    };

    async createAccount(accountKey) {
        // Clone but remove d and kid
        let key = (({ d, kid, ...o }) => o)(accountKey)
    
        let newAccountResponse = await jwsRequest(this._newNonceUrl, {
            accountKey: accountKey,
            url: this._newAccountUrl,
            protected: { jwk: key },
            payload: strToBuf(JSON.stringify({
                termsOfServiceAgreed: true,
                onlyReturnExisting: false,
            }))
        });
    
        // The account id url is the "kid" of the new account.
        let kid = newAccountResponse.headers.location;
    
        return kid;
    }

    async createCertificate(certificateOptions) {
        // Initialize all of the challenge plugins that could potentially be used.
        await this._initializeChallengePlugins(certificateOptions);

        // Create an order to request the certificate.
        let order = await this._orderCertificate(certificateOptions);

        // Request a claim for each authorization on the order.
        // Each claim is an array of challenges. Satisfying any one of them will satisfy the authorization.
        let claims = await this._requestChallenges(order, certificateOptions);

        // For each claim, select a challenge that is either already satisfied, or would be the quickest to satisfy.
        await this._selectChallenges(claims, certificateOptions);

        // For each selected challenge, compute information used by the challenge plugins.
        await this._computeChallenges(claims, certificateOptions);

        // Use the challenge plugins to set information that will later be verified.
        await this._setChallenges(claims, certificateOptions);

        // Post the challenges to Let's Encrypt so they can verify that the information from the previous step was successfully set.
        await this._postChallenges(claims, certificateOptions);
    
        // Once all authorizations have been verified as complete, we can finalize the order.
        let voucher = await this._finalizeOrder(order, certificateOptions);

        // Use the voucher to get the certificate.
        let certificate = await this._redeemCertificate(voucher, certificateOptions);
        
        return certificate;
    }

    async _initializeChallengePlugins(certificateOptions) {
        // Initialize challenge plugins and store their types only if they are supported.
        for(let challengeType of this.challengeTypes) {
            let challengePlugin = certificateOptions.challengePlugins[challengeType];
            if(challengePlugin !== undefined) {
                this._challengeTypes.push(challengeType);
                await challengePlugin.init({ type: "*", request: REQUEST.rootRequest });
            }
        }
    }

    async _orderCertificate(certificateOptions) {
        let certificateRequest = {
            // Keep any wildcards in the domains.
            identifiers: certificateOptions.domains.map((domain) => ({ type: "dns", value: domain }))
        };
        let payload = JSON.stringify(certificateRequest);
        
        let newOrderResponse = await jwsRequest(this._newNonceUrl, {
            accountKey: certificateOptions.accountKey,
            url: this._newOrderUrl,
            protected: { kid: certificateOptions.kid },
            payload: binToBuf(payload)
        });
        let order = JSON.parse(newOrderResponse.body);
        order.orderUrl = newOrderResponse.headers.location;

        return order;
    }

    async _requestChallenges(order, certificateOptions) {
        let claims = [];
        
        for(let authUrl of order.authorizations) {
            let authResponse = await jwsRequest(this._newNonceUrl, {
                accountKey: certificateOptions.accountKey,
                url: authUrl,
                protected: { kid: certificateOptions.kid },
                payload: binToBuf("")
            });
            authResponse.body = JSON.parse(authResponse.body);

            // The hostname will not include any wildcards, so if one is present then attach it to altname.
            let hostname = authResponse.body.identifier.value;
            let altname = authResponse.body.wildcard ? "*." + hostname : hostname;

            claims.push({
                hostname: hostname,
                altname: altname,
                authUrl: authUrl,
                challenges: authResponse.body.challenges
            });
        }

        return claims;
    };

    async _selectChallenges(claims, certificateOptions) {
        // For each claim, choose one challenge that we will use to satisfy the authorization.
        for(let claim of claims) {
            // If one of the claim's challenges is already valid, just use that one and continue on.
            // This may happen if a challenge from a previous execution is reused.
            let validChallenge = claim.challenges.find((challenge) => "valid" === challenge.status);
            if(validChallenge !== undefined) {
                claim.selectedChallenge = validChallenge;
                continue;
            }

            // Select the first challenge offered based on our type preference.
            // Our assumption is that all challenges will either pass or fail together, so let's pick the fastest one possible.
            let selectedChallenge;
            for(let challengeType of this._challengeTypes) {
                selectedChallenge = claim.challenges.find((challenge) => challengeType === challenge.type);
                if(selectedChallenge !== undefined) {
                    break;
                }
            }

            if(selectedChallenge === undefined) {
                // Bail with a descriptive message if no usable challenge could be selected
                // For example, wildcards require dns-01 and, if we don't have that, we have to bail
                let enabled = certificateOptions._challengeTypes.join(", ") || "none";
                let suitable = claim.challenges.map((challenge) => challenge.type).join(", ") || "none";
                throw new Error(
                    "None of the challenge types that you've enabled ( " + enabled + " ) are suitable for validating the domain you've selected (" + claim.altname + ").\n" +
                    "You must enable one of ( " + suitable + " )."
                );
            }

            claim.selectedChallenge = selectedChallenge;
        }
    }

    async _computeChallenges(claims, certificateOptions) {
        for(let claim of claims) {
            // Skip claims where the selected challenge is already valid.
            if("valid" === claim.selectedChallenge.status) {
                continue;
            }

            let computedChallenge = {};
            computedChallenge.thumbprint = certificateOptions.accountKey.thumb;
            computedChallenge.keyAuthorization = claim.selectedChallenge.token + "." + certificateOptions.accountKey.thumb;
        
            if("http-01" === claim.selectedChallenge.type) {
                // Conflicts with ACME challenge id url is already in use, so we call this challengeUrl instead.
                // Note that "hostname" is an alias of "auth.indentifier.value".
                computedChallenge.challengeUrl = "http://" + claim.hostname + this.challengeText["http-01"] + "/" + claim.selectedChallenge.token;
            }
            else if("dns-01" === claim.selectedChallenge.type) {
                // Always calculate dnsAuthorization because we may need to present to the user for confirmation / instruction _as part of_ the decision making process
                let hash = X509.shaDigest(strToBuf(computedChallenge.keyAuthorization), certificateOptions.accountKey.shaBits);
                let hash64 = bufToUrlBase64(hash);

                computedChallenge.dnsHost = this.challengeText["dns-01"] + "." + claim.hostname;
                computedChallenge.dnsAuthorization = hash64;
                computedChallenge.keyAuthorizationDigest = hash64;
            
                // Use the challenge plugin to query all of the zones the user has access to and find which one the hostname belongs to.
                let zones = await certificateOptions.challengePlugins["dns-01"].zones();
                let zone = pluckZone(zones, claim.hostname);
                if(zone === undefined) {
                    throw new Error(
                        "A DNS Zone could not be found for the hostname.\n" +
                        "Hostname: " + claim.hostname + "\n" +
                        "DNS Zones: " + zones.join(", ") || "none"
                    );
                }

                computedChallenge.dnsZone = zone;
                computedChallenge.dnsPrefix = computedChallenge.dnsHost
                    .replace(newZoneRegExp(zone), "") // Remove the zone
                    .replace(/\.$/, ""); // Remove the trailing period
            }

            claim.computedChallenge = computedChallenge;
        }
    };

    async _setChallenges(claims, certificateOptions) {
        // Computed challenges that are actually set during this execution will need to be removed in case an error occurs.
        // If there is no error, then they should not be removed until later.
        let cleanupFcns = [];

        let USE_DNS = false;
        let DNS_DELAY = certificateOptions.challengePlugins["dns-01"]?.propagationDelay ?? 0;

        try {
            for(let claim of claims) {
                // Skip claims where the selected challenge is already valid.
                if("valid" === claim.selectedChallenge.status) {
                    continue;
                }

                if("dns-01" === claim.selectedChallenge.type) {
                    USE_DNS = true;
                }

                let challengePlugin = certificateOptions.challengePlugins[claim.selectedChallenge.type];

                // Use a closure to create the cleanup function.
                cleanupFcns.push(((_type, _computedChallenge) => { return () => { certificateOptions.challengePlugins[_type].remove({ challenge: _computedChallenge }) } })(claim.selectedChallenge.type, claim.computedChallenge));

                await challengePlugin.set({ challenge: claim.computedChallenge });
            }
        }
        catch(err) {
            // Clean up before rethrowing the error.
            for(let cleanupFcn of cleanupFcns) {
                try {
                    await cleanupFcn();
                }
                catch(e) {
                    warn(e);
                }
            }
            
            throw err;
        }

        // If DNS was used, give nameservers a moment to propagate.
        if(USE_DNS) {
            await wait(DNS_DELAY);
        }
    };

    // https://tools.ietf.org/html/draft-ietf-acme-acme-10#section-7.5.1
    async _postChallenges(claims, certificateOptions) {
        for(let claim of claims) {
            // Skip claims where the selected challenge is already valid.
            if("valid" === claim.selectedChallenge.status) {
                continue;
            }

            let err;
            let postResponse;
            try {
                let count = 0;
                postResponse = await jwsRequest(this._newNonceUrl, {
                    accountKey: certificateOptions.accountKey,
                    url: claim.selectedChallenge.url,
                    protected: { kid: certificateOptions.kid },
                    payload: strToBuf(JSON.stringify({}))
                });
                postResponse.body = JSON.parse(postResponse.body);

                while(true) {
                    // https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.1.3
                    // Possible values are: "pending", "ready", "processing", "valid", "invalid"
                    if(count >= MAX_POLL_ATTEMPTS || !("pending" === postResponse.body.status || "processing" === postResponse.body.status)) {
                        // Break if we reach a terminal status or have polled too many times.
                        break;
                    }
                    else {
                        // Try again
                        count += 1;
                        await wait(RETRY_INTERVAL);

                        postResponse = await jwsRequest(this._newNonceUrl, {
                            accountKey: certificateOptions.accountKey,
                            url: claim.selectedChallenge.url,
                            protected: { kid: certificateOptions.kid },
                            payload: binToBuf("")
                        });
                        postResponse.body = JSON.parse(postResponse.body);
                    }
                }
            }
            catch(e) {
                err = e;
            }

            // Clean up no matter how we got here.
            try {
                await certificateOptions.challengePlugins[claim.selectedChallenge.type].remove({ challenge: claim.computedChallenge });
            }
            catch(e) {
                warn(e);
            }

            if("valid" !== postResponse?.body?.status) {
                if(err !== undefined) {
                    throw err;
                }
                else {
                    throw new Error(
                        "Did not post challenge.\n" +
                        "Status: " + postResponse.body.status + "\n" +
                        "Domain: " + claim.altname + "\n\n" +
                        JSON.stringify(postResponse.body, null, 2)
                    )
                }
            }
        }
    };

    async _finalizeOrder(order, certificateOptions) {
        let csr = X509.createCSR(certificateOptions.serverKey, certificateOptions.domains);
        let csr64 = hexToUrlBase64(csr);
        let payload = JSON.stringify({ csr: csr64 });

        let finalizeResponse = await jwsRequest(this._newNonceUrl, {
            accountKey: certificateOptions.accountKey,
            url: order.finalize,
            protected: { kid: certificateOptions.kid },
            payload: strToBuf(payload)
        })
        finalizeResponse.body = JSON.parse(finalizeResponse.body);

        let count = 0;

        while(true) {
            // https://tools.ietf.org/html/draft-ietf-acme-acme-12#section-7.1.3
            // Possible values are: "pending", "ready", "processing", "valid", "invalid"
            if(count >= MAX_POLL_ATTEMPTS || !("pending" === finalizeResponse.body.status || "processing" === finalizeResponse.body.status)) {
                // Break if we reach a terminal status or have polled too many times.
                break;
            }
            else {
                // Try again
                count += 1;
                await wait(RETRY_INTERVAL);

                finalizeResponse = await jwsRequest(this._newNonceUrl, {
                    accountKey: certificateOptions.accountKey,
                    url: order.orderUrl,
                    protected: { kid: certificateOptions.kid },
                    payload: binToBuf("")
                })
                finalizeResponse.body = JSON.parse(finalizeResponse.body);
            }
        }

        if("valid" === finalizeResponse?.body?.status) {
            let voucher = finalizeResponse.body;
            return voucher;
        }
        else {
            throw new Error(
                "Did not finalize order.\n" +
                "Status: " + finalizeResponse.body.status + "\n" +
                "Domains: " + certificateOptions.domains.join(", ") + "\n\n" +
                JSON.stringify(finalizeResponse.body, null, 2)
            )
        }
    };

    async _redeemCertificate(voucher, certificateOptions) {
        let certificateResponse = await jwsRequest(this._newNonceUrl, {
            accountKey: certificateOptions.accountKey,
            url: voucher.certificate,
            protected: { kid: certificateOptions.kid },
            payload: binToBuf("")
        })

        let serverKeyPEM = X509.convertPrivateKey(certificateOptions.serverKey);

        return {
            expires: voucher.expires,
            identifiers: voucher.identifiers,
            certificatePEM: certificateResponse.body,
            privateKeyPEM: serverKeyPEM
        };
    }
}

module.exports = ACME;

/*
    Util
*/

async function wait(ms) {
    return new Promise((resolve) => {
        setTimeout(resolve, ms);
    });
};

function warn(err) {
    // Print in yellow text. This sets the message apart from blue log text or red error text.
    console.log("\x1b[33m%s\n%s", "Warning:", err);
}

// Handle nonce, signing, and request.
async function jwsRequest(nonceURL, jwsOptions) {
    let nonceResponse = await REQUEST.request({
        method: "HEAD",
        url: nonceURL
    });
    let nonce = nonceResponse.headers["replay-nonce"];

    jwsOptions.protected.nonce = nonce;
    jwsOptions.protected.url = jwsOptions.url;

    let typ = "RSA" === jwsOptions.accountKey.kty ? "RS" : "ES";
    jwsOptions.protected.alg = typ + jwsOptions.accountKey.shaBits;

    let protected64 = strToUrlBase64(JSON.stringify(jwsOptions.protected));
    let payload64 = bufToUrlBase64(jwsOptions.payload);
    let msg = protected64 + "." + payload64;

    let signature = X509.createJWS(jwsOptions.accountKey, msg);
    let signature64 = bufToUrlBase64(signature);

    let jws = {
        protected: protected64,
        payload: payload64,
        signature: signature64
    };
    
    let body = JSON.stringify(jws);

    let jwsResponse = await REQUEST.request({
        headers: {
            "Accept": "application/json",
            "Content-Length": body.length,
            "Content-Type": "application/jose+json"
        },
        method: "POST",
        url: jwsOptions.url,
        body: body
    });

    return jwsResponse;
};

/*
    DNS
*/

function newZoneRegExp(zonename) {
    // (^|\.)example\.com$
    // which matches:
    //  foo.example.com
    //  example.com
    // but not:
    //  fooexample.com
    return new RegExp("(^|\\.)" + zonename.replace(/\./g, "\\.") + "$");
}

function pluckZone(zones, dnsHost) {
    // Find the zone that dnsHost belongs to.
    return zones
        .filter((zonename) => newZoneRegExp(zonename).test(dnsHost))
        .sort((a, b) => b.length - a.length)[0] // Only return the longest match
}

/*
    Helpers
*/

function base64ToUrlBase64(b64) {
    return b64
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");
};

function binToBuf(bin) {
    return Buffer.from(bin, "binary");
};

function bufToBase64(buf) {
    return buf.toString("base64");
}

function bufToUrlBase64(buf) {
    return base64ToUrlBase64(bufToBase64(buf));
};

function hexToBuf(hex) {
    return Buffer.from(hex, "hex");
};

function hexToUrlBase64(hex) {
    return base64ToUrlBase64(bufToBase64(hexToBuf(hex)));
};

function strToBuf(str) {
    // default is "utf8"
    return Buffer.from(str);
};

function strToUrlBase64(str) {
    return base64ToUrlBase64(bufToBase64(strToBuf(str)));
};