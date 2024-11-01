# Easy SSL
Easily generate SSL certificates signed by Let's Encrypt.

This code is an independent rewriting of the Root [acme.js](https://github.com/therootcompany/acme.js) repository. The goal was to streamline the functionality and make the code easier to understand.

This code has no external dependencies, although it operates under a "bring your own challenge plugin" model. For example, if the domain you wish to create a certificate for is hosted by Cloudflare, you will need to provide a challenge plugin that can interact with the Cloudflare API. You may write your own, but it is recommended that you use the plugins written by Root. See [this page](https://github.com/therootcompany/acme.js?tab=readme-ov-file#challenge-callbacks) for more information.

## Installation Instructions
Package available on [NPM](https://www.npmjs.com/package/@musicslayer/easy_ssl).

`> npm install @musicslayer/easy_ssl`

Any Root challenge plugins that you use must also be installed. For example, if your domain is hosted on Cloudflare:

`> npm install acme-dns-01-cloudflare`

## Example Usage
The three provided example apps demonstrate the basic workflow.

### Account Key Creation
app_createAccountKeyAndKID.js will create a new private key and use that to create a Let's Encrypt account. The account private key and the KID (key ID) of the new account are written to a file to be accessed later.

> [!IMPORTANT]
> This only needs to be done once. The same account can be reused to create more certificates.

### Server Key Creation
app_createServerKey.js will create a new private key to represent the server that you are getting the certificate for. This private key is different than the private key for the account that we created before. The server private key is written to a file to be accessed later.

> [!IMPORTANT]
> This step only needs to be done once per server that you are getting certificates for. The same server key can be reused to create more certificates.

### Certificate Creation
app_createCertificate.js will create an SSL certificate signed by Let's Encrypt. The account private key, account KID, and the server private key from before are used.

An array of domains that we wish to certify is provided. Note that we will get one certificate that covers the set of domains, **NOT** an individual certificate per domain.

In this example, the domains are hosted by Cloudflare and thus we use the Root Cloudflare challenge plugin. We must provide a Cloudflare API key with "Zone:Zone:Read" and "Zone:DNS:Edit" permissions.

## API
### createPrivateKey(keyOptions)

Creates a public/private key pair. Only the private key is returned.

Arguments:
- **keyOptions** is an object with the following fields:
	- kty =  "EC"
	- shaBits = 224, 256, 384, or 512
	- crv =  "P-224", "P-256", "P-384", or "P-521" (P-521 is NOT a typo! It really is called P-521 and not P-512.)
   
	OR

	- kty =  "RSA"
	- shaBits = 224, 256, 384, or 512
	- modulusLength (e.g. 2048)
	- publicExponent (eg 0x10001)

kty is the keypair type, either "EC" (Elliptic Curve) or "RSA" (Rivest–Shamir–Adleman).

For both EC and RSA, shaBits is the number of bits in the SHA digest.

For EC, crv is the name of the elliptic curve used by the EC algorithm.

For RSA, modulusLength and publicExponent are both numbers used by the RSA algorithm.

> [!IMPORTANT]
> Not all combinations are supported by Let's Encrypt. According to [here](https://letsencrypt.org/docs/integration-guide/#supported-key-algorithms), Let’s Encrypt only supports modulusLength = 2048, 3072, or 4096 and crv = "P-256" or "P-384". Also for EC, shaBits and crv must correspond to each other, so for example if you choose shaBits = 256, you must use crv = "P-256".

### createAccount(accountKey, directoryUrl)

Creates a Let's Encrypt account.

Arguments:
- **accountKey** is a private key generated from "createPrivateKey".
- **directoryUrl** is a URL where the rest of the Let's Encrypt API URLs can be queried. Currently, the possible values for this are:
	- Production: "https://acme-v02.api.letsencrypt.org/directory"
	- Staging: "https://acme-staging-v02.api.letsencrypt.org/directory"

### createCertificate(accountKey, serverKey, kid, directoryUrl, domains, challengePlugins)

Creates an SSL certificate signed by Let's Encrypt.

Arguments:
- **accountKey** is a private key generated from "createPrivateKey".
- **serverKey** is a private key generated from "createPrivateKey". This should be different from the account key.
- **kid** is the key ID associated with the account.
- **directoryUrl** is a URL where the rest of the Let's Encrypt API URLs can be queried. Currently, the possible values for this are:
	- Production: "https://acme-v02.api.letsencrypt.org/directory"
	- Staging: "https://acme-staging-v02.api.letsencrypt.org/directory"
- **domains** is an array of domains that you wish to create the certificate for. Entries with wildcards such as "*.shop.yourdomain.com" are permitted.
- **challengePlugins** is an object mapping different challenge types to a plugin that will be responsible for handling them (see section below for more information). It is highly recommended that you use the Root challenge plugins, although you can also create your own.

## Challenge Plugins
The **challengePlugins** argument to "createCertificate" will look like this:
```
challengePlugins = {
	"dns-01": plugin_for_dns,
	"http-01": plugin_for_http
}
```

Where each type of challenge that we wish to handle is mapped to a challenge plugin that can handle it. In our examples, the Cloudflare plugin is a DNS plugin, so we map it with "dns-01". We omit the "http-01" entry since we do not provide a plugin to handle those types of challenges.

You must either omit an entry or map it to exactly one plugin i.e. you cannot provide an array of plugins. Also, the program itself will decide which plugins can be used, and which priority they will take if more than one are provided.

> [!IMPORTANT]
> This code only supports "dns-01" and "http-01". Although the Root code does mention "tls-alpn-01", in my rewriting I decided not to provide any support for it.

## Additional Tips
### Deprecation Warnings
When running the examples with the Root Cloudflare challenge plugin, you may see the following printed to the console:
```
(node:13104) [DEP0066] DeprecationWarning: OutgoingMessage.prototype._headers is deprecated
(Use `node --trace-deprecation ...` to show where the warning was created)
```
This is caused by code within the plugin itself and can be ignored.

### Domains
A typical use case is to create a single certificate that covers your domain and all possible subdomains. For example, "yourdomain.com", "shop.yourdomain.com", "support.shop.yourdomain.com", etc.

To achieve this, call "createCertificate" with domains set to:
```
domains = ["*.yourdomain.com", "yourdomain.com"]
```

The wildcard entry will cover all possible subdomains, but you must explicitly specify the base domain in order for that to be covered as well.
