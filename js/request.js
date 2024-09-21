const http = require("http");
const https = require("https");
const url = require("url");

async function rootRequest(requestOptions) {
	// This function wraps "request" and is passed into the Root challenge plugins.
	if(requestOptions === undefined) {
		requestOptions = {};
	}
	let newRequestOptions = Object.clone(requestOptions);

	if(newRequestOptions.headers === undefined) {
		newRequestOptions.headers = {};
	}

	if(newRequestOptions.headers["User-Agent"] === undefined) {
		newRequestOptions.headers["User-Agent"] = "fake_user_agent";
	}

	if(newRequestOptions.json) {
		newRequestOptions.headers.Accept = "application/json";
		if(true !== newRequestOptions.json) {
			newRequestOptions.body = JSON.stringify(newRequestOptions.json);
		}
		if(newRequestOptions.json.protected) {
			newRequestOptions.headers["Content-Type"] = "application/jose+json";
		}
	}

	if(newRequestOptions.method === undefined) {
		newRequestOptions.method = "GET";
		if(newRequestOptions.body !== undefined) {
			newRequestOptions.method = "POST";
		}
	}

	let response = await request(newRequestOptions);

	if(response.toJSON !== undefined) {
		response = response.toJSON();
	}

	return response;
}

async function request(requestOptions) {
	let response = await _request(requestOptions);

	if(response.statusCode < 200 || response.statusCode >= 300) {
		throw new Error("Web Request Error:\n\n" +
			"Request Options:\n" +
			JSON.stringify(requestOptions) + "\n\n" +
			"Response Body:\n" +
			response.body
		);
	}

	return response;
};

async function _request(requestOptions) {
	return new Promise((resolve) => {
		let protocol = new url.URL(requestOptions.url).protocol;
		let requester = protocol === "https:" ? https : http;

		let req = requester.request(requestOptions.url, requestOptions, (res) => {
			let data = "";

			res.on("data", (chunk) => {
				data += chunk;
			});

			res.on("end", () => {
				res.body = data;
				resolve(res);
			});
		});

		req.end(requestOptions.body);
	});
}

module.exports.rootRequest = rootRequest;
module.exports.request = request;