"use strict";

const crypto = require("crypto");
const {URL} = require('url');

let HmacSigningUtil = {};

function parseHeaders(signatureHeaders) {
    let headers = "";
    for (var [key, val] of signatureHeaders) {
        if (headers !== "") {
            headers += " ";
        }
        headers += key;
    }
    return headers;
}

function getSignatureString(signatureHeaders) {

    let sigString = "";
    for (var [key, val] of signatureHeaders) {
        if (sigString !== "") {
            sigString += "\n";
        }
        if (key.toLowerCase() === "request-line") {
            sigString += val;
        } else {
            sigString += key.toLowerCase() + ": " + val;
        }
    }
    return sigString;
}

let getHmacSignature = function (signatureString, secret) {
    return crypto.createHmac("SHA256", secret).update(signatureString).digest("base64");
}

let getHmacDigest = function (data) {
    return crypto.createHash("SHA256").update(data, "binary").digest("base64");
}

function verifyParams(params) {
    if (!params.username || !params.username.length) {
        throw new Error("username is required");
    }
    // Secret
    if (!params.secret || !params.secret.length) {
        throw new Error("secret is required");
    }
    // URL
    if (!params.url || !params.url.length) {
        throw new Error("url is required");
    }
    // Method
    if (!params.method || !params.method.length) {
        throw new Error("method is required");
    }
    // host
    if (!params.host || !params.host.length) {
        throw new Error("host is required");
    }
    // Method
    let requestMethod = params.method.toUpperCase();
    if (requestMethod !== "GET" && requestMethod !== "POST" && requestMethod !== "UPDATE" && requestMethod !== "DELETE") {
        throw new Error("HTTP method is invalid");
    }
    if (requestMethod === "POST" || requestMethod === "UPDATE") {
        if (!params.data || !params.data.length) {
            throw new Error("Data is required when method is POST or UPDATE");
        }

        if (!params.contentType || !params.contentType.length) {
            throw new Error("contentType is required when method is POST or UPDATE");
        }
    }
}

HmacSigningUtil.getSignatureBaseString = (params) => {

    //Verify Parameters
    verifyParams(params);

    // Default Value
    let httpVersion = (params.httpVersion) ? params.httpVersion : "HTTP/1.1";
    // Set the signature hash algorithm
    const algorithm = "hmac-sha256";

    // Determine request method
    let bodyDigest;
    let contentLength;
    let signatureHeaders = new Map();
    let requestMethod = params.method.toUpperCase();

    if (requestMethod === "POST" || requestMethod === "UPDATE") {
        // MD5 digest of the content
        bodyDigest = getHmacDigest(params.data);

        // Set the content-length header
        contentLength = params.data.length;

        // Add headers for the signature hash
        signatureHeaders.set("content-type", params.contentType);
        signatureHeaders.set("content-length", contentLength);
    }

    // Build the request-line header
    let targetPath = new URL(params.url).pathname;
    let requestLine = `${requestMethod} ${targetPath} ${httpVersion}`;
    
    // Add to headers for the signature hash
    signatureHeaders.set("request-line", requestLine);

    // Set the date header
    let dateHeader = params.date;
    signatureHeaders.set("date", dateHeader);

    // Build the signature string
    let signatureString = getSignatureString(signatureHeaders);

    // Hash the signature string using the specified algorithm
    let signatureHash = getHmacSignature(signatureString, params.secret);
  
    // Get the list of headers
    let headers = parseHeaders(signatureHeaders);

    // Format the authorization header
    let authHeader = `hmac username="${params.username}",algorithm="${algorithm}",headers="${headers}",signature="${signatureHash}"`;

    // Set the default request headers
    let requestHeaders;
    if (requestMethod === "GET" || requestMethod === "DELETE") {
        requestHeaders = {
            "Authorization": authHeader,
            "Host": params.host,
            "Date": dateHeader
        }
    } else {
        requestHeaders = {
            "Authorization": authHeader,
            "Host": params.host,
            "Date": dateHeader,
            "Digest": `SHA-256=${bodyDigest}`,
            "Content-Type": params.contentType,
            "Content-Length": contentLength,
        }
    }
    return requestHeaders;
}

module.exports = HmacSigningUtil;