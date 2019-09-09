'use strict';
const HmacSigningUtil = require('../lib/HmacSigningUtil');

const username = "foo";
const secret = "bar";
const url = "http://localhost:8000/resources"; //change localhost:8000 to kong url
const method = "POST";
const httpVersion = "HTTP/1.1"; // default "HTTP/1.1"

const postBody = {
    "name" : "test"
}
const contentType = "application/json";


const params = {
    username: username,
    secret: secret,
    url: url,
    method: method,
    httpVersion: httpVersion,
    host: "localhost.com",
    data: JSON.stringify(postBody),
    contentType: contentType
}

let headers = HmacSigningUtil.getSignatureBaseString(params);

console.log(headers);

let options = {
    url: url,
    method: method,
    headers: headers,
    json: postBody
}

console.log(options);