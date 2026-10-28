// SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
// SPDX-License-Identifier: Apache-2.0

"use strict";

const http = require("node:http");
const MAX_BODY_BYTES = 262144;
const DEADLINE_MS = 2250;
const chunks = [];
let received = 0;
let response = null;
let completed = false;
const request = http.request({
    hostname: "127.0.0.1", port: 3000, path: "/metrics", method: "GET", agent: false,
    headers: {"Accept-Encoding": "identity", "Connection": "close"},
});

/** Retain only this separately authorized diagnostic response and close owned resources. */
function Finish(error) {
    if (completed) {
        return;
    }

    completed = true;
    clearTimeout(deadline);
    const headers = [];

    if (response !== null) {
        for (let index = 0; index < response.rawHeaders.length; index += 2) {
            headers.push([response.rawHeaders[index], response.rawHeaders[index + 1]]);
        }
    }

    console.log(JSON.stringify({
        status: response === null ? null : response.statusCode,
        headers, body_base64: Buffer.concat(chunks, received).toString("base64"),
        body_bytes: received, error,
    }));
    request.destroy();

    if (response !== null) {
        response.destroy();
    }

    if (error) {
        process.exitCode = error === "deadline" ? 124 : 4;
    }
}

const deadline = setTimeout(() => Finish("deadline"), DEADLINE_MS);
request.on("response", incoming => {
    response = incoming;
    incoming.on("data", chunk => {
        if (completed) {
            return;
        }

        const preserved = chunk.subarray(0, MAX_BODY_BYTES + 1 - received);
        chunks.push(preserved);
        received += preserved.length;

        if (received > MAX_BODY_BYTES) {
            Finish("body-limit");
        }
    });
    incoming.on("end", () => Finish(""));
    incoming.on("error", () => Finish("response-error"));
});
request.on("error", () => Finish("request-error"));
request.end();
