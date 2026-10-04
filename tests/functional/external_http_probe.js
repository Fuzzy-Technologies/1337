// SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
// SPDX-License-Identifier: Apache-2.0

"use strict";

const http = require("node:http");
const MAX_HTTP_BODY_BYTES = 65536;
const [path, port_text, budget_text] = process.argv.slice(1);
const port = Number(port_text);
const budget_ms = Number(budget_text);

if (
    process.argv.length !== 4 || typeof path !== "string" || !path.startsWith("/") ||
    path.startsWith("//") || /[\r\n]/.test(path) ||
    !Number.isInteger(port) || port < 1 || port > 65535 ||
    !Number.isInteger(budget_ms) || budget_ms < 1 || budget_ms > 5000
) {
    throw new Error("HTTP probe requires a loopback port, local path, and bounded deadline");
}

let completed = false;
let response = null;
let body_bytes = 0;
const chunks = [];
const request = http.request({hostname: "127.0.0.1", port, path, method: "GET", agent: false});

/** Preserve the received response and destroy every owned HTTP resource. */
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
        headers,
        body: Buffer.concat(chunks, body_bytes).toString("utf8"),
        error,
    }));
    request.destroy();

    if (response !== null) {
        response.destroy();
    }
}

const deadline = setTimeout(() => {
    const error = "HTTP probe exceeded its container wall-clock budget";
    process.exitCode = 124;
    Finish(error);
    console.error(error);
}, budget_ms);

request.on("response", incoming => {
    response = incoming;
    incoming.on("data", chunk => {
        if (completed) {
            return;
        }

        const remaining = MAX_HTTP_BODY_BYTES + 1 - body_bytes;
        const preserved = chunk.subarray(0, remaining);
        chunks.push(preserved);
        body_bytes += preserved.length;

        if (body_bytes > MAX_HTTP_BODY_BYTES) {
            Finish("HTTP response exceeded the bounded body budget");
        }
    });
    incoming.on("end", () => Finish(""));
    incoming.on("error", error => Finish(`${error.name}: ${error.message}`));
});
request.on("error", error => Finish(`${error.name}: ${error.message}`));
request.end();
