# Owned proxy and TLS fixtures

These first-party fixtures run only on ephemeral literal-loopback listeners.
Their independent oracle files describe expected target behavior. See
[`docs/PROXY_REGRESSION.md`](../../../docs/PROXY_REGRESSION.md) for the actual
Quick Scan, scope, evidence and lifecycle boundaries.

## Public synthetic certificate and key

`synthetic-self-signed-cert.pem` and `synthetic-public-test-key.pem` were generated
solely for the `owned-tls-untrusted-certificate.v1` regression. The private-key
encoding contains deliberately **public, non-secret test material**. It is not
a credential, is not used by any deployed service and must never be reused for
one. No existing user, host or service key was read or copied.

The self-signed RSA-2048 certificate has serial `0539`, IP SAN `127.0.0.1`,
SHA-256 signature, `CA:FALSE`, server-authentication usage, and a synthetic
`.invalid` common name. Its fixed validity interval is
2026-10-15 21:48:37 UTC through 2046-10-10 21:48:37 UTC. The contract test checks
the current time against that interval and fails explicitly outside it. It never
silently changes a trust-rejection test into an expiry test. Certificate/key
file hashes, DER fingerprint and exact generation tool version are pinned in
[`tls-certificate-oracle.v1.json`](tls-certificate-oracle.v1.json).

Generated locally using OpenSSL 3.0.13, without network access:

```bash
openssl req -x509 -newkey rsa:2048 -sha256 -noenc -days 7300 \
  -set_serial 1337 \
  -subj '/CN=synthetic-proxy-private-value.invalid/O=1337-Owned-Synthetic-Test-Only' \
  -addext 'subjectAltName=IP:127.0.0.1' \
  -addext 'basicConstraints=critical,CA:FALSE' \
  -addext 'keyUsage=critical,digitalSignature,keyEncipherment' \
  -addext 'extendedKeyUsage=serverAuth' \
  -keyout synthetic-public-test-key.pem -out synthetic-self-signed-cert.pem
```

Regeneration creates new random test key material and a new validity interval;
it requires a reviewed oracle/hash update. CI loads the committed fixtures with
the Python standard library and needs no OpenSSL executable or new dependency.
Generation-time independent checks examined the X.509 subject/issuer, serial,
validity, SAN, extensions and DER fingerprint, verified the self-signature, and
compared certificate/key public-key digests. The real server context also rejects
a mismatched key before starting its listener.

The independent client uses `ssl.create_default_context()` unchanged and must
raise `SSLCertVerificationError` with verification code `18` (self-signed). It
does not add the certificate to any trust store. The actual product retains its
existing fixed `tls` failure code, failed provider job and original acquisition;
it must create no successful HTTPS endpoint or vulnerability Finding. The owned
server independently records a certificate-rejection alert and zero completed
handshakes. The fixture has no HTTP handler. Neither client nor product receives
an insecure TLS context, CA injection, retry, environment override or bypass.

This profile proves rejection of this untrusted self-signed certificate only.
It does not establish successful trusted HTTPS, hostname-specific rejection,
expiry-specific rejection, revocation checking or a general TLS compliance
matrix. The IP SAN and validity assertions eliminate accidental fixture drift;
they do not make those untested product claims.
