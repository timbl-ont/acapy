# X.509 Certificates for Wallet Keys

ACA-Py can attach an X.509 certificate chain to a P-256 key in the wallet. You can then
put the chain in the `x5c` header of JWTs and SD-JWTs that the key signs. Verifiers that
trust X.509 (for example, SD-JWT VC verifiers that use `x5c` for issuer key resolution)
can then validate the issuer key without a DID.

The wallet signs CSRs and self-signed certificates itself, so the private key never
leaves the wallet. ACA-Py does not need a DID for this flow.

## Limitations

- Only P-256 keys (`ES256`) are supported.
- When you import a chain, ACA-Py checks that the leaf certificate holds the key, has
  not expired, and allows digital signatures. It also checks that each certificate is
  issued by the next one. It does not check the chain against a trust anchor.
- ACA-Py adds `x5c` when signing. It doesn't use `x5c` when verifying JWTs or SD-JWTs.
- Each key stores one certificate chain. A new self-signed certificate or imported chain
  replaces the existing one.

## Workflow

### 1. Create a P-256 key

`POST /wallet/keys`

```json
{
  "alg": "p256",
  "kid": "https://issuer.example.com#key-1"
}
```

The response contains the key's `multikey` (for example `zDnae...`). The following
endpoints use this value in their paths.

### 2a. Create a certificate signing request (CSR)

`POST /wallet/keys/{multikey}/csr`

```json
{
  "subject": "CN=Example Issuer,O=Example Org,C=CA",
  "dns_names": ["issuer.example.com"],
  "uris": ["https://issuer.example.com"]
}
```

The response contains the PEM encoded PKCS #10 request in `csr`. Submit it to your
certificate authority. Specify a `subject`, at least one subject alternative name
(`dns_names`, `uris`, `emails`), or both. The CSR requests the `digitalSignature` key
usage.

### 2b. Or create a self-signed certificate

`POST /wallet/keys/{multikey}/self-signed-certificate`

```json
{
  "subject": "CN=Example Issuer,O=Example Org,C=CA",
  "uris": ["https://issuer.example.com"],
  "validity_days": 365
}
```

ACA-Py stores the certificate for the key right away. Use this option for development, or
when verifiers are configured to trust the certificate directly.

### 3. Import the issued certificate chain

`PUT /wallet/keys/{multikey}/certificate`

```json
{
  "certificate_chain": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"
}
```

List the PEM certificates leaf first, followed by any intermediates. You can leave out
the trust anchor (root), as RFC 7515 recommends. `GET /wallet/keys/{multikey}/certificate`
returns the stored chain as PEM and in `x5c` form.

### 4. Sign with the certificate chain

To add the stored chain as the `x5c` header, set `include_x5c` to `true` on
`/wallet/jwt/sign` or `/wallet/sd-jwt/sign`. Set `verificationMethod` to the key's `kid`:

```json
{
  "verificationMethod": "https://issuer.example.com#key-1",
  "headers": {"typ": "dc+sd-jwt"},
  "payload": {
    "iss": "https://issuer.example.com",
    "vct": "https://credentials.example.com/identity_credential",
    "given_name": "John"
  },
  "non_sd_list": ["vct"],
  "include_x5c": true
}
```

If no chain is stored for the key, the request fails. The `kid` header is still set.
