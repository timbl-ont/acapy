
# Walkthrough - PKCS11-P256 Support

I have implemented support for the `PKCS11-P256` key type, enabling keys to be stored in an external HSM while ACA-Py retains only a reference (identifier). Signing operations are delegated to the HSM via a PKCS#11 plugin.

## Changes

### Configuration
- **Added `python-pkcs11` dependency** in `pyproject.toml`.
- **Added CLI arguments** in `acapy_agent/config/argparse.py`:
  - `--pkcs11-lib`: Path to the PKCS#11 shared library.
  - `--pkcs11-pin`: User PIN for the token.
  - `--pkcs11-token`: Token label.
  - `--pkcs11-slot`: Slot ID (preferred) or index.
  - `--pkcs11-iaca-write-back`: Persist generated IACA certs back to HSM.

### Key Type
- **Registered `PKCS11_P256`** in `acapy_agent/wallet/key_type.py`.

### Wallet Implementation
- **Created `acapy_agent/wallet/pkcs11.py`**:
  - `PKCS11Signer` class handling session management and signing.
  - Retrieves public keys from the HSM.
  - Signs messages (hashing with SHA256 before signing) using the HSM.
- **Modified `acapy_agent/wallet/askar.py`**:
  - `AskarWallet` now initializes a `PKCS11Signer` if configured.
  - `create_key` and `create_local_did` intercept `PKCS11_P256` requests. They treat the `seed` argument as the method to find the key (e.g., label) and fetch the public key from the HSM.
  - `sign_message` detects if a key is a PKCS11 key (via metadata `pkcs11_label`) and delegates signing to `PKCS11Signer`.
  - **Implemented `create_key`**:
    - Automatically generates `PKCS11_P256` keys in the HSM if they do not exist.
    - Uses UUID as label if not provided.

### Docker Integration
- **Updated `docker/Dockerfile`**:
  - Installed BouncyHsm PKCS#11 driver from a configurable tag (`BOUNCYHSM_VERSION`, default `v2.0.1`).
  - Configured default environment variables for BouncyHsm (`ACAPY_PKCS11_*`).

## Verification Results

### Automated Tests
- Created `acapy_agent/wallet/tests/test_pkcs11.py` to verify `PKCS11Signer`.
- ran `pytest` and confirmed 4 tests passed.

```
4 passed in 0.79s
```

### Manual Verification
- Since we do not have a physical HSM locally, verification relied on mocking.

### Running Unit Tests

To run the unit tests for the PKCS#11 integration (which use mocks and do not require the HSM):

```bash
podman run --rm -v $(pwd):/home/aries \
  --entrypoint "" \
  acapy-bouncyhsm \
  pytest acapy_agent/wallet/tests/test_pkcs11.py
```

### BouncyHsm Verification (Podman)

I have created a script `scripts/test_bouncy_hsm.py` to verify the integration in a containerized environment.

To run it:

1.  **Build the Image**:
    ```bash
    podman build -f docker/Dockerfile -t acapy-bouncyhsm \
      --build-arg BOUNCYHSM_VERSION=v2.0.1 .
    ```

    The PKCS#11 module version should match the running BouncyHsm server version.

2.  **Run the Verification Script**:
  Ensure your BouncyHsm server is reachable from inside the container.
  Set `BOUNCY_HSM_CFG_STRING` to the HSM endpoint used by the PKCS#11 driver.
  For Podman on macOS, `host.containers.internal` is usually the host bridge address.
    
    ```bash
    podman run --rm -v $(pwd)/scripts:/scripts \
      -e BOUNCY_HSM_CFG_STRING="Server=host.containers.internal;Port=8765;" \
      -e ACAPY_PKCS11_SLOT=2 \
      --entrypoint "" \
      --network host \
      acapy-bouncyhsm \
      python3 /scripts/test_bouncy_hsm.py
    ```

    If you see `Initialisation error (not initialized)`, the PKCS#11 module was loaded
    but could not initialize against the configured BouncyHsm endpoint.

    *Note: We use `--entrypoint ""` to override the default `aca-py` entrypoint so we can run python3 directly.*

    This script will:
    *   Connect to BouncyHsm.
    *   Provision a P-256 key (`test-key-p256`) if missing.
    *   Sign a test message using the `acapy_agent` PKCS#11 integration.
    *   Verify the signature locally.

    Note on session mode: this integration opens the token session with
    read-write mode (`rw=True`). For BouncyHsm, direct `python-pkcs11`
    experiments should also open the session in RW mode when creating keys
    or when the server expects mutable session semantics:

    ```python
    import pkcs11
    lib = pkcs11.lib("/usr/lib/BouncyHsm.Pkcs11.so")
    token = lib.get_token(token_label="token")
    session = token.open(user_pin="1234", rw=True)
    ```

    **Result**: The test script successfully provisioned the key (using explicit EC params) and verified the signature (after converting it from raw to DER format).

### Local Development Verification

If you are modifying the code locally and want to run the tests without rebuilding the container for every change, you can mount your local source code into the container:

```bash
podman run --rm \
  -v $(pwd)/scripts:/scripts \
  -v $(pwd)/acapy_agent:/home/aries/acapy_agent \
  --env PYTHONPATH=/home/aries \
  --entrypoint "" \
  --network host \
  acapy-bouncyhsm \
  python3 /scripts/test_bouncy_hsm.py
```

### Running ACA-Py

To start the full ACA-Py agent in the container with the Askar wallet and PKCS#11 support enabled (verifying startup configuration):

```bash
podman run --rm -it \
  -p 8000:8000 -p 8001:8001 \
  -v $(pwd)/acapy_agent:/home/aries/acapy_agent \
  --env PYTHONPATH=/home/aries \
  --entrypoint "" \
  acapy-bouncyhsm \
  python3 -m acapy_agent start \
  --inbound-transport http 0.0.0.0 8000 \
  --outbound-transport http \
  --wallet-type askar \
  --wallet-name test \
  --wallet-key test \
  --auto-provision \
  --admin 0.0.0.0 8001 \
  --admin-insecure-mode \
  --no-ledger \
  --log-level debug
```

*Note: We replaced `--network host` with explicit port mappings because `--network host` on macOS often prevents accessing container ports from the host machine.*

### Recommended Workflow for did:web with BouncyHsm

To ensure `did:web` works correctly with `jwt_sign` (requiring proper `kid` tagging), you can create the key and DID in a single step, but you **must** provide the `kid` in the metadata.

**Create the DID (and auto-create the key):**
```bash
curl -X POST http://localhost:8001/wallet/did/create \
  -d '{
    "method": "web",
    "options": {
      "did": "did:web:example.com",
      "key_type": "pkcs11_p256"
    },
    "metadata": {
      "kid": "did:web:example.com#key-01"
    }
  }'
```

*   **Key Creation**: If the key (labeled `did:web:example.com` or `pkcs11_label` if provided) does not exist in the HSM, it will be automatically created.
*   **KID Tagging**: The `kid` provided in metadata will be used to tag the key in the wallet, ensuring `jwt_sign` can find it.

### X509 Method (PKCS#11 only)

The `x509` DID method is available for PKCS#11-backed P-256 keys with the following rules:

* `options.key_type` must be `pkcs11_p256`
* `options.did` is not allowed
* `metadata.pkcs11_label` or `metadata.kid` is required

If only `metadata.kid` is provided, ACA-Py uses it to locate/create the PKCS#11 key label.
For `x509`, the persisted `metadata.kid` is always derived as the SHA-256 hash of the
public key bytes.

### Identifier Reuse Behavior

When the provided identifier (`pkcs11_label` or incoming `kid`) already exists in the HSM,
ACA-Py reuses that key instead of creating a new private key.

* Key lookup is attempted first using the identifier.
* New key generation is only attempted if the lookup fails.
* If the Askar key record already exists for the resolved verkey, metadata is merged and
  updated (including `iaca_certificate` when available) rather than failing.

### IACA Certificate Resolution Order

For `x509`, ACA-Py attempts to resolve `metadata.iaca_certificate` in this order:

1. Provider-specific PKCS#11 extension methods (`create_iaca_certificate`, etc.)
2. Existing PKCS#11 certificate object lookup by label/kid
3. Standard fallback: build self-signed IACA-style cert in ACA-Py and sign with HSM key

If `--pkcs11-iaca-write-back` (or `ACAPY_PKCS11_IACA_WRITE_BACK=true`) is enabled,
resolved/generated certificates are also written to the HSM as certificate objects.

If the PKCS#11 provider exposes an IACA certificate extension, ACA-Py will attempt to
attach it to `metadata.iaca_certificate` in the DID record.

If no provider extension is available, ACA-Py falls back to standard PKCS#11-backed
certificate creation: it builds a self-signed IACA-style X.509 certificate in software,
uses PKCS#11 ECDSA signing with the HSM private key, and stores the PEM in
`metadata.iaca_certificate`.

To additionally write the certificate back to the HSM as a PKCS#11 certificate object,
enable:

* CLI: `--pkcs11-iaca-write-back`
* Env: `ACAPY_PKCS11_IACA_WRITE_BACK=true`

Example:

```bash
curl -X POST http://localhost:8001/wallet/did/create \
  -d '{
    "method": "x509",
    "options": {
      "key_type": "pkcs11_p256"
    },
    "metadata": {
      "pkcs11_label": "x509-signer"
    }
  }'
```

For quick verification of DID/KID/certificate output, use:

```bash
python3 scripts/test_x509_create.py
```

You can test metadata modes:

```bash
# metadata.pkcs11_label only (default)
python3 scripts/test_x509_create.py

# metadata.kid only
ACAPY_X509_METADATA_MODE=kid ACAPY_X509_KID=my-explicit-kid python3 scripts/test_x509_create.py

# both metadata fields
ACAPY_X509_METADATA_MODE=both ACAPY_X509_KID=my-explicit-kid python3 scripts/test_x509_create.py
```

### Troubleshooting (`iaca_certificate` is `null`)

If the DID creation succeeds but `metadata.iaca_certificate` is null, check the following:

1. **Running code is up to date**
  - Ensure ACA-Py is running with the updated local source or a rebuilt image.
  - If using containers, mount `acapy_agent` or rebuild image after changes.

2. **Identifier resolves the intended key**
  - Confirm `metadata.pkcs11_label` (or incoming `metadata.kid`) maps to an existing
    PKCS#11 private key object.
  - If key lookup fails, certificate generation/signing cannot proceed.

3. **Provider extension support**
  - If your HSM exposes provider-specific IACA methods, verify those methods are available
    in the PKCS#11 binding/runtime.
  - If not available, ACA-Py uses fallback behavior (certificate object lookup, then
    standard self-signed generation with HSM signing).

4. **Certificate object lookup/write-back support**
  - Some providers may not support `CKO_CERTIFICATE` create/read operations through the
    current binding.
  - Enable write-back and verify whether certificate objects are created:
    - `--pkcs11-iaca-write-back`
    - `ACAPY_PKCS11_IACA_WRITE_BACK=true`

5. **Session/slot/token configuration**
  - Validate `pkcs11.lib`, `pkcs11.token`, `pkcs11.slot`, and PIN are correct.
  - Ensure slot ID vs slot index interpretation matches your provider setup.

6. **Version compatibility**
  - Match BouncyHsm server version and PKCS#11 module version.
  - A mismatch can cause partial behavior (e.g., slot list works, token info/cert ops fail).

7. **Check ACA-Py logs around IACA resolution path**
  - Look for warnings from `acapy_agent.wallet.pkcs11` indicating:
    - extension method failures,
    - certificate object lookup failures,
    - standard fallback generation/signing failures.

8. **Verify key-metadata persistence in Askar**
  - Re-run DID create with same identifier and confirm metadata merge/update behavior.
  - Existing key records should be updated with new metadata when available.
