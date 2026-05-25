
# Walkthrough - PKCS11-P256 Support

I have implemented support for the `PKCS11-P256` key type, enabling keys to be stored in an external HSM while ACA-Py retains only a reference (identifier). Signing operations are delegated to the HSM via a PKCS#11 plugin.

## Changes

### Configuration
- **Added `python-pkcs11` dependency** in `pyproject.toml`.
- **Added CLI arguments** in `acapy_agent/config/argparse.py`:
  - `--pkcs11-lib`: Path to the PKCS#11 shared library.
  - `--pkcs11-pin`: User PIN for the token.
  - `--pkcs11-token`: Token label.
  - `--pkcs11-token`: Token label.

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
  - Installed BouncyHsm PKCS#11 driver (v1.5.0).
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
    podman build -f docker/Dockerfile -t acapy-bouncyhsm .
    ```

2.  **Run the Verification Script**:
    Ensure your BouncyHsm instance is running at `http://192.168.1.136:8080`.
    
    ```bash
    podman run --rm -v $(pwd)/scripts:/scripts \
      --entrypoint "" \
      --network host \
      acapy-bouncyhsm \
      python3 /scripts/test_bouncy_hsm.py
    ```

    *Note: We use `--entrypoint ""` to override the default `aca-py` entrypoint so we can run python3 directly.*

    This script will:
    *   Connect to BouncyHsm.
    *   Provision a P-256 key (`test-key-p256`) if missing.
    *   Sign a test message using the `acapy_agent` PKCS#11 integration.
    *   Verify the signature locally.

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
