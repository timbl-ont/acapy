import json
import logging
import os
import sys

import requests

logging.basicConfig(level=logging.INFO)
LOGGER = logging.getLogger(__name__)

ADMIN_URL = os.environ.get("ACAPY_ADMIN_URL", "http://localhost:8001")
ADMIN_API_KEY = os.environ.get("ACAPY_ADMIN_API_KEY")
PKCS11_LABEL = os.environ.get("ACAPY_PKCS11_LABEL", "x509-signer")
X509_KID = os.environ.get("ACAPY_X509_KID")
METADATA_MODE = os.environ.get("ACAPY_X509_METADATA_MODE", "pkcs11_label").strip().lower()
TIMEOUT_SECONDS = int(os.environ.get("ACAPY_ADMIN_TIMEOUT", "30"))


def _build_headers() -> dict:
    headers = {"Content-Type": "application/json"}
    if ADMIN_API_KEY:
        headers["x-api-key"] = ADMIN_API_KEY
    return headers


def _build_payload() -> dict:
    metadata = {}

    if METADATA_MODE == "kid":
        metadata["kid"] = X509_KID or PKCS11_LABEL
    elif METADATA_MODE == "both":
        metadata["pkcs11_label"] = PKCS11_LABEL
        metadata["kid"] = X509_KID or PKCS11_LABEL
    else:
        metadata["pkcs11_label"] = PKCS11_LABEL

    return {
        "method": "x509",
        "options": {
            "key_type": "pkcs11_p256",
        },
        "metadata": metadata,
    }


def main() -> int:
    url = f"{ADMIN_URL.rstrip('/')}/wallet/did/create"
    payload = _build_payload()
    headers = _build_headers()

    LOGGER.info("Calling %s", url)
    LOGGER.info("Payload: %s", json.dumps(payload))

    try:
        response = requests.post(
            url,
            json=payload,
            headers=headers,
            timeout=TIMEOUT_SECONDS,
        )
    except requests.RequestException as err:
        LOGGER.error("Request failed: %s", err)
        return 1

    if response.status_code >= 400:
        LOGGER.error("HTTP %s", response.status_code)
        LOGGER.error("Body: %s", response.text)
        return 1

    try:
        body = response.json()
    except ValueError:
        LOGGER.error("Response was not JSON: %s", response.text)
        return 1

    result = body.get("result", {})
    metadata = result.get("metadata", {})

    output = {
        "did": result.get("did"),
        "method": result.get("method"),
        "key_type": result.get("key_type"),
        "pkcs11_label": metadata.get("pkcs11_label"),
        "kid": metadata.get("kid"),
        "iaca_certificate": metadata.get("iaca_certificate"),
    }

    print(json.dumps(output, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
