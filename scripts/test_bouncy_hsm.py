
import os
import sys
import logging
import json
import base64
import hashlib
import requests
from acapy_agent.wallet.pkcs11 import PKCS11Signer
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, encode_dss_signature

# Configure logging
logging.basicConfig(level=logging.INFO)
LOGGER = logging.getLogger(__name__)

# Configuration from environment or defaults (matching Dockerfile)
PKCS11_LIB = os.environ.get("ACAPY_PKCS11_LIB", "/usr/lib/BouncyHsm.Pkcs11.so")
PKCS11_TOKEN = os.environ.get("ACAPY_PKCS11_TOKEN", "token")
PKCS11_PIN = os.environ.get("ACAPY_PKCS11_PIN", "1234")
PKCS11_SLOT = int(os.environ.get("ACAPY_PKCS11_SLOT", "1"))
KEY_LABEL = "test-key-p256"

from acapy_agent.wallet.error import WalletError

def test_pkcs11_signer():
    LOGGER.info("Starting PKCS11 Signer Test...")
    
    # 1. Initialize Signer
    try:
        signer = PKCS11Signer(lib_path=PKCS11_LIB, token_label=PKCS11_TOKEN, pin=PKCS11_PIN)
    except Exception as e:
        LOGGER.error(f"Failed to initialize signer: {e}")
        return

    # 2. Provision or Get Public Key using PKCS11Signer
    try:
        LOGGER.info(f"Attempting to retrieve key '{KEY_LABEL}'...")
        pub_bytes = signer.get_public_key_bytes(KEY_LABEL)
        LOGGER.info("Key found.")
    except WalletError:
        LOGGER.info(f"Key '{KEY_LABEL}' not found. Creating new key via PKCS11Signer...")
        try:
             pub_bytes = signer.create_key(KEY_LABEL)
             LOGGER.info("Key created successfully.")
        except Exception as e:
             LOGGER.error(f"Failed to create key: {e}")
             return
    except Exception as e:
        LOGGER.error(f"Failed to get public key: {e}")
        return

    LOGGER.info(f"Retrieved Public Key Bytes (len={len(pub_bytes)}): {pub_bytes.hex()}")

    # 3. Sign Message
    message = b"Hello from ACA-Py + BouncyHsm!"
    try:
        signature = signer.sign(message, KEY_LABEL)
        LOGGER.info(f"Signature (len={len(signature)}): {signature.hex()}")
    except Exception as e:
        LOGGER.error(f"Failed to sign message: {e}")
        return

    # 5. Verify Signature (soft verification)
    try:
        # Load public key from bytes (Uncompressed point format assumed 0x04...)
        # python-pkcs11 usually returns the raw point (04 | x | y) or similar.
        
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub_bytes)
        
        # PKCS#11 returns raw (r|s) signature (64 bytes for P-256)
        # cryptography expects DER encoded signature
        if len(signature) == 64:
             r = int.from_bytes(signature[:32], "big")
             s = int.from_bytes(signature[32:], "big")
             der_signature = encode_dss_signature(r, s)
             LOGGER.info(f"Converted Raw signature to DER (len={len(der_signature)})")
        else:
             der_signature = signature

        public_key.verify(
            der_signature,
            message,
            ec.ECDSA(hashes.SHA256())
        )
        LOGGER.info("SUCCESS: Signature verified locally!")
        
    except Exception as e:
        LOGGER.error(f"Signature verification failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_pkcs11_signer()
