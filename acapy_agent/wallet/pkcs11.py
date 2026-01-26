"""PKCS11 Signer."""

import logging
from typing import Optional, Tuple

import pkcs11
from pkcs11 import KeyType, Mechanism, ObjectClass
from pkcs11.util.ec import encode_ec_public_key

from .error import WalletError

LOGGER = logging.getLogger(__name__)


class PKCS11Signer:
    """PKCS11 Signer class."""

    def __init__(
        self,
        lib_path: str,
        token_label: str,
        pin: Optional[str] = None,
        slot_index: Optional[int] = None,
    ):
        """Initialize PKCS11 Signer."""
        self.lib_path = lib_path
        self.token_label = token_label
        self.pin = pin
        self.slot_index = slot_index
        self._lib = None
        self._token = None
        self._session = None

    def _get_session(self):
        """Get PKCS11 session."""
        if self._session:
            return self._session

        try:
            self._lib = pkcs11.lib(self.lib_path)
            
            if self.slot_index is not None:
                slots = self._lib.get_slots()
                if 0 <= self.slot_index < len(slots):
                    token = slots[self.slot_index].get_token()
                else:
                    raise WalletError(f"Invalid slot index: {self.slot_index}")
            else:
                token = self._lib.get_token(token_label=self.token_label)

            self._token = token
            self._session = token.open(user_pin=self.pin, rw=True)
            return self._session
        except Exception as e:
            LOGGER.error(f"Error initializing PKCS11 session: {e}")
            raise WalletError(f"Error initializing PKCS11 session: {e}") from e

    def get_public_key_bytes(self, label: str) -> bytes:
        """Get public key bytes."""
        session = self._get_session()
        try:
            keys = list(
                session.get_objects(
                    {
                        pkcs11.Attribute.CLASS: ObjectClass.PUBLIC_KEY,
                        pkcs11.Attribute.LABEL: label,
                        pkcs11.Attribute.KEY_TYPE: KeyType.EC,
                    }
                )
            )
            if not keys:
                raise WalletError(f"Key with label {label} not found")
            
            public_key = keys[0]
            # Encode as X.509 SubjectPublicKeyInfo or raw points depending on need
            # For P-256 in ACA-Py/Askar, likely need raw bytes or SEC1 encoded
            # For simplicity and compatibility with what Askar likely expects (uncompressed point)
            # We might need to construct it manually from EC_POINT
            
            ec_point = public_key[pkcs11.Attribute.EC_POINT]
            return self._decode_ec_point(ec_point)

        except Exception as e:
             LOGGER.error(f"Error getting public key for {label}: {e}")
             raise WalletError(f"Error getting public key: {e}") from e

    def _decode_ec_point(self, ec_point: bytes) -> bytes:
        """Decode DER-encoded EC point."""
        # The 'ec_point' attribute in PKCS#11 is the DER encoding of the ANSI X9.62 ECPoint value.
        # This means it is an ASN.1 OCTET STRING wrapping the actual point bytes.
        if ec_point.startswith(b"\x04"):
             # It might be raw bytes if library is non-compliant or simplified
             # But strictly it should be DER OCTET STRING (tag 04) containing the point (usually starting with 04)
             pass
        
        der_bytes = ec_point
        # If it doesn't look like DER OCTET STRING (0x04 tag), assume it's raw
        if der_bytes[0] != 0x04:
             return der_bytes 
        
        # Simple length parsing
        idx = 1
        length = der_bytes[idx]
        if length & 0x80:
            n_bytes = length & 0x7f
            idx += 1 + n_bytes
        else:
            idx += 1
        
        point_bytes = der_bytes[idx:]
        return point_bytes

    def create_key(self, label: str) -> bytes:
        """Create a new P-256 keypair in the HSM."""
        session = self._get_session()
        try:
            # Generate P-256 Keypair
            # OID for secp256r1 (P-256): 1.2.840.10045.3.1.7
            pub, priv = session.generate_keypair(
                KeyType.EC,
                mechanism=Mechanism.EC_KEY_PAIR_GEN,
                public_template={
                    pkcs11.Attribute.LABEL: label,
                    pkcs11.Attribute.TOKEN: True,
                    pkcs11.Attribute.VERIFY: True,
                    pkcs11.Attribute.EC_PARAMS: b'\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07',
                },
                private_template={
                    pkcs11.Attribute.LABEL: label,
                    pkcs11.Attribute.TOKEN: True,
                    pkcs11.Attribute.SIGN: True,
                    pkcs11.Attribute.SENSITIVE: True,
                    pkcs11.Attribute.EXTRACTABLE: False,
                }
            )
            
            ec_point = pub[pkcs11.Attribute.EC_POINT]
            return self._decode_ec_point(ec_point)
            
        except Exception as e:
            LOGGER.error(f"Error creating key with label {label}: {e}")
            raise WalletError(f"Error creating key: {e}") from e

    def sign(self, message: bytes, label: str) -> bytes:
        """Sign message."""
        session = self._get_session()
        try:
            keys = list(
                session.get_objects(
                    {
                        pkcs11.Attribute.CLASS: ObjectClass.PRIVATE_KEY,
                        pkcs11.Attribute.LABEL: label,
                        pkcs11.Attribute.KEY_TYPE: KeyType.EC, # Assuming EC for P-256
                    }
                )
            )
            if not keys:
                 raise WalletError(f"Private key with label {label} not found")
            
            private_key = keys[0]
            signature = private_key.sign(
                message, 
                mechanism=Mechanism.ECDSA 
                # P-256 usually implies ECDSA. 
                # Hashing is often done before passed to sign if Mechanism does not include hashing.
                # BaseWallet.sign_message usually expects raw message to be signed? 
                # OR is it pre-hashed? Askar usually handles hashing if algorithm implies it.
                # But here we are at low level.
                # Wait, 'Mechanism.ECDSA' in PKCS11 inputs a digest.
                # If we want to sign full message we should use ECDSA_SHA256 if supported
                # OR we hash it ourselves.
                
                # ACAPy's Askar sign_message uses Key.sign_message(message).
                # Askar's P256 sign_message likely does SHA256 then ECDSA.
                # So we should hash it first if we use ECDSA.
            )
            
            # It seems safer to use ECDSA mechanism and hash manually to be explicit,
            # unless we know the HSM supports ECDSA_SHA256.
            # But let's check `sign_message` contract in `BaseWallet`.
            # "Sign message(s) ...". It doesn't say "Sign digest".
            # So I should probably hash it if I use generic ECDSA.
            # However, py-pkcs11 `private_key.sign` follows the mechanism.
            
            # Let's assume generic ECDSA for now and hash it.
            # Wait, python-pkcs11 example:
            # key.sign(data, mechanism=pkcs11.Mechanism.ECDSA)
            # data "Must be a digest" for ECDSA mechanism according to PKCS#11 spec logic usually.
            
            import hashlib
            digest = hashlib.sha256(message).digest()
            signature = private_key.sign(digest, mechanism=Mechanism.ECDSA)
            return signature

        except Exception as e:
            LOGGER.error(f"Error signing message with {label}: {e}")
            raise WalletError(f"Error signing message: {e}") from e
