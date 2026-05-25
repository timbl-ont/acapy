"""PKCS11 Signer."""

import base64
import datetime
import hashlib
import logging
import re
from typing import Optional

import pkcs11
from pkcs11 import KeyType, Mechanism, ObjectClass
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

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
        iaca_write_back: bool = False,
    ):
        """Initialize PKCS11 Signer."""
        self.lib_path = lib_path
        self.token_label = token_label
        self.pin = pin
        self.slot_index = slot_index
        self.iaca_write_back = iaca_write_back
        self._lib = None
        self._token = None
        self._session = None

    def _format_exception(self, err: Exception) -> str:
        """Build a detailed error string including nested exception data."""
        details = [
            f"type={type(err).__name__}",
            f"message={err}",
            f"args={err.args!r}",
        ]

        cause = getattr(err, "__cause__", None)
        if cause:
            details.append(
                "cause="
                f"{type(cause).__name__}(message={cause}, args={cause.args!r})"
            )

        context = getattr(err, "__context__", None)
        if context and context is not cause:
            details.append(
                "context="
                f"{type(context).__name__}(message={context}, args={context.args!r})"
            )

        return "; ".join(details)

    class _PKCS11ECPrivateKey(ec.EllipticCurvePrivateKey):
        """ECDSA private key adapter that signs through PKCS#11."""

        def __init__(self, signer: "PKCS11Signer", label: str, public_key):
            self._signer = signer
            self._label = label
            self._public_key = public_key

        @property
        def curve(self):
            return self._public_key.curve

        @property
        def key_size(self):
            return self._public_key.key_size

        def public_key(self):
            return self._public_key

        def sign(self, data: bytes, signature_algorithm) -> bytes:
            if not isinstance(signature_algorithm, ec.ECDSA):
                raise TypeError("Only ECDSA signatures are supported for PKCS11 adapter")

            hash_alg = signature_algorithm.algorithm
            digest = hashes.Hash(hash_alg)
            digest.update(data)
            hashed = digest.finalize()

            raw_sig = self._signer.sign_digest(hashed, self._label)
            if len(raw_sig) == 64:
                r = int.from_bytes(raw_sig[:32], "big")
                s = int.from_bytes(raw_sig[32:], "big")
                return encode_dss_signature(r, s)
            return raw_sig

        def private_numbers(self):
            raise TypeError("Private numbers are not available for PKCS11 keys")

        def private_bytes(self, encoding, format, encryption_algorithm):
            raise TypeError("Private key export is not available for PKCS11 keys")

        def exchange(self, algorithm, peer_public_key):
            raise TypeError("Key exchange is not implemented for PKCS11 adapter")

        def __copy__(self):
            """Return self: adapter is stateless wrapper around PKCS11 label."""
            return self

        def __deepcopy__(self, memo):
            """Return self for deepcopy to satisfy cryptography ABC in Python 3.13+."""
            return self

    @staticmethod
    def _normalize_certificate_output(raw_value) -> Optional[str]:
        """Normalize certificate output to text when possible."""
        if raw_value is None:
            return None
        if isinstance(raw_value, str):
            return raw_value
        if isinstance(raw_value, (bytes, bytearray)):
            try:
                return bytes(raw_value).decode("utf-8")
            except UnicodeDecodeError:
                return bytes(raw_value).hex()
        return str(raw_value)

    @staticmethod
    def _der_to_pem(der_bytes: bytes) -> str:
        body = base64.encodebytes(der_bytes).decode("ascii")
        return "-----BEGIN CERTIFICATE-----\n" + body + "-----END CERTIFICATE-----\n"

    @staticmethod
    def _certificate_to_der(cert_value: str) -> bytes:
        cert_value = cert_value.strip()
        if cert_value.startswith("-----BEGIN CERTIFICATE-----"):
            lines = [
                line.strip()
                for line in cert_value.splitlines()
                if line and "CERTIFICATE" not in line
            ]
            return base64.b64decode("".join(lines))

        if re.fullmatch(r"[0-9a-fA-F]+", cert_value) and len(cert_value) % 2 == 0:
            return bytes.fromhex(cert_value)

        try:
            return base64.b64decode(cert_value, validate=True)
        except Exception:
            return cert_value.encode("utf-8")

    def _lookup_certificate_object(self, label: Optional[str]) -> Optional[str]:
        if not label:
            return None

    def _create_standard_iaca_certificate(
        self,
        label: str,
        kid: Optional[str],
        public_key: bytes,
    ) -> Optional[str]:
        """Create a self-signed IACA-style certificate using PKCS#11 signing."""
        try:
            ec_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), public_key
            )
        except Exception as err:
            LOGGER.warning(
                "Unable to parse EC public key for IACA cert creation: %s",
                self._format_exception(err),
            )
            return None

        subject_cn = kid or label
        now = datetime.datetime.utcnow()
        serial_seed = hashlib.sha256(public_key + subject_cn.encode("utf-8")).digest()
        serial_number = int.from_bytes(serial_seed[:20], "big") >> 1

        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, subject_cn),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ACA-Py PKCS11"),
            ]
        )

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(ec_public_key)
            .serial_number(serial_number)
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(ec_public_key),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ec_public_key),
                critical=False,
            )
        )

        signing_key = PKCS11Signer._PKCS11ECPrivateKey(
            signer=self,
            label=label,
            public_key=ec_public_key,
        )

        try:
            cert = builder.sign(private_key=signing_key, algorithm=hashes.SHA256())
        except Exception as err:
            LOGGER.warning(
                "Standard IACA certificate generation failed: %s",
                self._format_exception(err),
            )
            return None

        return cert.public_bytes(encoding=Encoding.PEM).decode("utf-8")

        session = self._get_session()
        cert_class = getattr(ObjectClass, "CERTIFICATE", None)
        if cert_class is None:
            return None

        try:
            certs = list(
                session.get_objects(
                    {
                        pkcs11.Attribute.CLASS: cert_class,
                        pkcs11.Attribute.LABEL: label,
                    }
                )
            )
        except Exception as err:
            LOGGER.warning(
                "Failed PKCS#11 cert lookup for label %s: %s",
                label,
                self._format_exception(err),
            )
            return None

        if not certs:
            return None

        try:
            der_value = certs[0][pkcs11.Attribute.VALUE]
            if isinstance(der_value, (bytes, bytearray)):
                return self._der_to_pem(bytes(der_value))
            return self._normalize_certificate_output(der_value)
        except Exception as err:
            LOGGER.warning(
                "Failed reading PKCS#11 cert object for label %s: %s",
                label,
                self._format_exception(err),
            )
            return None

    def _write_certificate_to_hsm(
        self,
        cert_value: str,
        label: Optional[str],
        kid: Optional[str],
    ) -> None:
        session = self._get_session()
        cert_class = getattr(ObjectClass, "CERTIFICATE", None)
        if cert_class is None:
            LOGGER.warning("PKCS#11 provider does not expose CERTIFICATE class")
            return

        der_bytes = self._certificate_to_der(cert_value)
        cert_label = label or kid or "x509-iaca"

        attributes = {
            pkcs11.Attribute.CLASS: cert_class,
            pkcs11.Attribute.TOKEN: True,
            pkcs11.Attribute.LABEL: cert_label,
            pkcs11.Attribute.VALUE: der_bytes,
        }

        cert_type_attr = getattr(pkcs11.Attribute, "CERTIFICATE_TYPE", None)
        cert_type_enum = getattr(pkcs11, "CertificateType", None)
        if cert_type_attr is not None and cert_type_enum is not None:
            x509_type = getattr(cert_type_enum, "X_509", None)
            if x509_type is not None:
                attributes[cert_type_attr] = x509_type

        try:
            if hasattr(session, "create_object"):
                session.create_object(attributes)
                LOGGER.info(
                    "Persisted IACA certificate object in HSM with label=%s",
                    cert_label,
                )
            else:
                LOGGER.warning(
                    "PKCS#11 session does not support create_object; cannot write cert"
                )
        except Exception as err:
            LOGGER.warning(
                "Failed writing IACA cert object to HSM: %s",
                self._format_exception(err),
            )

    def _get_session(self):
        """Get PKCS11 session."""
        if self._session:
            return self._session

        try:
            self._lib = pkcs11.lib(self.lib_path)

            if self.slot_index is not None:
                slots = self._lib.get_slots()

                # Prefer exact PKCS#11 slot ID match (what most HSM UIs expose).
                matching_slot = next(
                    (
                        slot
                        for slot in slots
                        if getattr(slot, "slot_id", None) == self.slot_index
                    ),
                    None,
                )

                # Backward-compatible fallback: treat value as positional index.
                if matching_slot is None and 0 <= self.slot_index < len(slots):
                    matching_slot = slots[self.slot_index]
                    LOGGER.warning(
                        "Configured pkcs11.slot=%s did not match a slot_id; "
                        "using positional index fallback",
                        self.slot_index,
                    )

                if matching_slot is None:
                    available_slot_ids = [
                        getattr(slot, "slot_id", None) for slot in slots
                    ]
                    raise WalletError(
                        "Invalid slot value: "
                        f"{self.slot_index}. "
                        f"Available slot IDs: {available_slot_ids}; "
                        f"slot count: {len(slots)}"
                    )

                token = matching_slot.get_token()
            else:
                token = self._lib.get_token(token_label=self.token_label)

            self._token = token
            self._session = token.open(user_pin=self.pin, rw=True)
            return self._session
        except Exception as e:
            detail = self._format_exception(e)
            LOGGER.exception("Error initializing PKCS11 session: %s", detail)
            raise WalletError(f"Error initializing PKCS11 session: {detail}") from e

    def create_iaca_certificate(
        self,
        label: Optional[str],
        kid: Optional[str],
        public_key: bytes,
        write_back: Optional[bool] = None,
    ) -> Optional[str]:
        """Attempt to create or retrieve an IACA certificate via provider extensions.

        This is optional and provider-specific. If no known extension point exists,
        this method returns None.
        """
        session = self._get_session()

        should_write_back = self.iaca_write_back if write_back is None else write_back

        extension_targets = [self._lib, session]
        extension_method_names = (
            "create_iaca_certificate",
            "create_iaca_cert",
            "get_iaca_certificate",
            "get_iaca_cert",
        )

        for target in extension_targets:
            if not target:
                continue

            for method_name in extension_method_names:
                if not hasattr(target, method_name):
                    continue

                extension_method = getattr(target, method_name)
                try:
                    result = extension_method(
                        label=label,
                        kid=kid,
                        public_key=public_key,
                    )
                    cert = self._normalize_certificate_output(result)
                    if cert:
                        LOGGER.info(
                            "IACA certificate produced via extension method %s",
                            method_name,
                        )
                        if should_write_back:
                            self._write_certificate_to_hsm(cert, label=label, kid=kid)
                        return cert
                except TypeError:
                    try:
                        result = extension_method(label, kid, public_key)
                        cert = self._normalize_certificate_output(result)
                        if cert:
                            LOGGER.info(
                                "IACA certificate produced via extension method %s",
                                method_name,
                            )
                            if should_write_back:
                                self._write_certificate_to_hsm(cert, label=label, kid=kid)
                            return cert
                    except Exception as err:
                        LOGGER.warning(
                            "IACA extension method %s failed: %s",
                            method_name,
                            self._format_exception(err),
                        )
                except Exception as err:
                    LOGGER.warning(
                        "IACA extension method %s failed: %s",
                        method_name,
                        self._format_exception(err),
                    )

        # Standard PKCS#11 fallback: check whether a cert object already exists.
        found_cert = self._lookup_certificate_object(label) or self._lookup_certificate_object(kid)
        if found_cert:
            return found_cert

        if label:
            generated_cert = self._create_standard_iaca_certificate(
                label=label,
                kid=kid,
                public_key=public_key,
            )
            if generated_cert:
                if should_write_back:
                    self._write_certificate_to_hsm(generated_cert, label=label, kid=kid)
                return generated_cert

        return None

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
               detail = self._format_exception(e)
               LOGGER.exception("Error getting public key for %s: %s", label, detail)
               raise WalletError(f"Error getting public key: {detail}") from e

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
            detail = self._format_exception(e)
            LOGGER.exception("Error creating key with label %s: %s", label, detail)
            raise WalletError(f"Error creating key: {detail}") from e

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
            signature = self.sign_digest(digest, label)
            return signature

        except Exception as e:
            detail = self._format_exception(e)
            LOGGER.exception("Error signing message with %s: %s", label, detail)
            raise WalletError(f"Error signing message: {detail}") from e

    def sign_digest(self, digest: bytes, label: str) -> bytes:
        """Sign pre-hashed digest with PKCS#11 private key label."""
        session = self._get_session()
        try:
            keys = list(
                session.get_objects(
                    {
                        pkcs11.Attribute.CLASS: ObjectClass.PRIVATE_KEY,
                        pkcs11.Attribute.LABEL: label,
                        pkcs11.Attribute.KEY_TYPE: KeyType.EC,
                    }
                )
            )
            if not keys:
                raise WalletError(f"Private key with label {label} not found")

            return keys[0].sign(digest, mechanism=Mechanism.ECDSA)
        except Exception as e:
            detail = self._format_exception(e)
            LOGGER.exception("Error signing digest with %s: %s", label, detail)
            raise WalletError(f"Error signing digest: {detail}") from e
