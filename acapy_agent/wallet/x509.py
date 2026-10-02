"""X.509 certificate support for wallet keys.

Certificate signing requests (CSRs) and self-signed certificates are signed by the
wallet itself, so the private key never leaves the wallet. Certificate chains are
stored in the key metadata, in `x5c` form (RFC 7517 §4.7), for use in JWS headers.
"""

import base64
import datetime
from typing import List, Optional, Sequence, Tuple, TypeVar, Union

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from .base import BaseWallet
from .did_info import KeyInfo
from .error import WalletError
from .key_type import P256, KeyType
from .util import b58_to_bytes

X5C_METADATA_KEY = "x5c"
DEFAULT_VALIDITY_DAYS = 365

# Curve and hash algorithm applied by the wallet when signing with each key type
_SUPPORTED_KEY_TYPES = {
    P256.key_type: (ec.SECP256R1(), hashes.SHA256()),
}

_KEY_USAGE_DIGITAL_SIGNATURE = x509.KeyUsage(
    digital_signature=True,
    content_commitment=False,
    key_encipherment=False,
    data_encipherment=False,
    key_agreement=False,
    key_cert_sign=False,
    crl_sign=False,
    encipher_only=False,
    decipher_only=False,
)

_Builder = TypeVar(
    "_Builder", x509.CertificateBuilder, x509.CertificateSigningRequestBuilder
)


class X509Error(WalletError):
    """X.509 certificate error."""


class _WalletSigningKey(ec.EllipticCurvePrivateKey):
    """EC private key stand-in whose signature is produced by the wallet.

    The cryptography builders sign synchronously while wallet signing is async, so
    the builder runs twice: the first pass captures the to-be-signed bytes, which
    the wallet then signs, and the second pass returns that signature.
    """

    def __init__(self, public_key: ec.EllipticCurvePublicKey):
        self._public_key = public_key
        self.tbs: Optional[bytes] = None
        self.signature: Optional[bytes] = None

    @property
    def curve(self) -> ec.EllipticCurve:
        return self._public_key.curve

    @property
    def key_size(self) -> int:
        return self._public_key.curve.key_size

    def public_key(self) -> ec.EllipticCurvePublicKey:
        return self._public_key

    def sign(
        self,
        data: Union[bytes, bytearray, memoryview],
        signature_algorithm: ec.EllipticCurveSignatureAlgorithm,
    ) -> bytes:
        if self.signature is None:
            self.tbs = bytes(data)
            # Placeholder signature, discarded after the first pass
            return encode_dss_signature(1, 1)
        if bytes(data) != self.tbs:
            raise X509Error("To-be-signed data changed between signing passes")
        return self.signature

    def exchange(self, algorithm, peer_public_key) -> bytes:
        raise NotImplementedError("Key agreement is not supported")

    def private_numbers(self) -> ec.EllipticCurvePrivateNumbers:
        raise NotImplementedError("Private key material is held by the wallet")

    def private_bytes(self, encoding, format, encryption_algorithm) -> bytes:
        raise NotImplementedError("Private key material is held by the wallet")

    def __copy__(self) -> "_WalletSigningKey":
        return self


def _curve_and_hash(
    key_type: KeyType,
) -> Tuple[ec.EllipticCurve, hashes.HashAlgorithm]:
    if key_type.key_type not in _SUPPORTED_KEY_TYPES:
        raise X509Error(
            f"X.509 certificates are not supported for key type '{key_type.key_type}'; "
            f"supported key types: {', '.join(_SUPPORTED_KEY_TYPES)}"
        )
    return _SUPPORTED_KEY_TYPES[key_type.key_type]


def public_key_for(key_info: KeyInfo) -> ec.EllipticCurvePublicKey:
    """Return the public key of a wallet key as a cryptography object."""
    curve, _ = _curve_and_hash(key_info.key_type)
    return ec.EllipticCurvePublicKey.from_encoded_point(
        curve, b58_to_bytes(key_info.verkey)
    )


async def _sign_with_wallet(
    builder: _Builder, wallet: BaseWallet, key_info: KeyInfo
) -> Union[x509.Certificate, x509.CertificateSigningRequest]:
    curve, hash_alg = _curve_and_hash(key_info.key_type)
    signing_key = _WalletSigningKey(public_key_for(key_info))

    builder.sign(signing_key, hash_alg)
    raw_signature = await wallet.sign_message(signing_key.tbs, key_info.verkey)

    # The wallet returns a raw (r || s) signature; X.509 requires DER encoding
    size = (curve.key_size + 7) // 8
    if len(raw_signature) != 2 * size:
        raise X509Error("Unexpected signature length returned by the wallet")
    signing_key.signature = encode_dss_signature(
        int.from_bytes(raw_signature[:size], "big"),
        int.from_bytes(raw_signature[size:], "big"),
    )
    return builder.sign(signing_key, hash_alg)


def parse_subject(subject: Optional[str]) -> x509.Name:
    """Parse an RFC 4514 distinguished name, such as `CN=Issuer,O=Example,C=CA`."""
    if not subject:
        return x509.Name([])
    try:
        return x509.Name.from_rfc4514_string(subject)
    except ValueError as err:
        raise X509Error(f"Invalid subject name '{subject}': {err}") from err


def _subject_alt_names(
    dns_names: Optional[Sequence[str]] = None,
    uris: Optional[Sequence[str]] = None,
    emails: Optional[Sequence[str]] = None,
) -> List[x509.GeneralName]:
    try:
        return [
            *(x509.DNSName(name) for name in dns_names or []),
            *(x509.UniformResourceIdentifier(uri) for uri in uris or []),
            *(x509.RFC822Name(email) for email in emails or []),
        ]
    except ValueError as err:
        raise X509Error(f"Invalid subject alternative name: {err}") from err


async def create_csr(
    wallet: BaseWallet,
    key_info: KeyInfo,
    subject: Optional[str] = None,
    *,
    dns_names: Optional[Sequence[str]] = None,
    uris: Optional[Sequence[str]] = None,
    emails: Optional[Sequence[str]] = None,
) -> x509.CertificateSigningRequest:
    """Create a certificate signing request (PKCS #10) signed by a wallet key.

    Args:
        wallet: the wallet holding the key
        key_info: the key to certify
        subject: RFC 4514 subject distinguished name
        dns_names: DNS names for the subject alternative name extension
        uris: URIs for the subject alternative name extension
        emails: email addresses for the subject alternative name extension

    Returns:
        The signed certificate signing request

    """
    name = parse_subject(subject)
    san = _subject_alt_names(dns_names, uris, emails)
    if len(name) == 0 and not san:
        raise X509Error("A subject or subject alternative name is required")

    builder = x509.CertificateSigningRequestBuilder().subject_name(name)
    if san:
        # RFC 5280 §4.2.1.6: critical when the subject is empty
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san), critical=len(name) == 0
        )
    builder = builder.add_extension(_KEY_USAGE_DIGITAL_SIGNATURE, critical=True)

    csr = await _sign_with_wallet(builder, wallet, key_info)
    if not csr.is_signature_valid:
        raise X509Error("Wallet produced an invalid certificate request signature")
    return csr


async def create_self_signed_certificate(
    wallet: BaseWallet,
    key_info: KeyInfo,
    subject: str,
    *,
    dns_names: Optional[Sequence[str]] = None,
    uris: Optional[Sequence[str]] = None,
    emails: Optional[Sequence[str]] = None,
    validity_days: int = DEFAULT_VALIDITY_DAYS,
) -> x509.Certificate:
    """Create a self-signed end-entity certificate for a wallet key.

    Args:
        wallet: the wallet holding the key
        key_info: the key to certify
        subject: RFC 4514 subject (and issuer) distinguished name
        dns_names: DNS names for the subject alternative name extension
        uris: URIs for the subject alternative name extension
        emails: email addresses for the subject alternative name extension
        validity_days: number of days the certificate is valid for

    Returns:
        The self-signed certificate

    """
    name = parse_subject(subject)
    if len(name) == 0:
        raise X509Error("A subject is required for a self-signed certificate")
    if validity_days < 1:
        raise X509Error("Certificate validity must be at least one day")
    san = _subject_alt_names(dns_names, uris, emails)

    public_key = public_key_for(key_info)
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(_KEY_USAGE_DIGITAL_SIGNATURE, critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key),
            critical=False,
        )
    )
    if san:
        builder = builder.add_extension(x509.SubjectAlternativeName(san), critical=False)

    certificate = await _sign_with_wallet(builder, wallet, key_info)
    try:
        certificate.verify_directly_issued_by(certificate)
    except InvalidSignature as err:
        raise X509Error("Wallet produced an invalid certificate signature") from err
    return certificate


def load_pem_certificate_chain(certificate_chain: str) -> List[x509.Certificate]:
    """Load one or more PEM encoded certificates."""
    try:
        return x509.load_pem_x509_certificates(certificate_chain.encode())
    except ValueError as err:
        raise X509Error(f"Invalid PEM certificate chain: {err}") from err


def validate_certificate_chain(
    chain: Sequence[x509.Certificate],
    key_info: KeyInfo,
    now: Optional[datetime.datetime] = None,
):
    """Check that a certificate chain (leaf first) certifies a wallet key.

    The leaf certificate must hold the wallet public key, be unexpired and permit
    digital signatures, and each certificate must be issued by the next one. The
    chain is not validated against any trust anchor.
    """
    if not chain:
        raise X509Error("Certificate chain is empty")

    leaf = chain[0]
    leaf_public_key = leaf.public_key()
    expected = public_key_for(key_info)
    if not (
        isinstance(leaf_public_key, ec.EllipticCurvePublicKey)
        and leaf_public_key.curve.name == expected.curve.name
        and leaf_public_key.public_numbers() == expected.public_numbers()
    ):
        raise X509Error("Leaf certificate public key does not match the wallet key")

    now = now or datetime.datetime.now(datetime.timezone.utc)
    if leaf.not_valid_after_utc < now:
        raise X509Error("Leaf certificate has expired")

    try:
        key_usage = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        key_usage = None
    if key_usage is not None and not key_usage.digital_signature:
        raise X509Error("Leaf certificate key usage does not permit digital signatures")

    for certificate, issuer in zip(chain, chain[1:]):
        try:
            certificate.verify_directly_issued_by(issuer)
        except (ValueError, TypeError, InvalidSignature, UnsupportedAlgorithm) as err:
            raise X509Error(
                f"Certificate '{certificate.subject.rfc4514_string()}' is not issued "
                f"by '{issuer.subject.rfc4514_string()}'; the chain must be ordered "
                "leaf first"
            ) from err


def certificate_chain_to_x5c(chain: Sequence[x509.Certificate]) -> List[str]:
    """Encode certificates as an `x5c` value (base64 DER, not base64url)."""
    return [
        base64.b64encode(certificate.public_bytes(serialization.Encoding.DER)).decode()
        for certificate in chain
    ]


def x5c_to_pem(x5c: Sequence[str]) -> str:
    """Convert an `x5c` value to concatenated PEM certificates."""
    return "".join(
        x509.load_der_x509_certificate(base64.b64decode(cert))
        .public_bytes(serialization.Encoding.PEM)
        .decode()
        for cert in x5c
    )


def get_x5c(key_info: KeyInfo) -> Optional[List[str]]:
    """Return the certificate chain stored for a wallet key, if any."""
    return (key_info.metadata or {}).get(X5C_METADATA_KEY)


async def store_certificate_chain(
    wallet: BaseWallet,
    key_info: KeyInfo,
    chain: Sequence[x509.Certificate],
) -> List[str]:
    """Validate and store a certificate chain (leaf first) for a wallet key.

    Any previously stored chain is replaced.

    Returns:
        The stored chain in `x5c` form

    """
    validate_certificate_chain(chain, key_info)
    x5c = certificate_chain_to_x5c(chain)
    metadata = {**(key_info.metadata or {}), X5C_METADATA_KEY: x5c}
    await wallet.replace_signing_key_metadata(key_info.verkey, metadata)
    return x5c
