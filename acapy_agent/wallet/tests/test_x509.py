import base64
import datetime
from unittest import IsolatedAsyncioTestCase

import pytest
from cryptography import x509 as cx509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from ...tests import mock
from ...utils.testing import create_test_profile
from .. import x509
from ..base import BaseWallet
from ..key_type import ED25519, P256, KeyTypes


def make_ca(name: str = "Test CA", issuer_key=None, issuer_name=None):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = cx509.Name([cx509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        cx509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name or subject)
        .public_key(key.public_key())
        .serial_number(cx509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(cx509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(issuer_key or key, hashes.SHA256())
    )
    return key, cert


def issue_from_csr(
    csr: cx509.CertificateSigningRequest,
    ca_key,
    ca_cert: cx509.Certificate,
    not_valid_after: datetime.datetime | None = None,
    key_usage: cx509.KeyUsage | None = None,
) -> cx509.Certificate:
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        cx509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(cx509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=2))
        .not_valid_after(not_valid_after or now + datetime.timedelta(days=10))
    )
    if key_usage:
        builder = builder.add_extension(key_usage, critical=True)
    return builder.sign(ca_key, hashes.SHA256())


class TestX509(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.profile = await create_test_profile()
        self.profile.context.injector.bind_instance(KeyTypes, KeyTypes())
        async with self.profile.session() as session:
            wallet = session.inject(BaseWallet)
            key = await wallet.create_key(P256, metadata={"note": "keep"})
            self.key_info = await wallet.get_signing_key(key.verkey)

    def wallet_public_key(self) -> ec.EllipticCurvePublicKey:
        return x509.public_key_for(self.key_info)

    async def test_create_csr(self):
        async with self.profile.session() as session:
            csr = await x509.create_csr(
                session.inject(BaseWallet),
                self.key_info,
                "CN=Issuer,O=Example,C=CA",
                dns_names=["issuer.example.com"],
                uris=["https://issuer.example.com"],
                emails=["issuer@example.com"],
            )

        assert csr.is_signature_valid
        assert csr.subject.rfc4514_string() == "CN=Issuer,O=Example,C=CA"
        assert csr.public_key() == self.wallet_public_key()
        assert csr.signature_hash_algorithm.name == "sha256"
        san = csr.extensions.get_extension_for_class(cx509.SubjectAlternativeName)
        assert not san.critical
        assert san.value.get_values_for_type(cx509.DNSName) == ["issuer.example.com"]
        assert san.value.get_values_for_type(cx509.UniformResourceIdentifier) == [
            "https://issuer.example.com"
        ]
        assert san.value.get_values_for_type(cx509.RFC822Name) == ["issuer@example.com"]
        key_usage = csr.extensions.get_extension_for_class(cx509.KeyUsage)
        assert key_usage.critical and key_usage.value.digital_signature

    async def test_create_csr_san_only(self):
        async with self.profile.session() as session:
            csr = await x509.create_csr(
                session.inject(BaseWallet), self.key_info, dns_names=["a.example"]
            )
        assert len(csr.subject) == 0
        san = csr.extensions.get_extension_for_class(cx509.SubjectAlternativeName)
        assert san.critical

    async def test_create_csr_x_invalid(self):
        async with self.profile.session() as session:
            wallet = session.inject(BaseWallet)
            with pytest.raises(x509.X509Error, match="subject or subject alt"):
                await x509.create_csr(wallet, self.key_info)
            with pytest.raises(x509.X509Error, match="Invalid subject name"):
                await x509.create_csr(wallet, self.key_info, "not a dn")
            with pytest.raises(x509.X509Error, match="alternative name"):
                await x509.create_csr(wallet, self.key_info, emails=["bad\u00e9"])

    async def test_x_unsupported_key_type(self):
        async with self.profile.session() as session:
            wallet = session.inject(BaseWallet)
            ed_key = await wallet.create_key(ED25519)
            with pytest.raises(x509.X509Error, match="not supported for key type"):
                await x509.create_csr(wallet, ed_key, "CN=Issuer")
            with pytest.raises(x509.X509Error, match="not supported for key type"):
                await x509.create_self_signed_certificate(wallet, ed_key, "CN=Issuer")

    async def test_create_self_signed_certificate(self):
        async with self.profile.session() as session:
            cert = await x509.create_self_signed_certificate(
                session.inject(BaseWallet),
                self.key_info,
                "CN=Issuer,C=CA",
                uris=["https://issuer.example.com"],
                validity_days=30,
            )

        cert.verify_directly_issued_by(cert)
        assert cert.subject == cert.issuer
        assert cert.subject.rfc4514_string() == "CN=Issuer,C=CA"
        assert cert.public_key() == self.wallet_public_key()
        assert (cert.not_valid_after_utc - cert.not_valid_before_utc).days == 30
        basic = cert.extensions.get_extension_for_class(cx509.BasicConstraints)
        assert basic.critical and not basic.value.ca
        assert cert.extensions.get_extension_for_class(
            cx509.KeyUsage
        ).value.digital_signature
        assert cert.extensions.get_extension_for_class(cx509.SubjectAlternativeName)
        x509.validate_certificate_chain([cert], self.key_info)

    async def test_create_self_signed_certificate_x_invalid(self):
        async with self.profile.session() as session:
            wallet = session.inject(BaseWallet)
            with pytest.raises(x509.X509Error, match="subject is required"):
                await x509.create_self_signed_certificate(wallet, self.key_info, "")
            with pytest.raises(x509.X509Error, match="at least one day"):
                await x509.create_self_signed_certificate(
                    wallet, self.key_info, "CN=Issuer", validity_days=0
                )

    async def test_x_bad_wallet_signature(self):
        wallet = mock.MagicMock(BaseWallet, autospec=True)
        wallet.sign_message = mock.CoroutineMock(return_value=b"\x01" * 10)
        with pytest.raises(x509.X509Error, match="Unexpected signature length"):
            await x509.create_csr(wallet, self.key_info, "CN=Issuer")

        wallet.sign_message = mock.CoroutineMock(return_value=b"\x01" * 64)
        with pytest.raises(x509.X509Error, match="invalid certificate request"):
            await x509.create_csr(wallet, self.key_info, "CN=Issuer")
        with pytest.raises(x509.X509Error, match="invalid certificate signature"):
            await x509.create_self_signed_certificate(wallet, self.key_info, "CN=Issuer")

    def test_wallet_signing_key_x_tbs_changed(self):
        signing_key = x509._WalletSigningKey(self.wallet_public_key())
        signing_key.sign(b"first", ec.ECDSA(hashes.SHA256()))
        signing_key.signature = b"sig"
        assert signing_key.sign(b"first", ec.ECDSA(hashes.SHA256())) == b"sig"
        with pytest.raises(x509.X509Error, match="changed between signing passes"):
            signing_key.sign(b"second", ec.ECDSA(hashes.SHA256()))
        with pytest.raises(NotImplementedError):
            signing_key.private_bytes(None, None, None)
        with pytest.raises(NotImplementedError):
            signing_key.private_numbers()
        with pytest.raises(NotImplementedError):
            signing_key.exchange(None, None)
        assert signing_key.key_size == 256

    async def test_csr_round_trip_with_ca(self):
        root_key, root_cert = make_ca("Root CA")
        int_key, int_cert = make_ca(
            "Intermediate CA", issuer_key=root_key, issuer_name=root_cert.subject
        )
        async with self.profile.session() as session:
            wallet = session.inject(BaseWallet)
            csr = await x509.create_csr(wallet, self.key_info, "CN=Issuer")
            leaf = issue_from_csr(csr, int_key, int_cert)
            pem = "".join(
                c.public_bytes(serialization.Encoding.PEM).decode()
                for c in (leaf, int_cert, root_cert)
            )
            chain = x509.load_pem_certificate_chain(pem)
            x5c = await x509.store_certificate_chain(wallet, self.key_info, chain)
            stored = await wallet.get_signing_key(self.key_info.verkey)

        assert len(x5c) == 3
        assert x509.get_x5c(stored) == x5c
        assert stored.metadata["note"] == "keep"
        assert cx509.load_der_x509_certificate(base64.b64decode(x5c[0])) == leaf
        assert x509.load_pem_certificate_chain(x509.x5c_to_pem(x5c)) == chain

    async def test_store_certificate_chain_replaces(self):
        async with self.profile.session() as session:
            wallet = session.inject(BaseWallet)
            first = await x509.create_self_signed_certificate(
                wallet, self.key_info, "CN=First"
            )
            await x509.store_certificate_chain(wallet, self.key_info, [first])
            key_info = await wallet.get_signing_key(self.key_info.verkey)
            second = await x509.create_self_signed_certificate(
                wallet, key_info, "CN=Second"
            )
            x5c = await x509.store_certificate_chain(wallet, key_info, [second])
            stored = await wallet.get_signing_key(self.key_info.verkey)

        assert x509.get_x5c(stored) == x5c == x509.certificate_chain_to_x5c([second])

    async def test_kid_changes_preserve_certificate_chain(self):
        async with self.profile.session() as session:
            wallet = session.inject(BaseWallet)
            cert = await x509.create_self_signed_certificate(
                wallet, self.key_info, "CN=Issuer"
            )
            x5c = await x509.store_certificate_chain(wallet, self.key_info, [cert])
            await wallet.assign_kid_to_key(self.key_info.verkey, "kid-1")
            assert x509.get_x5c(await wallet.get_signing_key(self.key_info.verkey)) == x5c
            await wallet.unassign_kid_from_key(self.key_info.verkey, "kid-1")
            assert x509.get_x5c(await wallet.get_signing_key(self.key_info.verkey)) == x5c

    async def test_validate_certificate_chain_x_invalid(self):
        ca_key, ca_cert = make_ca()
        other_key, other_ca = make_ca("Other CA")
        async with self.profile.session() as session:
            csr = await x509.create_csr(
                session.inject(BaseWallet), self.key_info, "CN=Issuer"
            )

        with pytest.raises(x509.X509Error, match="empty"):
            x509.validate_certificate_chain([], self.key_info)

        with pytest.raises(x509.X509Error, match="does not match the wallet key"):
            x509.validate_certificate_chain([ca_cert], self.key_info)

        expired = issue_from_csr(
            csr,
            ca_key,
            ca_cert,
            not_valid_after=datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(days=1),
        )
        with pytest.raises(x509.X509Error, match="expired"):
            x509.validate_certificate_chain([expired, ca_cert], self.key_info)

        no_signing = issue_from_csr(
            csr,
            ca_key,
            ca_cert,
            key_usage=cx509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
        )
        with pytest.raises(x509.X509Error, match="key usage"):
            x509.validate_certificate_chain([no_signing, ca_cert], self.key_info)

        leaf = issue_from_csr(csr, ca_key, ca_cert)
        x509.validate_certificate_chain([leaf, ca_cert], self.key_info)
        with pytest.raises(x509.X509Error, match="not issued by"):
            x509.validate_certificate_chain([leaf, other_ca], self.key_info)
        with pytest.raises(x509.X509Error, match="does not match"):
            x509.validate_certificate_chain([ca_cert, leaf], self.key_info)

    def test_load_pem_certificate_chain_x_invalid(self):
        with pytest.raises(x509.X509Error, match="Invalid PEM"):
            x509.load_pem_certificate_chain("not a certificate")
        with pytest.raises(x509.X509Error, match="Invalid PEM"):
            x509.load_pem_certificate_chain("")
