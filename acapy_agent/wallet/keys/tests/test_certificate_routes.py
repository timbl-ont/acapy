import json
from unittest import IsolatedAsyncioTestCase

from cryptography import x509 as cx509
from cryptography.hazmat.primitives import serialization

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.tests import mock
from acapy_agent.utils.testing import create_test_profile
from acapy_agent.wallet import x509
from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.key_type import ED25519, P256, KeyTypes
from acapy_agent.wallet.keys import routes as test_module
from acapy_agent.wallet.keys.manager import verkey_to_multikey
from acapy_agent.wallet.tests.test_x509 import issue_from_csr, make_ca


class TestKeyCertificateRoutes(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.profile = await create_test_profile(
            settings={"admin.admin_api_key": "secret-key"},
        )
        self.profile.context.injector.bind_instance(KeyTypes, KeyTypes())
        async with self.profile.session() as session:
            key = await session.inject(BaseWallet).create_key(P256)
        self.verkey = key.verkey
        self.multikey = verkey_to_multikey(key.verkey, alg="p256")

        self.context = AdminRequestContext.test_context({}, self.profile)
        self.request_dict = {"context": self.context}
        self.request = mock.MagicMock(
            app={},
            match_info={"multikey": self.multikey},
            query={},
            __getitem__=lambda _, k: self.request_dict[k],
            headers={"x-api-key": "secret-key"},
        )

    def set_body(self, body: dict):
        self.request.json = mock.CoroutineMock(return_value=body)

    async def call(self, handler):
        response = await handler(self.request)
        return response.status, json.loads(response.body)

    async def test_create_csr(self):
        self.set_body({"subject": "CN=Issuer", "dns_names": ["issuer.example.com"]})
        status, body = await self.call(test_module.create_key_csr)

        assert status == 200
        assert body["multikey"] == self.multikey
        csr = cx509.load_pem_x509_csr(body["csr"].encode())
        assert csr.is_signature_valid
        assert csr.subject.rfc4514_string() == "CN=Issuer"

    async def test_create_csr_x_invalid(self):
        self.set_body({"subject": "not a dn"})
        status, body = await self.call(test_module.create_key_csr)
        assert status == 400
        assert "Invalid subject name" in body["message"]

        async with self.profile.session() as session:
            ed_key = await session.inject(BaseWallet).create_key(ED25519)
        self.request.match_info["multikey"] = verkey_to_multikey(
            ed_key.verkey, alg="ed25519"
        )
        self.set_body({"subject": "CN=Issuer"})
        status, body = await self.call(test_module.create_key_csr)
        assert status == 400
        assert "not supported for key type" in body["message"]

    async def test_x_invalid_multikey(self):
        self.request.match_info["multikey"] = "not-a-multikey"
        self.set_body({"subject": "CN=Issuer"})
        status, body = await self.call(test_module.create_key_csr)
        assert status == 400
        assert "Invalid multikey" in body["message"]

    async def test_x_unknown_key(self):
        other_profile = await create_test_profile()
        other_profile.context.injector.bind_instance(KeyTypes, KeyTypes())
        async with other_profile.session() as session:
            other = await session.inject(BaseWallet).create_key(P256)
        self.request.match_info["multikey"] = verkey_to_multikey(other.verkey, alg="p256")
        self.set_body({"subject": "CN=Issuer"})

        for handler in (
            test_module.create_key_csr,
            test_module.create_key_self_signed_certificate,
            test_module.fetch_key_certificate,
        ):
            status, _ = await self.call(handler)
            assert status == 404

    async def test_self_signed_certificate_and_fetch(self):
        status, body = await self.call(test_module.fetch_key_certificate)
        assert status == 404

        self.set_body({"subject": "CN=Issuer,C=CA", "validity_days": 10})
        status, created = await self.call(test_module.create_key_self_signed_certificate)
        assert status == 200
        assert created["multikey"] == self.multikey
        assert len(created["x5c"]) == 1
        cert = cx509.load_pem_x509_certificate(created["certificate_chain"].encode())
        assert cert.subject == cert.issuer
        assert (cert.not_valid_after_utc - cert.not_valid_before_utc).days == 10

        status, fetched = await self.call(test_module.fetch_key_certificate)
        assert status == 200
        assert fetched == created

    async def test_self_signed_certificate_x_invalid(self):
        self.set_body({"subject": ""})
        status, body = await self.call(test_module.create_key_self_signed_certificate)
        assert status == 400
        assert "subject is required" in body["message"]

    async def test_import_certificate(self):
        ca_key, ca_cert = make_ca()
        async with self.profile.session() as session:
            wallet = session.inject(BaseWallet)
            csr = await x509.create_csr(
                wallet, await wallet.get_signing_key(self.verkey), "CN=Issuer"
            )
        leaf = issue_from_csr(csr, ca_key, ca_cert)
        pem = "".join(
            c.public_bytes(serialization.Encoding.PEM).decode() for c in (leaf, ca_cert)
        )

        self.set_body({"certificate_chain": pem})
        status, body = await self.call(test_module.import_key_certificate)
        assert status == 200
        assert body["certificate_chain"] == pem
        assert body["x5c"] == x509.certificate_chain_to_x5c([leaf, ca_cert])

        status, fetched = await self.call(test_module.fetch_key_certificate)
        assert status == 200
        assert fetched["x5c"] == body["x5c"]

    async def test_import_certificate_x_invalid(self):
        self.set_body({"certificate_chain": "garbage"})
        status, body = await self.call(test_module.import_key_certificate)
        assert status == 400
        assert "Invalid PEM" in body["message"]

        _, ca_cert = make_ca()
        self.set_body(
            {
                "certificate_chain": ca_cert.public_bytes(
                    serialization.Encoding.PEM
                ).decode()
            }
        )
        status, body = await self.call(test_module.import_key_certificate)
        assert status == 400
        assert "does not match the wallet key" in body["message"]

    async def test_register(self):
        mock_app = mock.MagicMock()
        mock_app.add_routes = mock.MagicMock()
        await test_module.register(mock_app)
        paths = {route.path for route in mock_app.add_routes.call_args[0][0]}
        assert "/wallet/keys/{multikey}/csr" in paths
        assert "/wallet/keys/{multikey}/self-signed-certificate" in paths
        assert "/wallet/keys/{multikey}/certificate" in paths
