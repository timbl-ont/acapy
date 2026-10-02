from typing import Tuple
from unittest import IsolatedAsyncioTestCase

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from acapy_agent.resolver.default.key import KeyDIDResolver

from ...resolver.did_resolver import DIDResolver
from ...resolver.tests.test_did_resolver import MockResolver
from ...utils.testing import create_test_profile
from ...wallet.did_method import KEY, DIDMethods
from ...wallet.key_type import ED25519, P256, KeyType, KeyTypes
from .. import x509
from ..base import BaseWallet
from ..default_verification_key_strategy import (
    BaseVerificationKeyStrategy,
    DefaultVerificationKeyStrategy,
)
from ..jwt import b64_to_dict, jwt_sign, jwt_verify
from ..util import b64_to_bytes


class TestJWT(IsolatedAsyncioTestCase):
    """Tests for JWT sign and verify using dids."""

    seed = "testseed000000000000000000000001"
    did_key_ed25519_did = "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL"
    did_key_ed25519_verification_method = "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL#z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL"
    did_key_ed25519_doc = {
        "@context": "https://www.w3.org/ns/did/v1",
        "id": "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL",
        "verificationMethod": [
            {
                "id": "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL#z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL",
                "type": "Ed25519VerificationKey2018",
                "controller": "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL",
                "publicKeyBase58": "3Dn1SJNPaCXcvvJvSbsFWP2xaCjMom3can8CQNhWrTRx",
            }
        ],
        "authentication": [
            "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL#z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL"
        ],
        "assertionMethod": [
            "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL#z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL"
        ],
        "capabilityDelegation": [
            "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL#z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL"
        ],
        "capabilityInvocation": [
            "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL#z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL"
        ],
        "keyAgreement": [
            {
                "id": "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL#z6LSbkodSr6SU2trs8VUgnrnWtSm7BAPG245ggrBmSrxbv1R",
                "type": "X25519KeyAgreementKey2019",
                "controller": "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL",
                "publicKeyBase58": "5dTvYHaNaB7mk7iA9LqCJEHG2dGZQsvoi8WGzDRtYEf",
            }
        ],
    }
    did_key_p256_did = "did:key:zDnaehWviigWQQD7bqF3btFquwA5w8DX2sQwkVxnAyJ7oxdjq"
    did_key_p256_verification_method = "did:key:zDnaehWviigWQQD7bqF3btFquwA5w8DX2sQwkVxnAyJ7oxdjq#zDnaehWviigWQQD7bqF3btFquwA5w8DX2sQwkVxnAyJ7oxdjq"
    did_key_p256_doc = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/multikey/v1",
        ],
        "id": "did:key:zDnaehWviigWQQD7bqF3btFquwA5w8DX2sQwkVxnAyJ7oxdjq",
        "verificationMethod": [
            {
                "id": "did:key:zDnaehWviigWQQD7bqF3btFquwA5w8DX2sQwkVxnAyJ7oxdjq#zDnaehWviigWQQD7bqF3btFquwA5w8DX2sQwkVxnAyJ7oxdjq",
                "type": "Multikey",
                "controller": "did:key:zDnaehWviigWQQD7bqF3btFquwA5w8DX2sQwkVxnAyJ7oxdjq",
                "publicKeyMultibase": "zDnaehWviigWQQD7bqF3btFquwA5w8DX2sQwkVxnAyJ7oxdjq",
            }
        ],
        "authentication": [
            "did:key:zDnaehWviigWQQD7bqF3btFquwA5w8DX2sQwkVxnAyJ7oxdjq#zDnaehWviigWQQD7bqF3btFquwA5w8DX2sQwkVxnAyJ7oxdjq"
        ],
        "assertionMethod": [
            "did:key:zDnaehWviigWQQD7bqF3btFquwA5w8DX2sQwkVxnAyJ7oxdjq#zDnaehWviigWQQD7bqF3btFquwA5w8DX2sQwkVxnAyJ7oxdjq"
        ],
        "capabilityDelegation": [
            "did:key:zDnaehWviigWQQD7bqF3btFquwA5w8DX2sQwkVxnAyJ7oxdjq#zDnaehWviigWQQD7bqF3btFquwA5w8DX2sQwkVxnAyJ7oxdjq"
        ],
        "capabilityInvocation": [
            "did:key:zDnaehWviigWQQD7bqF3btFquwA5w8DX2sQwkVxnAyJ7oxdjq#zDnaehWviigWQQD7bqF3btFquwA5w8DX2sQwkVxnAyJ7oxdjq"
        ],
        "keyAgreement": [],
    }

    async def asyncSetUp(self):
        self.profile = await create_test_profile()
        self.profile.context.injector.bind_instance(DIDMethods, DIDMethods())
        self.profile.context.injector.bind_instance(
            BaseVerificationKeyStrategy, DefaultVerificationKeyStrategy()
        )
        self.profile.context.injector.bind_instance(KeyTypes, KeyTypes())
        self.profile.context.injector.bind_instance(
            DIDResolver, DIDResolver([KeyDIDResolver()])
        )

    async def setUpTestingDid(self, key_type: KeyType) -> Tuple[str, str]:
        async with self.profile.session() as session:
            wallet = session.inject(BaseWallet)
            await wallet.create_local_did(KEY, key_type, self.seed)

        if key_type == P256:
            did = self.did_key_p256_did
            vm_id = self.did_key_p256_verification_method
            did_doc = self.did_key_p256_doc
        elif key_type == ED25519:
            did = self.did_key_ed25519_did
            vm_id = self.did_key_ed25519_verification_method
            did_doc = self.did_key_ed25519_doc

        resolver = DIDResolver()
        resolver.register_resolver(
            MockResolver(
                ["key"],
                resolved=did_doc,
                native=True,
            )
        )
        self.profile.context.injector.bind_instance(DIDResolver, resolver)

        return (did, vm_id)

    async def test_sign_with_did_key_and_verify(self):
        for key_type in [ED25519, P256]:
            (did, _) = await self.setUpTestingDid(key_type)
            verification_method = None

            headers = {}
            payload = {}
            signed = await jwt_sign(
                self.profile, headers, payload, did, verification_method
            )

            assert signed

            assert await jwt_verify(self.profile, signed)

    async def test_sign_with_verification_method_and_verify(self):
        for key_type in [ED25519, P256]:
            (_, verification_method) = await self.setUpTestingDid(key_type)
            did = None
            headers = {}
            payload = {}
            signed: str = await jwt_sign(
                self.profile, headers, payload, did, verification_method
            )

            assert signed

            assert await jwt_verify(self.profile, signed)

    async def test_sign_x_invalid_did(self):
        did = "did:key:zzzzgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL"
        headers = {}
        payload = {}
        verification_method = None
        with pytest.raises(Exception) as e_info:
            await jwt_sign(self.profile, headers, payload, did, verification_method)
        assert "No key type for prefixed public key" in str(e_info)

    async def test_sign_x_invalid_verification_method(self):
        did = None
        headers = {}
        payload = {}
        verification_method = "did:key:zzzzgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL#z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL"
        with pytest.raises(Exception) as e_info:
            await jwt_sign(self.profile, headers, payload, did, verification_method)
        assert "DIDNotFound" in str(e_info)

    async def test_verify_x_invalid_signed(self):
        for key_type in [ED25519, P256]:
            (did, _) = await self.setUpTestingDid(key_type)
            verification_method = None

            headers = {}
            payload = {}
            signed = await jwt_sign(
                self.profile, headers, payload, did, verification_method
            )

            assert signed
            signed = f"{signed[:-2]}2"

            with pytest.raises(Exception):
                await jwt_verify(self.profile, signed)

    async def test_sign_with_x5c(self):
        (did, vm_id) = await self.setUpTestingDid(P256)
        async with self.profile.session() as session:
            wallet = session.inject(BaseWallet)
            key_info = await wallet.get_signing_key(
                (await wallet.get_local_did(did)).verkey
            )
            certificate = await x509.create_self_signed_certificate(
                wallet, key_info, "CN=Issuer"
            )
            x5c = await x509.store_certificate_chain(wallet, key_info, [certificate])

        signed = await jwt_sign(self.profile, {}, {"a": 1}, did, include_x5c=True)
        encoded_headers, encoded_payload, encoded_sig = signed.split(".")
        headers = b64_to_dict(encoded_headers)
        assert headers["x5c"] == x5c
        assert headers["kid"] == vm_id
        assert headers["alg"] == "ES256"

        # The signature verifies against the certificate public key
        sig = b64_to_bytes(encoded_sig, urlsafe=True)
        certificate.public_key().verify(
            encode_dss_signature(
                int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
            ),
            f"{encoded_headers}.{encoded_payload}".encode(),
            ec.ECDSA(hashes.SHA256()),
        )
        assert await jwt_verify(self.profile, signed)

        signed = await jwt_sign(self.profile, {}, {"a": 1}, did)
        assert "x5c" not in b64_to_dict(signed.split(".")[0])

    async def test_sign_with_x5c_x_no_certificate(self):
        (did, _) = await self.setUpTestingDid(P256)
        with pytest.raises(x509.X509Error, match="No X.509 certificate chain"):
            await jwt_sign(self.profile, {}, {}, did, include_x5c=True)
