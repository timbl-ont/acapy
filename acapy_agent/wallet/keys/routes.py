"""Key admin routes."""

import logging

from aiohttp import web
from aiohttp_apispec import docs, match_info_schema, request_schema, response_schema
from cryptography.hazmat.primitives import serialization
from marshmallow import fields, validate

from ...admin.decorators.auth import tenant_authentication
from ...admin.request_context import AdminRequestContext
from ...core.profile import ProfileSession
from ...messaging.models.openapi import OpenAPISchema
from ...wallet.error import WalletDuplicateError, WalletError, WalletNotFoundError
from .. import x509
from ..base import BaseWallet
from ..did_info import KeyInfo
from ..routes import WALLET_TAG_TITLE
from .manager import (
    DEFAULT_ALG,
    MultikeyManager,
    MultikeyManagerError,
    multikey_to_verkey,
)

LOGGER = logging.getLogger(__name__)

MULTIKEY_EXAMPLE = "zDnaeSd75MAwSRmem34MfZEzSMjQNcpWLmzkbF8Su49AuA9U2"


class CreateKeyRequestSchema(OpenAPISchema):
    """Request schema for creating a new key."""

    alg = fields.Str(
        required=False,
        metadata={
            "description": "Which key algorithm to use.",
            "example": DEFAULT_ALG,
        },
    )

    seed = fields.Str(
        required=False,
        metadata={
            "description": (
                "Optional seed to generate the key pair. "
                "Must enable insecure wallet mode."
            ),
            "example": "00000000000000000000000000000000",
        },
    )

    kid = fields.Str(
        required=False,
        metadata={
            "description": (
                "Optional kid to bind to the keypair, such as a verificationMethod."
            ),
            "example": "did:web:example.com#key-01",
        },
    )


class CreateKeyResponseSchema(OpenAPISchema):
    """Response schema from creating a new key."""

    multikey = fields.Str(
        metadata={
            "description": "The Public Key Multibase format (multikey)",
            "example": "z6MkgKA7yrw5kYSiDuQFcye4bMaJpcfHFry3Bx45pdWh3s8i",
        },
    )

    kid = fields.Str(
        metadata={
            "description": "The associated kid",
            "example": "did:web:example.com#key-01",
        },
    )


class UpdateKeyRequestSchema(OpenAPISchema):
    """Request schema for updating an existing key pair."""

    multikey = fields.Str(
        required=True,
        metadata={
            "description": "Multikey of the key pair to update",
            "example": "z6MkgKA7yrw5kYSiDuQFcye4bMaJpcfHFry3Bx45pdWh3s8i",
        },
    )

    kid = fields.Str(
        required=True,
        metadata={
            "description": (
                "New kid to bind to the key pair, such as a verificationMethod."
            ),
            "example": "did:web:example.com#key-02",
        },
    )


class UpdateKeyResponseSchema(OpenAPISchema):
    """Response schema from updating an existing key pair."""

    multikey = fields.Str(
        metadata={
            "description": "The Public Key Multibase format (multikey)",
            "example": "z6MkgKA7yrw5kYSiDuQFcye4bMaJpcfHFry3Bx45pdWh3s8i",
        },
    )

    kid = fields.Str(
        metadata={
            "description": "The associated kid",
            "example": "did:web:example.com#key-02",
        },
    )


class FetchKeyResponseSchema(OpenAPISchema):
    """Response schema from updating an existing key pair."""

    multikey = fields.Str(
        metadata={
            "description": "The Public Key Multibase format (multikey)",
            "example": "z6MkgKA7yrw5kYSiDuQFcye4bMaJpcfHFry3Bx45pdWh3s8i",
        },
    )

    kid = fields.Str(
        metadata={
            "description": "The associated kid",
            "example": "did:web:example.com#key-01",
        },
    )


class KeyMultikeyMatchInfoSchema(OpenAPISchema):
    """Path parameters for routes addressing a key by multikey."""

    multikey = fields.Str(
        required=True,
        metadata={
            "description": "The Public Key Multibase format (multikey)",
            "example": MULTIKEY_EXAMPLE,
        },
    )


class CertificateSubjectSchema(OpenAPISchema):
    """Subject and subject alternative names for an X.509 certificate."""

    subject = fields.Str(
        required=False,
        metadata={
            "description": "Subject distinguished name (RFC 4514)",
            "example": "CN=Example Issuer,O=Example Org,C=CA",
        },
    )
    dns_names = fields.List(
        fields.Str(),
        required=False,
        metadata={
            "description": "DNS names for the subject alternative name extension",
            "example": ["issuer.example.com"],
        },
    )
    uris = fields.List(
        fields.Str(),
        required=False,
        metadata={
            "description": "URIs for the subject alternative name extension",
            "example": ["https://issuer.example.com"],
        },
    )
    emails = fields.List(
        fields.Str(),
        required=False,
        metadata={
            "description": "Email addresses for the subject alternative name extension",
            "example": ["issuer@example.com"],
        },
    )


class CreateCsrRequestSchema(CertificateSubjectSchema):
    """Request schema for creating a certificate signing request."""


class CreateCsrResponseSchema(OpenAPISchema):
    """Response schema for creating a certificate signing request."""

    multikey = fields.Str(
        metadata={
            "description": "The Public Key Multibase format (multikey)",
            "example": MULTIKEY_EXAMPLE,
        },
    )
    csr = fields.Str(
        metadata={
            "description": "PEM encoded PKCS #10 certificate signing request",
            "example": (
                "-----BEGIN CERTIFICATE REQUEST-----\n...\n"
                "-----END CERTIFICATE REQUEST-----\n"
            ),
        },
    )


class CreateSelfSignedCertificateRequestSchema(CertificateSubjectSchema):
    """Request schema for creating a self-signed certificate."""

    subject = fields.Str(
        required=True,
        metadata={
            "description": "Subject and issuer distinguished name (RFC 4514)",
            "example": "CN=Example Issuer,O=Example Org,C=CA",
        },
    )
    validity_days = fields.Int(
        required=False,
        load_default=x509.DEFAULT_VALIDITY_DAYS,
        validate=validate.Range(min=1),
        metadata={
            "description": "Number of days the certificate is valid for",
            "example": x509.DEFAULT_VALIDITY_DAYS,
        },
    )


class ImportCertificateRequestSchema(OpenAPISchema):
    """Request schema for importing a certificate chain for a key."""

    certificate_chain = fields.Str(
        required=True,
        metadata={
            "description": (
                "PEM encoded certificate chain, leaf certificate first. The leaf "
                "certificate must certify this key."
            ),
            "example": ("-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"),
        },
    )


class CertificateResponseSchema(OpenAPISchema):
    """Response schema for a key's certificate chain."""

    multikey = fields.Str(
        metadata={
            "description": "The Public Key Multibase format (multikey)",
            "example": MULTIKEY_EXAMPLE,
        },
    )
    certificate_chain = fields.Str(
        metadata={
            "description": "PEM encoded certificate chain, leaf certificate first",
            "example": ("-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"),
        },
    )
    x5c = fields.List(
        fields.Str(),
        metadata={
            "description": (
                "Certificate chain as a JWS x5c header value (base64 DER, leaf first)"
            ),
        },
    )


async def _get_signing_key(session: ProfileSession, multikey: str) -> KeyInfo:
    try:
        verkey = multikey_to_verkey(multikey)
    except (MultikeyManagerError, ValueError) as err:
        raise MultikeyManagerError(f"Invalid multikey '{multikey}'") from err
    return await session.inject(BaseWallet).get_signing_key(verkey)


def _error_response(err: Exception) -> web.Response:
    status = 404 if isinstance(err, WalletNotFoundError) else 400
    return web.json_response({"message": str(err)}, status=status)


def _certificate_response(multikey: str, x5c: list) -> web.Response:
    return web.json_response(
        {
            "multikey": multikey,
            "certificate_chain": x509.x5c_to_pem(x5c),
            "x5c": x5c,
        },
        status=200,
    )


@docs(tags=[WALLET_TAG_TITLE], summary="Fetch key info.")
@response_schema(FetchKeyResponseSchema, 200, description="")
@tenant_authentication
async def fetch_key(request: web.BaseRequest):
    """Request handler for fetching a key.

    Args:
        request: aiohttp request object

    """
    context: AdminRequestContext = request["context"]
    multikey = request.match_info["multikey"]

    try:
        async with context.session() as session:
            key_info = await MultikeyManager(session).from_multikey(multikey=multikey)
        return web.json_response(
            key_info,
            status=200,
        )

    except (MultikeyManagerError, WalletDuplicateError, WalletNotFoundError) as err:
        return web.json_response({"message": str(err)}, status=400)


@docs(tags=[WALLET_TAG_TITLE], summary="Create a key pair")
@request_schema(CreateKeyRequestSchema())
@response_schema(CreateKeyResponseSchema, 200, description="")
@tenant_authentication
async def create_key(request: web.BaseRequest):
    """Request handler for creating a new key pair in the wallet.

    Args:
        request: aiohttp request object

    Returns:
        The Public Key Multibase format (multikey)

    """
    context: AdminRequestContext = request["context"]
    body = await request.json()

    seed = body.get("seed") or None
    kid = body.get("kid") or None
    alg = body.get("alg") or DEFAULT_ALG

    if seed and not context.settings.get("wallet.allow_insecure_seed"):
        raise MultikeyManagerError("Seed support is not enabled.")

    try:
        async with context.session() as session:
            key_info = await MultikeyManager(session).create(seed=seed, kid=kid, alg=alg)
        return web.json_response(
            key_info,
            status=201,
        )
    except (MultikeyManagerError, WalletDuplicateError, WalletNotFoundError) as err:
        return web.json_response({"message": str(err)}, status=400)


@docs(tags=[WALLET_TAG_TITLE], summary="Update a key pair's kid")
@request_schema(UpdateKeyRequestSchema())
@response_schema(UpdateKeyResponseSchema, 200, description="")
@tenant_authentication
async def update_key(request: web.BaseRequest):
    """Request handler for creating a new key pair in the wallet.

    Args:
        request: aiohttp request object

    Returns:
        The Public Key Multibase format (multikey)

    """
    context: AdminRequestContext = request["context"]
    body = await request.json()

    multikey = body.get("multikey")
    kid = body.get("kid")

    try:
        async with context.session() as session:
            key_info = await MultikeyManager(session).update(
                multikey=multikey,
                kid=kid,
            )
        return web.json_response(
            key_info,
            status=200,
        )
    except (MultikeyManagerError, WalletDuplicateError, WalletNotFoundError) as err:
        return web.json_response({"message": str(err)}, status=400)


@docs(
    tags=[WALLET_TAG_TITLE],
    summary="Create an X.509 certificate signing request (CSR) for a key",
)
@match_info_schema(KeyMultikeyMatchInfoSchema())
@request_schema(CreateCsrRequestSchema())
@response_schema(CreateCsrResponseSchema(), 200, description="")
@tenant_authentication
async def create_key_csr(request: web.BaseRequest):
    """Request handler for creating a CSR signed by a wallet key.

    Args:
        request: aiohttp request object

    Returns:
        The PEM encoded certificate signing request

    """
    context: AdminRequestContext = request["context"]
    multikey = request.match_info["multikey"]
    body = await request.json()

    try:
        async with context.session() as session:
            key_info = await _get_signing_key(session, multikey)
            csr = await x509.create_csr(
                session.inject(BaseWallet),
                key_info,
                body.get("subject"),
                dns_names=body.get("dns_names"),
                uris=body.get("uris"),
                emails=body.get("emails"),
            )
    except (MultikeyManagerError, WalletError) as err:
        return _error_response(err)

    return web.json_response(
        {
            "multikey": multikey,
            "csr": csr.public_bytes(serialization.Encoding.PEM).decode(),
        },
        status=200,
    )


@docs(
    tags=[WALLET_TAG_TITLE],
    summary="Create and store a self-signed X.509 certificate for a key",
)
@match_info_schema(KeyMultikeyMatchInfoSchema())
@request_schema(CreateSelfSignedCertificateRequestSchema())
@response_schema(CertificateResponseSchema(), 200, description="")
@tenant_authentication
async def create_key_self_signed_certificate(request: web.BaseRequest):
    """Request handler for creating a self-signed certificate for a wallet key.

    The certificate replaces any certificate chain stored for the key.

    Args:
        request: aiohttp request object

    Returns:
        The stored certificate chain

    """
    context: AdminRequestContext = request["context"]
    multikey = request.match_info["multikey"]
    body = await request.json()

    try:
        async with context.session() as session:
            wallet = session.inject(BaseWallet)
            key_info = await _get_signing_key(session, multikey)
            certificate = await x509.create_self_signed_certificate(
                wallet,
                key_info,
                body.get("subject"),
                dns_names=body.get("dns_names"),
                uris=body.get("uris"),
                emails=body.get("emails"),
                validity_days=body.get("validity_days", x509.DEFAULT_VALIDITY_DAYS),
            )
            x5c = await x509.store_certificate_chain(wallet, key_info, [certificate])
    except (MultikeyManagerError, WalletError) as err:
        return _error_response(err)

    return _certificate_response(multikey, x5c)


@docs(
    tags=[WALLET_TAG_TITLE],
    summary="Import an X.509 certificate chain for a key",
)
@match_info_schema(KeyMultikeyMatchInfoSchema())
@request_schema(ImportCertificateRequestSchema())
@response_schema(CertificateResponseSchema(), 200, description="")
@tenant_authentication
async def import_key_certificate(request: web.BaseRequest):
    """Request handler for importing a certificate chain for a wallet key.

    Typically used to import the certificate issued for a CSR. The chain replaces
    any certificate chain stored for the key.

    Args:
        request: aiohttp request object

    Returns:
        The stored certificate chain

    """
    context: AdminRequestContext = request["context"]
    multikey = request.match_info["multikey"]
    body = await request.json()

    try:
        chain = x509.load_pem_certificate_chain(body.get("certificate_chain") or "")
        async with context.session() as session:
            key_info = await _get_signing_key(session, multikey)
            x5c = await x509.store_certificate_chain(
                session.inject(BaseWallet), key_info, chain
            )
    except (MultikeyManagerError, WalletError) as err:
        return _error_response(err)

    return _certificate_response(multikey, x5c)


@docs(
    tags=[WALLET_TAG_TITLE],
    summary="Fetch the X.509 certificate chain stored for a key",
)
@match_info_schema(KeyMultikeyMatchInfoSchema())
@response_schema(CertificateResponseSchema(), 200, description="")
@tenant_authentication
async def fetch_key_certificate(request: web.BaseRequest):
    """Request handler for fetching the certificate chain stored for a wallet key.

    Args:
        request: aiohttp request object

    Returns:
        The stored certificate chain

    """
    context: AdminRequestContext = request["context"]
    multikey = request.match_info["multikey"]

    try:
        async with context.session() as session:
            key_info = await _get_signing_key(session, multikey)
    except (MultikeyManagerError, WalletError) as err:
        return _error_response(err)

    x5c = x509.get_x5c(key_info)
    if not x5c:
        return web.json_response(
            {"message": f"No certificate chain stored for key {multikey}"}, status=404
        )
    return _certificate_response(multikey, x5c)


async def register(app: web.Application):
    """Register routes."""
    app.add_routes(
        [
            web.get("/wallet/keys/{multikey}", fetch_key, allow_head=False),
            web.post("/wallet/keys", create_key),
            web.put("/wallet/keys", update_key),
            web.post("/wallet/keys/{multikey}/csr", create_key_csr),
            web.post(
                "/wallet/keys/{multikey}/self-signed-certificate",
                create_key_self_signed_certificate,
            ),
            web.put("/wallet/keys/{multikey}/certificate", import_key_certificate),
            web.get(
                "/wallet/keys/{multikey}/certificate",
                fetch_key_certificate,
                allow_head=False,
            ),
        ]
    )
