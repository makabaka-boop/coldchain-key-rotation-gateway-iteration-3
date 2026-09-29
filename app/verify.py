"""Gateway message verification.

v1 (legacy): Ed25519 over the raw request body; every accepted request mints
a fresh receipt.

v2 (optional, idempotent): the signature covers a canonical string binding
the protocol domain, tenant, key id, message id and a SHA-256 digest of the
request body. The first accepted (tenant, messageId) mints one immutable
receipt; a byte-identical retry returns that receipt forever (even after the
key retires); a reused id with different content/key/signature is a 409
conflict that reveals nothing about the stored message.
"""
import hashlib
import re
import uuid

import asyncpg
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from . import db
from .auth import require
from .config import MAX_BODY_BYTES
from .errors import ApiError
from .util import b64url_decode_unpadded

# Separate routers so v1's wire contract stays exactly as it was.
router = APIRouter(tags=["verify"])
router_v2 = APIRouter(tags=["verify"])

# Domain separator embedded in every v2 signature: it fixes the protocol
# version and keeps a v2 signature from being replayed against any other
# signed surface (v1 raw-body verification, PoP challenges).
V2_DOMAIN = "coldchain-verify-v2"

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


async def _read_body(request: Request) -> bytes:
    """Read at most MAX_BODY_BYTES; anything larger is a 413."""
    content_length = request.headers.get("content-length")
    try:
        declared = int(content_length) if content_length is not None else None
    except ValueError:
        declared = None
    if declared is not None and declared > MAX_BODY_BYTES:
        raise ApiError(413, "PAYLOAD_TOO_LARGE", limit=MAX_BODY_BYTES)
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_BODY_BYTES:
            raise ApiError(413, "PAYLOAD_TOO_LARGE", limit=MAX_BODY_BYTES)
        chunks.append(chunk)
    return b"".join(chunks)


def v2_signed_message(
    tenant_id: str, key_id: str, message_id: str, body_digest: bytes
) -> bytes:
    """Exact bytes signed for a v2 verification request.

    The digest is the lowercase hex SHA-256 of the raw request body, so the
    signature binds domain + tenant + key + message id + body without the
    verifier having to sign the (possibly 1 MiB) payload itself.
    """
    return (
        V2_DOMAIN.encode("ascii")
        + f"\ntenant={tenant_id}".encode()
        + f"\nkey={key_id}".encode()
        + f"\nmessage={message_id}".encode()
        + b"\nsha256="
        + body_digest.hex().encode("ascii")
    )


def _v2_headers(request: Request) -> tuple[str, str, str, str]:
    tenant_id = request.headers.get("x-tenant-id")
    key_id = request.headers.get("x-key-id")
    message_id = request.headers.get("x-message-id")
    signature_b64 = request.headers.get("x-signature")
    if not tenant_id or not key_id or not message_id or not signature_b64:
        raise ApiError(
            400, "BAD_REQUEST",
            detail="X-Tenant-Id, X-Key-Id, X-Message-Id and X-Signature headers"
            " are required",
        )
    if not _ID_RE.fullmatch(tenant_id):
        raise ApiError(400, "BAD_REQUEST", field="tenantId")
    if not _ID_RE.fullmatch(message_id):
        raise ApiError(400, "BAD_REQUEST", field="messageId")
    return tenant_id, key_id, message_id, signature_b64


@router.post("/verify")
async def verify_message(request: Request, _: None = Depends(require("verify"))):
    tenant_id = request.headers.get("x-tenant-id")
    key_id = request.headers.get("x-key-id")
    signature_b64 = request.headers.get("x-signature")
    if not tenant_id or not key_id or not signature_b64:
        raise ApiError(
            400, "BAD_REQUEST",
            detail="X-Tenant-Id, X-Key-Id and X-Signature headers are required",
        )

    body = await _read_body(request)

    async with db.pool.acquire() as conn:
        # The role read below is the ordering point against a concurrent
        # retire: a snapshot taken before the retire commits may still verify;
        # one taken after observes 'retired' and fails with KEY_RETIRED.
        row = await conn.fetchrow(
            "SELECT role, public_key FROM tenant_keys WHERE tenant_id = $1 AND key_id = $2",
            tenant_id, key_id,
        )
        if row is None:
            # Unknown key ids and other tenants' keys are indistinguishable.
            raise ApiError(404, "KEY_UNKNOWN")
        if row["role"] == "retired":
            raise ApiError(410, "KEY_RETIRED")

        signature = b64url_decode_unpadded(signature_b64, error_code="BAD_SIGNATURE")
        if len(signature) != 64:
            raise ApiError(400, "BAD_SIGNATURE")
        try:
            Ed25519PublicKey.from_public_bytes(bytes(row["public_key"])).verify(signature, body)
        except InvalidSignature:
            raise ApiError(400, "BAD_SIGNATURE") from None

        receipt_id = uuid.uuid4()
        await conn.execute(
            "INSERT INTO receipts (receipt_id, tenant_id, key_id, body_sha256, body_size)"
            " VALUES ($1, $2, $3, $4, $5)",
            receipt_id, tenant_id, key_id, hashlib.sha256(body).digest(), len(body),
        )

    return JSONResponse({"receiptId": str(receipt_id)}, status_code=202)


@router_v2.post("/verify")
async def verify_message_v2(request: Request, _: None = Depends(require("verify"))):
    tenant_id, key_id, message_id, signature_b64 = _v2_headers(request)

    # Malformed signatures are rejected before any state lookup or write:
    # they must never create a placeholder row or probe for an existing id.
    signature = b64url_decode_unpadded(signature_b64, error_code="BAD_SIGNATURE")
    if len(signature) != 64:
        raise ApiError(400, "BAD_SIGNATURE")

    body = await _read_body(request)
    body_digest = hashlib.sha256(body).digest()
    signed_message = v2_signed_message(tenant_id, key_id, message_id, body_digest)
    receipt_id: uuid.UUID | None = None

    async with db.pool.acquire() as conn:
        try:
            async with conn.transaction():
                # Serialize first-vs-retry adjudication for this exact
                # (tenant, message) within the transaction; the unique
                # constraint below remains the durable backstop across
                # instances and lock-key collisions.
                await conn.execute(
                    "SELECT pg_advisory_xact_lock(hashtext('v2_receipts'),"
                    " hashtext($1 || E'\\x1f' || $2))",
                    tenant_id, message_id,
                )

                existing = await conn.fetchrow(
                    "SELECT receipt_id, key_id, body_sha256, signature"
                    " FROM v2_receipts WHERE tenant_id = $1 AND message_id = $2",
                    tenant_id, message_id,
                )

                key_row = await conn.fetchrow(
                    "SELECT role, public_key FROM tenant_keys"
                    " WHERE tenant_id = $1 AND key_id = $2",
                    tenant_id, key_id,
                )
                if key_row is None:
                    # Unknown key ids and other tenants' keys are
                    # indistinguishable, exactly as on v1.
                    raise ApiError(404, "KEY_UNKNOWN")

                if existing is not None:
                    # A replay must prove possession of the very signature
                    # that created the receipt BEFORE we reveal anything
                    # about the stored row: a bad signature is BAD_SIGNATURE,
                    # never a conflict oracle.
                    try:
                        Ed25519PublicKey.from_public_bytes(
                            bytes(key_row["public_key"])
                        ).verify(signature, signed_message)
                    except InvalidSignature:
                        raise ApiError(400, "BAD_SIGNATURE") from None

                    if (
                        existing["key_id"] == key_id
                        and bytes(existing["body_sha256"]) == body_digest
                        and bytes(existing["signature"]) == signature
                    ):
                        # Byte-identical retry: hand back the immutable
                        # receipt without any UPDATE. The key's current role
                        # is irrelevant -- an accepted message keeps its
                        # receipt after rotation/retirement.
                        return JSONResponse(
                            {"receiptId": str(existing["receipt_id"])}, status_code=202
                        )
                    # Same id, different key/content/signature. Echo only
                    # what the client itself supplied; never the stored key
                    # id, digest or receipt id.
                    raise ApiError(409, "RECEIPT_CONFLICT", messageId=message_id)

                # First sighting. New messages may not be signed by a
                # retired key; current/candidate/retiring all verify.
                if key_row["role"] == "retired":
                    raise ApiError(410, "KEY_RETIRED")
                try:
                    Ed25519PublicKey.from_public_bytes(
                        bytes(key_row["public_key"])
                    ).verify(signature, signed_message)
                except InvalidSignature:
                    raise ApiError(400, "BAD_SIGNATURE") from None

                receipt_id = uuid.uuid4()
                await conn.execute(
                    "INSERT INTO v2_receipts (receipt_id, tenant_id, message_id,"
                    " key_id, body_sha256, signature, body_size)"
                    " VALUES ($1, $2, $3, $4, $5, $6, $7)",
                    receipt_id, tenant_id, message_id, key_id,
                    body_digest, signature, len(body),
                )
        except asyncpg.UniqueViolationError:
            # A concurrent first submission on another instance committed
            # first. Re-read after the loser transaction rolled back and
            # adjudicate exactly once more: identical -> original receipt,
            # divergent -> conflict. This plus the unique constraint is why
            # two instances receiving the same request still produce one row.
            winner = await conn.fetchrow(
                "SELECT receipt_id, key_id, body_sha256, signature"
                " FROM v2_receipts WHERE tenant_id = $1 AND message_id = $2",
                tenant_id, message_id,
            )
            if (
                winner is not None
                and winner["key_id"] == key_id
                and bytes(winner["body_sha256"]) == body_digest
                and bytes(winner["signature"]) == signature
            ):
                return JSONResponse(
                    {"receiptId": str(winner["receipt_id"])}, status_code=202
                )
            raise ApiError(409, "RECEIPT_CONFLICT", messageId=message_id) from None

    # Any ApiError raised above happened strictly before the insert, or the
    # insert's transaction was rolled back: a rejection never leaves a
    # placeholder receipt.
    return JSONResponse({"receiptId": str(receipt_id)}, status_code=202)
