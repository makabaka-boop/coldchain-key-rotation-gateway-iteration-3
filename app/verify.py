"""Gateway message verification: Ed25519 over the raw request body."""
import hashlib
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from . import db
from .auth import require
from .config import MAX_BODY_BYTES
from .errors import ApiError
from .util import b64url_decode_unpadded

router = APIRouter(tags=["verify"])


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
