"""Acceptance tests for the optional v2 idempotent verification contract.

Covered against a real PostgreSQL:
- first submission mints one immutable receipt
- two instances receiving the same request concurrently -> one receipt
- byte-identical retry (also after the key retires) returns that receipt
- same id, different body / different key -> 409 RECEIPT_CONFLICT, no leak
- retired keys cannot sign new messages; bad signatures never write rows
- cross-tenant message ids are isolated
- v1 raw-body verification and rotation behaviour stays unchanged
"""
import threading
import uuid

import httpx
import pytest

from conftest import (
    ADMIN_HEADERS,
    BASE2_URL,
    BASE_URL,
    GATEWAY_HEADERS,
    promote,
    receipts_list,
    register_key,
    retire,
    submit,
    submit_v2,
    v2_sign,
)


@pytest.fixture()
def gateway_client2():
    with httpx.Client(base_url=BASE2_URL, headers=GATEWAY_HEADERS, timeout=30.0) as client:
        yield client


def _fresh_message_id():
    return f"msg-{uuid.uuid4().hex}"


def _v2_count(direct_db, tenant_id):
    return direct_db.scalar(
        "SELECT count(*) FROM v2_receipts WHERE tenant_id = $1", tenant_id
    )


# ---------------------------------------------------------------- first submit


def test_v2_first_submission_creates_one_receipt(
    admin_client, gateway_client, tenant_id, make_key, direct_db
):
    key = make_key()
    register_key(admin_client, tenant_id, key)
    message_id = _fresh_message_id()
    body = b"temp=-18.4;hum=62"
    sig = v2_sign(key, tenant_id, key.key_id, message_id, body)

    resp = submit_v2(gateway_client, tenant_id, key.key_id, message_id, sig, body)
    assert resp.status_code == 202, resp.text
    receipt_id = resp.json()["receiptId"]

    receipts = receipts_list(admin_client, tenant_id)
    assert len(receipts) == 1
    row = receipts[0]
    assert row["version"] == "v2"
    assert row["receiptId"] == receipt_id
    assert row["messageId"] == message_id
    assert row["keyId"] == key.key_id
    assert _v2_count(direct_db, tenant_id) == 1


def test_v2_empty_body_is_accepted(
    admin_client, gateway_client, tenant_id, make_key
):
    key = make_key()
    register_key(admin_client, tenant_id, key)
    message_id = _fresh_message_id()
    sig = v2_sign(key, tenant_id, key.key_id, message_id, b"")
    resp = submit_v2(gateway_client, tenant_id, key.key_id, message_id, sig, b"")
    assert resp.status_code == 202, resp.text


def test_v2_missing_message_id_header_is_bad_request(
    admin_client, gateway_client, tenant_id, make_key
):
    key = make_key()
    register_key(admin_client, tenant_id, key)
    body = b"x"
    sig = v2_sign(key, tenant_id, key.key_id, "msg-1", body)
    resp = gateway_client.post(
        "/v2/verify",
        content=body,
        headers={
            "X-Tenant-Id": tenant_id,
            "X-Key-Id": key.key_id,
            "X-Signature": sig,
        },
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "BAD_REQUEST"


# ----------------------------------------------------------------- retry / idem


def test_v2_identical_retry_returns_same_receipt(
    admin_client, gateway_client, tenant_id, make_key, direct_db
):
    key = make_key()
    register_key(admin_client, tenant_id, key)
    message_id = _fresh_message_id()
    body = b"reading-42"
    sig = v2_sign(key, tenant_id, key.key_id, message_id, body)

    first = submit_v2(gateway_client, tenant_id, key.key_id, message_id, sig, body)
    assert first.status_code == 202
    receipt_id = first.json()["receiptId"]

    # Network-jitter retries, same content and signature: same receipt.
    for _ in range(3):
        retry = submit_v2(gateway_client, tenant_id, key.key_id, message_id, sig, body)
        assert retry.status_code == 202
        assert retry.json() == {"receiptId": receipt_id}

    assert _v2_count(direct_db, tenant_id) == 1


def test_v2_retry_with_retired_key_still_returns_original_receipt(
    admin_client, gateway_client, tenant_id, make_key, direct_db
):
    k1, k2 = make_key(), make_key()
    register_key(admin_client, tenant_id, k1)
    register_key(admin_client, tenant_id, k2)

    message_id = _fresh_message_id()
    body = b"cold-chain-event"
    sig = v2_sign(k1, tenant_id, k1.key_id, message_id, body)
    first = submit_v2(gateway_client, tenant_id, k1.key_id, message_id, sig, body)
    assert first.status_code == 202
    receipt_id = first.json()["receiptId"]

    # Rotate k1 current -> retiring -> retired.
    promote(admin_client, tenant_id)
    retire(admin_client, tenant_id)

    # A new message with the retired key is rejected ...
    new_id = _fresh_message_id()
    new_sig = v2_sign(k1, tenant_id, k1.key_id, new_id, body)
    rejected = submit_v2(gateway_client, tenant_id, k1.key_id, new_id, new_sig, body)
    assert rejected.status_code == 410
    assert rejected.json()["error"] == "KEY_RETIRED"

    # ... but the byte-identical retry of the already-accepted message keeps
    # returning its original receipt -- idempotency survives key retirement.
    retry = submit_v2(gateway_client, tenant_id, k1.key_id, message_id, sig, body)
    assert retry.status_code == 202
    assert retry.json() == {"receiptId": receipt_id}
    assert _v2_count(direct_db, tenant_id) == 1


def test_v2_receipt_is_immutable(
    admin_client, gateway_client, tenant_id, make_key, direct_db
):
    key = make_key()
    register_key(admin_client, tenant_id, key)
    message_id = _fresh_message_id()
    body = b"immutable"
    sig = v2_sign(key, tenant_id, key.key_id, message_id, body)
    resp = submit_v2(gateway_client, tenant_id, key.key_id, message_id, sig, body)
    receipt_id = resp.json()["receiptId"]

    retry = submit_v2(gateway_client, tenant_id, key.key_id, message_id, sig, body)
    assert retry.json()["receiptId"] == receipt_id

    row = direct_db.rows(
        "SELECT key_id, encode(body_sha256,'hex') AS d, encode(signature,'hex') AS s,"
        " body_size FROM v2_receipts WHERE tenant_id = $1 AND message_id = $2",
        tenant_id, message_id,
    )
    assert len(row) == 1
    assert row[0]["key_id"] == key.key_id
    assert row[0]["body_size"] == len(body)


# ------------------------------------------------------------------ conflicts


def test_v2_same_id_different_body_conflicts_and_leaks_nothing(
    admin_client, gateway_client, tenant_id, make_key, direct_db
):
    key = make_key()
    register_key(admin_client, tenant_id, key)
    message_id = _fresh_message_id()
    body_a = b"payload-a"
    sig_a = v2_sign(key, tenant_id, key.key_id, message_id, body_a)
    first = submit_v2(gateway_client, tenant_id, key.key_id, message_id, sig_a, body_a)
    assert first.status_code == 202

    body_b = b"payload-b-different"
    sig_b = v2_sign(key, tenant_id, key.key_id, message_id, body_b)
    conflict = submit_v2(
        gateway_client, tenant_id, key.key_id, message_id, sig_b, body_b
    )
    assert conflict.status_code == 409
    # Only the client-supplied id is echoed: no stored digest, key or receipt.
    assert conflict.json() == {"error": "RECEIPT_CONFLICT", "messageId": message_id}

    assert _v2_count(direct_db, tenant_id) == 1
    receipts = receipts_list(admin_client, tenant_id)
    assert receipts[0]["receiptId"] == first.json()["receiptId"]
    # Original content unchanged.
    import hashlib

    assert receipts[0]["sha256"] == hashlib.sha256(body_a).hexdigest()


def test_v2_same_id_different_key_conflicts(
    admin_client, gateway_client, tenant_id, make_key, direct_db
):
    k1, k2 = make_key(), make_key()
    register_key(admin_client, tenant_id, k1)
    register_key(admin_client, tenant_id, k2)  # candidate: may verify new msgs

    message_id = _fresh_message_id()
    body = b"same-body"
    sig1 = v2_sign(k1, tenant_id, k1.key_id, message_id, body)
    first = submit_v2(gateway_client, tenant_id, k1.key_id, message_id, sig1, body)
    assert first.status_code == 202

    # Reusing the message id under a different key id (even with a valid
    # signature bound to that key) must not rotate the receipt's key.
    sig2 = v2_sign(k2, tenant_id, k2.key_id, message_id, body)
    conflict = submit_v2(gateway_client, tenant_id, k2.key_id, message_id, sig2, body)
    assert conflict.status_code == 409
    assert conflict.json() == {"error": "RECEIPT_CONFLICT", "messageId": message_id}
    assert _v2_count(direct_db, tenant_id) == 1


def test_v2_conflict_does_not_leak_to_an_unauthenticated_signer(
    admin_client, gateway_client, tenant_id, make_key, direct_db
):
    k1, attacker = make_key(), make_key()
    register_key(admin_client, tenant_id, k1)
    message_id = _fresh_message_id()
    body_a = b"original"
    sig_a = v2_sign(k1, tenant_id, k1.key_id, message_id, body_a)
    submit_v2(gateway_client, tenant_id, k1.key_id, message_id, sig_a, body_a)

    # Attacker holds no registered key for the tenant: KEY_UNKNOWN gives no
    # hint that the message id exists.
    body_b = b"attacker-payload"
    sig_b = v2_sign(attacker, tenant_id, k1.key_id, message_id, body_b)
    resp = submit_v2(gateway_client, tenant_id, k1.key_id, message_id, sig_b, body_b)
    assert resp.status_code == 400
    assert resp.json() == {"error": "BAD_SIGNATURE"}

    sig_b2 = v2_sign(attacker, tenant_id, "no-such-key", message_id, body_b)
    resp2 = submit_v2(gateway_client, tenant_id, "no-such-key", message_id, sig_b2, body_b)
    assert resp2.status_code == 404
    assert resp2.json() == {"error": "KEY_UNKNOWN"}
    assert _v2_count(direct_db, tenant_id) == 1


# -------------------------------------------------------------- bad signatures


def test_v2_bad_signature_is_rejected_without_placeholder(
    admin_client, gateway_client, tenant_id, make_key, direct_db
):
    key, other = make_key(), make_key()
    register_key(admin_client, tenant_id, key)
    message_id = _fresh_message_id()
    body = b"signed by someone else"
    forged = v2_sign(other, tenant_id, key.key_id, message_id, body)

    resp = submit_v2(gateway_client, tenant_id, key.key_id, message_id, forged, body)
    assert resp.status_code == 400
    assert resp.json() == {"error": "BAD_SIGNATURE"}
    assert _v2_count(direct_db, tenant_id) == 0
    assert receipts_list(admin_client, tenant_id) == []


def test_v2_body_tampering_is_rejected_without_placeholder(
    admin_client, gateway_client, tenant_id, make_key, direct_db
):
    key = make_key()
    register_key(admin_client, tenant_id, key)
    message_id = _fresh_message_id()
    sig = v2_sign(key, tenant_id, key.key_id, message_id, b"original-body")
    resp = submit_v2(
        gateway_client, tenant_id, key.key_id, message_id, sig, b"tampered-body"
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "BAD_SIGNATURE"
    assert _v2_count(direct_db, tenant_id) == 0


def test_v2_message_id_binding_blocks_reuse_under_another_id(
    admin_client, gateway_client, tenant_id, make_key, direct_db
):
    """The signature binds the message id: a signature for msg-a is invalid
    for msg-b, so message ids cannot be swapped to mint extra receipts."""
    key = make_key()
    register_key(admin_client, tenant_id, key)
    body = b"bound"
    sig = v2_sign(key, tenant_id, key.key_id, "msg-a", body)
    resp = submit_v2(gateway_client, tenant_id, key.key_id, "msg-b", sig, body)
    assert resp.status_code == 400
    assert resp.json()["error"] == "BAD_SIGNATURE"
    assert _v2_count(direct_db, tenant_id) == 0


def test_v2_tenant_binding_blocks_cross_tenant_signature(
    admin_client, gateway_client, tenant_id, make_key
):
    key = make_key()
    register_key(admin_client, tenant_id, key)
    body = b"x"
    sig = v2_sign(key, tenant_id, key.key_id, "m1", body)
    resp = submit_v2(gateway_client, tenant_id + "-other", key.key_id, "m1", sig, body)
    assert resp.status_code == 404
    assert resp.json() == {"error": "KEY_UNKNOWN"}


def test_v2_malformed_signature_encoding_is_bad_signature(
    admin_client, gateway_client, tenant_id, make_key, direct_db
):
    key = make_key()
    register_key(admin_client, tenant_id, key)
    body = b"x"
    resp = submit_v2(
        gateway_client, tenant_id, key.key_id, "m1", "not!!!base64url", body
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "BAD_SIGNATURE"
    assert _v2_count(direct_db, tenant_id) == 0


# ------------------------------------------------------------- retired / roles


def test_v2_new_message_rejects_retired_key(
    admin_client, gateway_client, tenant_id, make_key
):
    k1, k2 = make_key(), make_key()
    register_key(admin_client, tenant_id, k1)
    register_key(admin_client, tenant_id, k2)
    promote(admin_client, tenant_id)
    retire(admin_client, tenant_id)

    body = b"too late"
    message_id = _fresh_message_id()
    sig = v2_sign(k1, tenant_id, k1.key_id, message_id, body)
    resp = submit_v2(gateway_client, tenant_id, k1.key_id, message_id, sig, body)
    assert resp.status_code == 410
    assert resp.json()["error"] == "KEY_RETIRED"


def test_v2_retiring_key_can_sign_new_messages(
    admin_client, gateway_client, tenant_id, make_key
):
    k1, k2 = make_key(), make_key()
    register_key(admin_client, tenant_id, k1)
    register_key(admin_client, tenant_id, k2)
    promote(admin_client, tenant_id)  # k1 retiring

    body = b"grace window"
    message_id = _fresh_message_id()
    sig = v2_sign(k1, tenant_id, k1.key_id, message_id, body)
    resp = submit_v2(gateway_client, tenant_id, k1.key_id, message_id, sig, body)
    assert resp.status_code == 202, resp.text


def test_v2_unknown_and_cross_tenant_key_are_indistinguishable(
    admin_client, gateway_client, tenant_id, make_key
):
    key = make_key()
    register_key(admin_client, tenant_id, key)
    body = b"x"
    sig = v2_sign(key, tenant_id, key.key_id, "m1", body)
    cross = submit_v2(gateway_client, tenant_id + "-other", key.key_id, "m1", sig, body)
    sig2 = v2_sign(key, tenant_id, "ghost", "m1", body)
    unknown = submit_v2(gateway_client, tenant_id, "ghost", "m1", sig2, body)
    assert cross.status_code == unknown.status_code == 404
    assert cross.json() == unknown.json() == {"error": "KEY_UNKNOWN"}


# ------------------------------------------------------------- cross-tenant id


def test_v2_message_ids_are_isolated_across_tenants(
    admin_client, gateway_client, make_key, direct_db
):
    t_a, t_b = "ta-" + uuid.uuid4().hex[:12], "tb-" + uuid.uuid4().hex[:12]
    ka, kb = make_key(), make_key()
    register_key(admin_client, t_a, ka)
    register_key(admin_client, t_b, kb)

    message_id = "shared-message-id"
    body = b"same id, different tenants"
    sig_a = v2_sign(ka, t_a, ka.key_id, message_id, body)
    sig_b = v2_sign(kb, t_b, kb.key_id, message_id, body)

    ra = submit_v2(gateway_client, t_a, ka.key_id, message_id, sig_a, body)
    rb = submit_v2(gateway_client, t_b, kb.key_id, message_id, sig_b, body)
    assert ra.status_code == rb.status_code == 202
    assert ra.json()["receiptId"] != rb.json()["receiptId"]

    assert _v2_count(direct_db, t_a) == 1
    assert _v2_count(direct_db, t_b) == 1


# ------------------------------------------------------- concurrent first submit


def test_v2_two_instances_same_request_only_one_receipt(
    admin_client, gateway_client, gateway_client2, tenant_id, make_key, direct_db
):
    key = make_key()
    register_key(admin_client, tenant_id, key)
    message_id = _fresh_message_id()
    body = b"jitter-broadcast"
    sig = v2_sign(key, tenant_id, key.key_id, message_id, body)

    results: dict[str, httpx.Response] = {}
    barrier = threading.Barrier(2)

    def fire(name, client):
        barrier.wait()
        results[name] = submit_v2(
            client, tenant_id, key.key_id, message_id, sig, body
        )

    t1 = threading.Thread(target=fire, args=("a", gateway_client))
    t2 = threading.Thread(target=fire, args=("b", gateway_client2))
    t1.start(); t2.start(); t1.join(); t2.join()

    ra, rb = results["a"], results["b"]
    assert ra.status_code == rb.status_code == 202, (ra.text, rb.text)
    # The loser must hand back the winner's receipt id, not a second receipt.
    assert ra.json()["receiptId"] == rb.json()["receiptId"]

    rows = direct_db.rows(
        "SELECT receipt_id FROM v2_receipts"
        " WHERE tenant_id = $1 AND message_id = $2",
        tenant_id, message_id,
    )
    assert len(rows) == 1
    assert str(rows[0]["receipt_id"]) == ra.json()["receiptId"]


def test_v2_concurrent_same_id_different_content_one_receipt_and_conflict(
    admin_client, gateway_client, gateway_client2, tenant_id, make_key, direct_db
):
    key = make_key()
    register_key(admin_client, tenant_id, key)
    message_id = _fresh_message_id()
    body_a = b"version-A"
    body_b = b"version-B-DIFFERENT"
    sig_a = v2_sign(key, tenant_id, key.key_id, message_id, body_a)
    sig_b = v2_sign(key, tenant_id, key.key_id, message_id, body_b)

    results: dict[str, httpx.Response] = {}
    barrier = threading.Barrier(2)

    def fire(name, client, body, sig):
        barrier.wait()
        results[name] = submit_v2(
            client, tenant_id, key.key_id, message_id, sig, body
        )

    t1 = threading.Thread(target=fire, args=("a", gateway_client, body_a, sig_a))
    t2 = threading.Thread(target=fire, args=("b", gateway_client2, body_b, sig_b))
    t1.start(); t2.start(); t1.join(); t2.join()

    statuses = sorted(r.status_code for r in results.values())
    assert statuses == [202, 409], {k: (v.status_code, v.text) for k, v in results.items()}
    conflict = next(r for r in results.values() if r.status_code == 409)
    assert conflict.json() == {"error": "RECEIPT_CONFLICT", "messageId": message_id}
    assert _v2_count(direct_db, tenant_id) == 1


def test_v2_repeated_concurrent_identical_requests_never_duplicate(
    admin_client, gateway_client, gateway_client2, tenant_id, make_key, direct_db
):
    key = make_key()
    register_key(admin_client, tenant_id, key)
    body = b"storm"

    outcomes = []
    lock = threading.Lock()

    def storm(message_id, client):
        sig = v2_sign(key, tenant_id, key.key_id, message_id, body)
        resp = submit_v2(client, tenant_id, key.key_id, message_id, sig, body)
        with lock:
            outcomes.append((message_id, resp.status_code, resp.json()))

    threads = []
    for i in range(8):
        message_id = f"storm-{i}"
        threads.append(
            threading.Thread(target=storm, args=(message_id, gateway_client))
        )
        threads.append(
            threading.Thread(target=storm, args=(message_id, gateway_client2))
        )
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(outcomes) == 16
    assert all(code == 202 for _, code, _ in outcomes)
    for i in range(8):
        ids = {body["receiptId"] for mid, _, body in outcomes if mid == f"storm-{i}"}
        assert ids and len(ids) == 1
    assert direct_db.scalar(
        "SELECT count(*) FROM v2_receipts WHERE tenant_id = $1", tenant_id
    ) == 8


# -------------------------------------------------- storage constraint / rollback


def test_v2_database_enforces_one_receipt_per_tenant_message(direct_db, tenant_id):
    """The unique constraint itself rejects a duplicate even if a buggy
    writer bypassed the API: (tenant, message) is the authoritative key."""
    import asyncio
    import os

    import asyncpg

    async def scenario():
        conn = await asyncpg.connect(os.environ["DATABASE_URL"])
        await conn.execute(
            "INSERT INTO v2_receipts (receipt_id, tenant_id, message_id, key_id,"
            " body_sha256, signature, body_size)"
            " VALUES (gen_random_uuid(), $1, 'dup-probe', 'k', $2, $3, 0)",
            tenant_id, b"\x00" * 32, b"\x00" * 64,
        )
        with pytest.raises(asyncpg.UniqueViolationError):
            await conn.execute(
                "INSERT INTO v2_receipts (receipt_id, tenant_id, message_id, key_id,"
                " body_sha256, signature, body_size)"
                " VALUES (gen_random_uuid(), $1, 'dup-probe', 'k2', $2, $3, 1)",
                tenant_id, b"\x01" * 32, b"\x01" * 64,
            )
        await conn.close()

    asyncio.run(scenario())

    # Same message id under a different tenant is allowed: isolation is real.
    assert direct_db.scalar(
        "SELECT count(*) FROM v2_receipts"
        " WHERE tenant_id = $1 AND message_id = 'dup-probe'",
        tenant_id,
    ) == 1
    direct_db.rows(
        "DELETE FROM v2_receipts WHERE tenant_id = $1 AND message_id = 'dup-probe'",
        tenant_id,
    )


def test_v2_all_failure_paths_leave_no_extra_receipts(
    admin_client, gateway_client, tenant_id, make_key, direct_db
):
    """Exercise every rejection path and assert the failure transaction
    rolled back cleanly: exactly zero rows for ids that never succeeded."""
    k1, k2, other = make_key(), make_key(), make_key()
    register_key(admin_client, tenant_id, k1)
    register_key(admin_client, tenant_id, k2)

    body = b"failure-walk"

    # 1. unknown key
    r = submit_v2(
        gateway_client, tenant_id, "ghost", "m-unknown",
        v2_sign(k1, tenant_id, "ghost", "m-unknown", body), body,
    )
    assert r.status_code == 404

    # 2. bad signature
    r = submit_v2(
        gateway_client, tenant_id, k1.key_id, "m-bad",
        v2_sign(other, tenant_id, k1.key_id, "m-bad", body), body,
    )
    assert r.status_code == 400

    # 3. retired key on new message
    promote(admin_client, tenant_id)
    retire(admin_client, tenant_id)
    r = submit_v2(
        gateway_client, tenant_id, k1.key_id, "m-retired",
        v2_sign(k1, tenant_id, k1.key_id, "m-retired", body), body,
    )
    assert r.status_code == 410

    # 4. one good message, then conflicting retries
    good = _fresh_message_id()
    r1 = submit_v2(
        gateway_client, tenant_id, k2.key_id, good,
        v2_sign(k2, tenant_id, k2.key_id, good, body), body,
    )
    assert r1.status_code == 202
    other_body = b"failure-walk-DIFFERENT"
    r2 = submit_v2(
        gateway_client, tenant_id, k2.key_id, good,
        v2_sign(k2, tenant_id, k2.key_id, good, other_body), other_body,
    )
    assert r2.status_code == 409
    r3 = submit_v2(
        gateway_client, tenant_id, k1.key_id, good,
        v2_sign(k1, tenant_id, k1.key_id, good, body), body,
    )
    assert r3.status_code == 409

    assert _v2_count(direct_db, tenant_id) == 1
    stored = direct_db.rows(
        "SELECT message_id FROM v2_receipts WHERE tenant_id = $1", tenant_id
    )
    assert [r["message_id"] for r in stored] == [good]
    # No legacy receipts either.
    assert direct_db.scalar(
        "SELECT count(*) FROM receipts WHERE tenant_id = $1", tenant_id
    ) == 0


# ----------------------------------------------------------- v1 compatibility


def test_v1_contract_is_unchanged_raw_body_and_new_receipt_every_time(
    admin_client, gateway_client, tenant_id, make_key
):
    key = make_key()
    register_key(admin_client, tenant_id, key)
    body = b"legacy-raw-body"

    r1 = submit(gateway_client, tenant_id, key.key_id, key.sign(body), body)
    r2 = submit(gateway_client, tenant_id, key.key_id, key.sign(body), body)
    assert r1.status_code == r2.status_code == 202
    # v1 still mints a fresh receipt per accepted request (no idempotency).
    assert r1.json()["receiptId"] != r2.json()["receiptId"]

    receipts = receipts_list(admin_client, tenant_id)
    assert {r["version"] for r in receipts} == {"v1"}
    assert all(r["messageId"] is None for r in receipts)

    # v1 verification never consults the v2 domain string: a v2 signature
    # header over canonical text does not validate over the raw body.
    message_id = _fresh_message_id()
    v2_sig = v2_sign(key, tenant_id, key.key_id, message_id, body)
    cross = submit(gateway_client, tenant_id, key.key_id, v2_sig, body)
    assert cross.status_code == 400
    assert cross.json()["error"] == "BAD_SIGNATURE"


def test_v2_signature_does_not_verify_on_v1_endpoint_and_vice_versa(
    admin_client, gateway_client, tenant_id, make_key
):
    key = make_key()
    register_key(admin_client, tenant_id, key)
    body = b"domain-separation"
    message_id = _fresh_message_id()

    # Raw-body signature sent to v2 (which hashes the body into a canonical
    # message) must fail.
    r = submit_v2(
        gateway_client, tenant_id, key.key_id, message_id, key.sign(body), body
    )
    assert r.status_code == 400
    assert r.json()["error"] == "BAD_SIGNATURE"


def test_v1_rotation_and_retirement_behaviour_unchanged(
    admin_client, gateway_client, tenant_id, make_key
):
    k1, k2 = make_key(), make_key()
    register_key(admin_client, tenant_id, k1)
    register_key(admin_client, tenant_id, k2)
    body = b"rotation"
    assert submit(gateway_client, tenant_id, k1.key_id, k1.sign(body), body).status_code == 202
    promote(admin_client, tenant_id)
    assert submit(gateway_client, tenant_id, k1.key_id, k1.sign(body), body).status_code == 202
    retire(admin_client, tenant_id)
    r = submit(gateway_client, tenant_id, k1.key_id, k1.sign(body), body)
    assert r.status_code == 410
    assert r.json()["error"] == "KEY_RETIRED"


# ------------------------------------------------------------------ auth/misc


def test_v2_requires_gateway_scope(tenant_id, make_key):
    with httpx.Client(base_url=BASE_URL, timeout=30.0) as client:
        no_token = client.post("/v2/verify", content=b"x")
        bad_token = client.post(
            "/v2/verify", content=b"x", headers={"Authorization": "Bearer nope"}
        )
        assert no_token.status_code == 401
        assert bad_token.status_code == 401

    # Admin token carries the verify scope.
    key = make_key()
    with httpx.Client(base_url=BASE_URL, headers=ADMIN_HEADERS, timeout=30.0) as admin:
        register = admin.post(
            f"/v1/tenants/{tenant_id}/keys",
            json={"keyId": key.key_id, "publicKey": key.public_key_b64},
        )
        assert register.status_code == 201, register.text
        body = b"admin-can-verify"
        message_id = _fresh_message_id()
        sig = v2_sign(key, tenant_id, key.key_id, message_id, body)
        ok = submit_v2(admin, tenant_id, key.key_id, message_id, sig, body)
        assert ok.status_code == 202, ok.text


def test_v2_gateway_token_cannot_manage_keys(
    admin_client, gateway_client, tenant_id, make_key
):
    key = make_key()
    resp = gateway_client.post(
        f"/v1/tenants/{tenant_id}/keys",
        json={"keyId": key.key_id, "publicKey": key.public_key_b64},
    )
    assert resp.status_code == 403


def test_v2_size_limit(admin_client, gateway_client, tenant_id, make_key):
    key = make_key()
    register_key(admin_client, tenant_id, key)
    over = bytes(1_048_577)
    message_id = _fresh_message_id()
    sig = v2_sign(key, tenant_id, key.key_id, message_id, over)
    resp = submit_v2(gateway_client, tenant_id, key.key_id, message_id, sig, over)
    assert resp.status_code == 413
    assert resp.json()["error"] == "PAYLOAD_TOO_LARGE"
