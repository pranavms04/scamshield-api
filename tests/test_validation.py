"""Strict input validation across the API: every bad input must be a clean 4xx, never a 500."""
import pytest

from tests.conftest import make_moderator, register_and_login, signup_body


def fields(r):
    return {e["field"] for e in r.json()["errors"]}


# --- Register ---------------------------------------------------------------
def test_register_success_returns_profile(client):
    r = client.post("/v1/auth/register", json=signup_body(phone="+91 98765-43210", email="  Priya@Example.COM "))
    assert r.status_code == 201
    body = r.json()
    assert body["email"] == "priya@example.com"
    assert body["phone"] == "+919876543210"
    assert body["full_name"] == "Priya Sharma" and body["state"] == "Kerala" and body["role"] == "citizen"
    assert "password" not in body and "password_hash" not in body


@pytest.mark.parametrize("override,field", [
    ({"email": "not-an-email"}, "email"),
    ({"full_name": "P"}, "full_name"),
    ({"full_name": "Priya123"}, "full_name"),
    ({"full_name": "<script>"}, "full_name"),
    ({"phone": "12345"}, "phone"),
    ({"phone": "5876543210"}, "phone"),  # Indian mobiles start with 6-9
    ({"state": "Atlantis"}, "state"),
    ({"city": "K0chi!"}, "city"),
])
def test_register_rejects_bad_fields(client, override, field):
    r = client.post("/v1/auth/register", json=signup_body(**override))
    assert r.status_code == 422 and field in fields(r)


@pytest.mark.parametrize("password", [
    "Sh0rt!",            # too short
    "alllowercase1!",    # no uppercase
    "ALLUPPERCASE1!",    # no lowercase
    "NoDigitsHere!!",    # no digit
    "NoSpecial1234x",    # no special character
    "Has Space1!x",      # whitespace
    "Password@123",      # common
    "Abcde!9xyzQ",       # sequence
    "Aaaaa!9xyzQ",       # repeated characters
    "A1!" + "x" * 70,    # too long
])
def test_register_rejects_weak_passwords(client, password):
    r = client.post("/v1/auth/register", json=signup_body(password=password))
    assert r.status_code == 422 and "password" in fields(r)


def test_register_cross_field_rules(client):
    cases = [
        signup_body(confirm_password="Different!Pass9"),
        signup_body(accept_terms=False),
        signup_body(email="kumar.ravi@example.com", password="Kumar.Ravi!77", confirm_password="Kumar.Ravi!77"),
        signup_body(full_name="Ravi Kumar", password="Kumar!Strong9", confirm_password="Kumar!Strong9"),
    ]
    for body in cases:
        assert client.post("/v1/auth/register", json=body).status_code == 422


def test_register_rejects_unknown_and_missing_fields(client):
    # privilege escalation attempt: extra fields are forbidden, not silently ignored
    r = client.post("/v1/auth/register", json={**signup_body(), "role": "admin"})
    assert r.status_code == 422 and "role" in fields(r)
    body = signup_body()
    del body["phone"]
    assert client.post("/v1/auth/register", json=body).status_code == 422
    assert client.post("/v1/auth/register", content="not json",
                       headers={"Content-Type": "application/json"}).status_code == 422


# --- Login ------------------------------------------------------------------
def test_login_with_phone_and_token_shape(client):
    body = signup_body(phone="9123456780")
    client.post("/v1/auth/register", json=body)
    r = client.post("/v1/auth/login", data={"username": "+91 91234 56780", "password": body["password"]})
    assert r.status_code == 200
    assert r.json()["token_type"] == "bearer" and r.json()["expires_in"] > 0


@pytest.mark.parametrize("data", [
    {"username": "", "password": "x"},
    {"username": "user@example.com", "password": ""},
    {"username": "not-email-or-phone", "password": "x"},
    {"username": "user@example.com", "password": "x" * 65},
    {"username": "user@example.com"},
])
def test_login_rejects_bad_input(client, data):
    assert client.post("/v1/auth/login", data=data).status_code == 422


def test_login_unknown_user_same_error_as_wrong_password(client):
    register_and_login(client)
    a = client.post("/v1/auth/login", data={"username": "ghost@example.com", "password": "Wr0ng!Pass#1"})
    b = client.post("/v1/auth/login", data={"username": "user@example.com", "password": "Wr0ng!Pass#1"})
    assert a.status_code == b.status_code == 401 and a.json() == b.json()


def test_login_lockout_after_repeated_failures(client):
    register_and_login(client)
    codes = [client.post("/v1/auth/login", data={"username": "user@example.com", "password": "Wr0ng!Pass#1"}).status_code
             for _ in range(6)]
    assert codes == [401] * 5 + [429]
    # even the right password is refused while locked
    r = client.post("/v1/auth/login", data={"username": "user@example.com", "password": signup_body()["password"]})
    assert r.status_code == 429 and "Retry-After" in r.headers


def test_disabled_account_cannot_log_in(client):
    import asyncio

    from sqlalchemy import update

    from app.db.session import SessionLocal
    from app.models import User
    register_and_login(client)

    async def disable():
        async with SessionLocal() as db:
            await db.execute(update(User).values(is_active=False))
            await db.commit()
    asyncio.run(disable())
    r = client.post("/v1/auth/login", data={"username": "user@example.com", "password": signup_body()["password"]})
    assert r.status_code == 403


def test_bad_tokens_are_401_not_500(client):
    for token in ["garbage", "a.b.c", "x" * 5000]:
        assert client.get("/v1/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401
    assert client.post("/v1/check", json={"message": "hi"}, headers={"X-API-Key": "wrong"}).status_code == 401


# --- Profile & password -----------------------------------------------------
def test_update_profile_and_change_password(client):
    h = register_and_login(client)
    r = client.patch("/v1/auth/me", json={"city": "Thrissur", "state": "Kerala"}, headers=h)
    assert r.status_code == 200 and r.json()["city"] == "Thrissur"
    assert client.patch("/v1/auth/me", json={}, headers=h).status_code == 422
    assert client.patch("/v1/auth/me", json={"phone": None}, headers=h).status_code == 422
    assert client.patch("/v1/auth/me", json={"role": "admin"}, headers=h).status_code == 422

    old = signup_body()["password"]
    bad = client.post("/v1/auth/change-password", headers=h,
                      json={"current_password": "Wr0ng!Pass#1", "new_password": "N3w!Secure#8",
                            "confirm_new_password": "N3w!Secure#8"})
    assert bad.status_code == 422 and "current_password" in fields(bad)
    ok = client.post("/v1/auth/change-password", headers=h,
                     json={"current_password": old, "new_password": "N3w!Secure#8",
                           "confirm_new_password": "N3w!Secure#8"})
    assert ok.status_code == 204
    assert client.post("/v1/auth/login", data={"username": "user@example.com", "password": "N3w!Secure#8"}).status_code == 200


# --- API keys ---------------------------------------------------------------
def test_api_key_validation(client):
    h = register_and_login(client)
    assert client.post("/v1/api-keys", json={"name": "  "}, headers=h).status_code == 422
    assert client.post("/v1/api-keys", json={"name": "ab"}, headers=h).status_code == 422
    assert client.post("/v1/api-keys", json={"name": "bad\x00name"}, headers=h).status_code == 422
    first = client.post("/v1/api-keys", json={"name": "wallet app"}, headers=h)
    assert first.status_code == 201
    assert client.post("/v1/api-keys", json={"name": "Wallet App"}, headers=h).status_code == 409
    kid = first.json()["id"]
    assert client.delete(f"/v1/api-keys/{kid}", headers=h).status_code == 204
    assert client.delete(f"/v1/api-keys/{kid}", headers=h).status_code == 409
    assert client.delete("/v1/api-keys/0", headers=h).status_code == 422
    assert client.delete("/v1/api-keys/99999999999", headers=h).status_code == 422
    assert client.delete("/v1/api-keys/abc", headers=h).status_code == 422


# --- Check ------------------------------------------------------------------
@pytest.mark.parametrize("body", [
    {}, {"message": "   "}, {"message": "x" * 2001}, {"phone": "123"}, {"upi_id": "not-a-upi"},
    {"url": "nodot"}, {"message": "hello", "explain": "yes"}, {"message": "hello", "extra": 1},
    {"message": "bad\x00byte"},
])
def test_check_rejects_bad_input(client, body):
    h = register_and_login(client)
    assert client.post("/v1/check", json=body, headers=h).status_code == 422


def test_check_accepts_explicit_entities(client):
    h = register_and_login(client)
    r = client.post("/v1/check", json={"phone": "09876543210", "upi_id": "Fraud.KYC@ybl", "url": "www.bit.ly/x"}, headers=h)
    assert r.status_code == 200
    ents = r.json()["detected_entities"]
    assert ents["phone"] == ["+919876543210"] and ents["upi"] == ["fraud.kyc@ybl"] and ents["url"] == ["bit.ly/x"]


# --- Reports & moderation ---------------------------------------------------
REPORT = {"entity_type": "phone", "entity_value": "9876543210", "scam_type": "kyc_update",
          "description": "Caller asked me for the OTP to update KYC"}


@pytest.mark.parametrize("override", [
    {"entity_type": "fax"}, {"scam_type": "unknown"}, {"description": "too short"},
    {"description": "1234567890 1234567890 !!"}, {"entity_type": "upi", "entity_value": "9876543210"},
    {"message_text": "short"}, {"status": "verified"},
])
def test_report_rejects_bad_input(client, override):
    h = register_and_login(client)
    assert client.post("/v1/reports", json={**REPORT, **override}, headers=h).status_code == 422


def test_duplicate_pending_report_conflict(client):
    h = register_and_login(client)
    assert client.post("/v1/reports", json=REPORT, headers=h).status_code == 201
    assert client.post("/v1/reports", json={**REPORT, "entity_value": "+91 98765 43210"}, headers=h).status_code == 409


def test_moderation_validation(client):
    citizen, mod = register_and_login(client), make_moderator(client)
    rid = client.post("/v1/reports", json=REPORT, headers=citizen).json()["id"]
    url = f"/v1/moderation/reports/{rid}/decision"
    assert client.post(url, json={"status": "pending"}, headers=mod).status_code == 422
    assert client.post(url, json={"status": "rejected"}, headers=mod).status_code == 422  # note required
    assert client.post("/v1/moderation/reports/0/decision", json={"status": "verified"}, headers=mod).status_code == 422
    assert client.post("/v1/moderation/reports/999/decision", json={"status": "verified"}, headers=mod).status_code == 404
    # moderators can't approve their own reports
    own = client.post("/v1/reports", json={**REPORT, "entity_value": "8123456789"}, headers=mod).json()["id"]
    assert client.post(f"/v1/moderation/reports/{own}/decision", json={"status": "verified"}, headers=mod).status_code == 403
    assert client.get("/v1/moderation/reports", params={"status": "bogus"}, headers=mod).status_code == 422
    assert client.get("/v1/moderation/reports", params={"limit": 0}, headers=mod).status_code == 422


def test_lookup_and_query_validation(client):
    h = register_and_login(client)
    assert client.get("/v1/entities/lookup", params={"type": "phone", "value": "12"}, headers=h).status_code == 422
    assert client.get("/v1/entities/lookup", params={"type": "phone", "value": "12345"}, headers=h).status_code == 422
    assert client.get("/v1/entities/lookup", params={"type": "fax", "value": "9876543210"}, headers=h).status_code == 422
    assert client.get("/v1/reports/mine", params={"limit": 1000}, headers=h).status_code == 422
    assert client.get("/v1/reports/mine", params={"skip": -1}, headers=h).status_code == 422
    mod = make_moderator(client)
    assert client.get("/v1/analytics/trending", params={"days": 0}, headers=mod).status_code == 422
    assert client.get("/v1/analytics/scam-types", params={"days": 1000}, headers=mod).status_code == 422


def test_validation_error_format(client):
    r = client.post("/v1/auth/register", json=signup_body(email="bad"))
    body = r.json()
    assert body["detail"] == "Validation failed"
    assert {"field", "message", "type"} <= set(body["errors"][0])
