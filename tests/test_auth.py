from tests.conftest import register_and_login, signup_body


def test_register_login_me(client):
    headers = register_and_login(client)
    r = client.get("/v1/auth/me", headers=headers)
    assert r.status_code == 200 and r.json()["role"] == "citizen"


def test_duplicate_email_conflict(client):
    body = signup_body("a@example.com")
    assert client.post("/v1/auth/register", json=body).status_code == 201
    assert client.post("/v1/auth/register", json=body).status_code == 409
    # same phone, different email is also a conflict
    r = client.post("/v1/auth/register", json={**body, "email": "b@example.com"})
    assert r.status_code == 409 and "Phone" in r.json()["detail"]


def test_wrong_password(client):
    register_and_login(client)
    r = client.post("/v1/auth/login", data={"username": "user@example.com", "password": "Wr0ng!Pass#1"})
    assert r.status_code == 401


def test_api_key_lifecycle(client):
    headers = register_and_login(client)
    created = client.post("/v1/api-keys", json={"name": "wallet app"}, headers=headers).json()
    assert created["api_key"].startswith("ss_live_")
    listed = client.get("/v1/api-keys", headers=headers).json()
    assert "api_key" not in listed[0]  # the raw key is never shown again
    key_headers = {"X-API-Key": created["api_key"]}
    assert client.post("/v1/check", json={"message": "hello"}, headers=key_headers).status_code == 200
    assert client.delete(f"/v1/api-keys/{created['id']}", headers=headers).status_code == 204
    assert client.post("/v1/check", json={"message": "hello"}, headers=key_headers).status_code == 401


def test_check_requires_auth(client):
    assert client.post("/v1/check", json={"message": "hi"}).status_code == 401
