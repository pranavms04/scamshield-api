from tests.conftest import make_moderator, register_and_login


def test_analytics(client):
    citizen, mod = register_and_login(client), make_moderator(client)
    for value, stype in [("9876543210", "kyc_update"), ("9876543210", "kyc_update"), ("8123456789", "fake_job")]:
        rid = client.post("/v1/reports", headers=citizen, json={
            "entity_type": "phone", "entity_value": value, "scam_type": stype,
            "description": "Reported for analytics test"}).json()["id"]
        client.post(f"/v1/moderation/reports/{rid}/decision", json={"status": "verified"}, headers=mod)
    client.post("/v1/check", json={"message": "You won a lottery! claim prize now"}, headers=citizen)

    trending = client.get("/v1/analytics/trending", headers=mod).json()
    assert trending[0] == {"type": "phone", "value": "+919876543210", "verified_reports": 2, "rank": 1}

    shares = {s["scam_type"]: s["share_pct"] for s in client.get("/v1/analytics/scam-types", headers=mod).json()}
    assert shares == {"kyc_update": 66.7, "fake_job": 33.3}

    daily = client.get("/v1/analytics/daily-checks", headers=mod).json()
    assert daily[0]["checks"] == 1

    assert client.get("/v1/analytics/trending", headers=citizen).status_code == 403
