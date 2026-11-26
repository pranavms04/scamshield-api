from tests.conftest import make_moderator, register_and_login

SCAM = "Dear customer your SBI KYC has expired. Update immediately at http://bit.ly/sbi-kyc or account will be blocked today"
SAFE = "Hi, are we still meeting for lunch tomorrow at 1?"


def test_scam_message_is_high_risk(client):
    h = register_and_login(client)
    body = client.post("/v1/check", json={"message": SCAM}, headers=h).json()
    assert body["verdict"] in {"suspicious", "high_risk"}
    assert body["risk_score"] >= 0.4
    assert "bit.ly/sbi-kyc" in body["detected_entities"]["url"]
    assert body["explanation"]["scam_type"] == "kyc_update"
    assert body["explanation"]["source"] == "rules"


def test_safe_message_is_low_risk(client):
    h = register_and_login(client)
    body = client.post("/v1/check", json={"message": SAFE}, headers=h).json()
    assert body["verdict"] == "likely_safe"


def test_verified_number_is_high_risk_even_with_innocent_text(client):
    citizen, mod = register_and_login(client), make_moderator(client)
    rid = client.post("/v1/reports", headers=citizen, json={
        "entity_type": "upi", "entity_value": "refund.help@ybl", "scam_type": "upi_collect",
        "description": "Asked me to enter UPI PIN to receive refund"}).json()["id"]
    client.post(f"/v1/moderation/reports/{rid}/decision", json={"status": "verified"}, headers=mod)
    for _ in range(2):  # two more verified reports from other citizens
        c = register_and_login(client, email=f"c{_}@example.com")
        rid = client.post("/v1/reports", headers=c, json={
            "entity_type": "upi", "entity_value": "REFUND.HELP@ybl", "scam_type": "upi_collect",
            "description": "Same UPI ID, collect request scam"}).json()["id"]
        client.post(f"/v1/moderation/reports/{rid}/decision", json={"status": "verified"}, headers=mod)

    body = client.post("/v1/check", json={"message": "Please send to refund.help@ybl"}, headers=citizen).json()
    assert body["verdict"] == "high_risk"
    assert body["signals"]["reputation"][0]["verified_reports"] == 3


def test_verified_report_becomes_similar_pattern(client):
    citizen, mod = register_and_login(client), make_moderator(client)
    rid = client.post("/v1/reports", headers=citizen, json={
        "entity_type": "url", "entity_value": "indiapost-track.top/pay", "scam_type": "delivery",
        "description": "Fake India Post parcel fee", "message_text":
        "Your parcel is held at the warehouse. Pay Rs 49 redelivery fee at indiapost-track.top/pay"}).json()["id"]
    client.post(f"/v1/moderation/reports/{rid}/decision", json={"status": "verified"}, headers=mod)

    body = client.post("/v1/check", headers=citizen, json={
        "message": "Parcel held at warehouse, pay Rs 25 redelivery fee today", "explain": False}).json()
    assert body["signals"]["similar_scams"], "verified message should be found as a similar scam"
    assert body["signals"]["similar_scams"][0]["scam_type"] == "delivery"
    assert body["explanation"] is None


def test_cache_and_validation(client):
    h = register_and_login(client)
    first = client.post("/v1/check", json={"message": SCAM}, headers=h).json()
    second = client.post("/v1/check", json={"message": SCAM}, headers=h).json()
    assert not first["cached"] and second["cached"]
    assert client.post("/v1/check", json={}, headers=h).status_code == 422


def test_rate_limit(client):
    h = register_and_login(client)
    client.app.state.limiter.per_minute = 3
    codes = [client.post("/v1/check", json={"message": f"m{i}"}, headers=h).status_code for i in range(4)]
    assert codes == [200, 200, 200, 429]
