from tests.conftest import make_moderator, register_and_login

REPORT = {
    "entity_type": "phone", "entity_value": "+91 98765 43210", "scam_type": "kyc_update",
    "description": "Caller said my SBI KYC expired and asked for OTP",
    "message_text": "Dear customer your SBI KYC expired. Update at bit.ly/sbi-kyc or account blocked today",
}


def test_report_moderation_and_reputation(client):
    citizen = register_and_login(client)
    mod = make_moderator(client)

    r = client.post("/v1/reports", json=REPORT, headers=citizen)
    assert r.status_code == 201 and r.json()["status"] == "pending"
    report_id = r.json()["id"]

    # citizens cannot moderate
    assert client.get("/v1/moderation/reports", headers=citizen).status_code == 403

    queue = client.get("/v1/moderation/reports", headers=mod).json()
    assert [q["id"] for q in queue] == [report_id]

    r = client.post(f"/v1/moderation/reports/{report_id}/decision", json={"status": "verified"}, headers=mod)
    assert r.json()["status"] == "verified"
    # deciding twice is a conflict
    assert client.post(f"/v1/moderation/reports/{report_id}/decision",
                       json={"status": "rejected"}, headers=mod).status_code == 409

    # same number written differently resolves to the same entity
    rep = client.get("/v1/entities/lookup", params={"type": "phone", "value": "9876543210"}, headers=citizen).json()
    assert rep["known"] and rep["verified_reports"] == 1 and rep["reputation_score"] > 0.5
    assert rep["top_scam_type"] == "kyc_update"


def test_invalid_entity_rejected(client):
    citizen = register_and_login(client)
    bad = {**REPORT, "entity_value": "123"}
    assert client.post("/v1/reports", json=bad, headers=citizen).status_code == 422
