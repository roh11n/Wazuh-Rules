"""Backend tests for OSINT Pipeline API."""
import os
import time
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "https://threat-scanner-77.preview.emergentagent.com").rstrip("/")
API = f"{BASE_URL}/api"


@pytest.fixture(scope="module")
def client():
    s = requests.Session()
    s.headers.update({"Content-Type": "application/json"})
    return s


# ── Health check ──────────────────────────────────────
class TestHealth:
    def test_root_health(self, client):
        r = client.get(f"{API}/")
        assert r.status_code == 200
        data = r.json()
        assert "message" in data
        assert data.get("status") == "ok"


# ── Settings endpoints ─────────────────────────────────
class TestSettings:
    def test_get_settings_masked(self, client):
        r = client.get(f"{API}/settings")
        assert r.status_code == 200
        data = r.json()
        for k in ("ipinfo_token", "abuseipdb_key", "virustotal_key", "otx_key", "discord_webhook"):
            assert k in data
            assert f"{k}_set" in data
            assert isinstance(data[f"{k}_set"], bool)
            # No plaintext bulk of key in display value
            assert not data[k].startswith("sk-") if data[k] else True

    def test_put_settings_stores_and_masks(self, client):
        payload = {"ipinfo_token": "TESTipinfo_TOKEN_1234567890abcdef"}
        r = client.put(f"{API}/settings", json=payload)
        assert r.status_code == 200
        assert r.json().get("ok") is True
        # re-fetch and verify masking + flag
        g = client.get(f"{API}/settings").json()
        assert g["ipinfo_token_set"] is True
        # masked value should NOT equal the original plaintext
        assert g["ipinfo_token"] != payload["ipinfo_token"]
        # but should contain last 4 chars
        assert g["ipinfo_token"].endswith(payload["ipinfo_token"][-4:])


# ── Scan validation ────────────────────────────────────
class TestScanValidation:
    def test_create_scan_empty_target(self, client):
        r = client.post(f"{API}/scans", json={"target": ""})
        assert r.status_code == 400

    def test_create_scan_invalid_target(self, client):
        r = client.post(f"{API}/scans", json={"target": "notadomain"})
        assert r.status_code == 400

    def test_get_nonexistent_scan(self, client):
        r = client.get(f"{API}/scans/nonexistent-id-12345")
        assert r.status_code == 404

    def test_report_nonexistent_scan(self, client):
        r = client.get(f"{API}/scans/nonexistent-id-12345/report")
        assert r.status_code == 404

    def test_delete_nonexistent_scan(self, client):
        r = client.delete(f"{API}/scans/nonexistent-id-12345")
        assert r.status_code == 404


# ── Scan list ──────────────────────────────────────────
class TestScanList:
    def test_list_scans(self, client):
        r = client.get(f"{API}/scans")
        assert r.status_code == 200
        assert isinstance(r.json(), list)


# ── Create scan + progress polling (fast: queued/running) ─
class TestScanCreation:
    def test_create_scan_returns_id_and_queued(self, client):
        r = client.post(f"{API}/scans", json={
            "target": "example.com",
            "skip_dorking": True,
            "skip_screenshots": True,
        })
        assert r.status_code == 200
        data = r.json()
        assert "id" in data
        assert data["target"] == "example.com"
        assert data["status"] in ("queued", "running")
        assert data["progress"] in (0, 1)

        scan_id = data["id"]
        # Report should be 400 while not complete
        r2 = client.get(f"{API}/scans/{scan_id}/report")
        assert r2.status_code == 400

        # Status polling works
        r3 = client.get(f"{API}/scans/{scan_id}/status")
        assert r3.status_code == 200
        assert r3.json()["id"] == scan_id

        # cleanup
        client.delete(f"{API}/scans/{scan_id}")


# ── End to end scan completion ─────────────────────────
class TestScanEndToEnd:
    def test_scan_completes_and_report_renders(self, client):
        r = client.post(f"{API}/scans", json={
            "target": "example.com",
            "skip_dorking": True,
            "skip_screenshots": True,
        })
        assert r.status_code == 200
        scan_id = r.json()["id"]

        # Poll for up to 120s
        deadline = time.time() + 120
        final = None
        while time.time() < deadline:
            s = client.get(f"{API}/scans/{scan_id}/status")
            assert s.status_code == 200
            final = s.json()
            if final["status"] in ("completed", "failed"):
                break
            time.sleep(3)

        assert final is not None, "No status returned"
        assert final["status"] == "completed", f"Scan did not complete: {final}"
        assert final["progress"] == 100

        # Full doc
        full = client.get(f"{API}/scans/{scan_id}").json()
        assert full["status"] == "completed"
        assert full.get("result") is not None
        result = full["result"]

        # Risk fields
        assert "risk" in result and result["risk"] is not None
        assert "severity" in result["risk"]
        assert "risk_score" in result["risk"]
        assert "reasons" in result["risk"]

        # Populated sub-sections
        assert isinstance(result.get("dns_records"), (dict, list))
        assert isinstance(result.get("subdomains"), list)
        assert isinstance(result.get("live_hosts"), list)
        assert isinstance(result.get("ips"), list)
        assert isinstance(result.get("services"), list)
        assert isinstance(result.get("tls_certs"), list)

        # Report endpoint renders HTML
        rep = client.get(f"{API}/scans/{scan_id}/report")
        assert rep.status_code == 200
        assert "text/html" in rep.headers.get("content-type", "")
        assert "<html" in rep.text.lower() or "<!doctype" in rep.text.lower()

        # Delete and confirm gone
        d = client.delete(f"{API}/scans/{scan_id}")
        assert d.status_code == 200
        assert client.get(f"{API}/scans/{scan_id}").status_code == 404
