"""Backend tests for OSINT Pipeline multi-mode API (domain/website/ip/dork)."""
import os
import time
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/")
API = f"{BASE_URL}/api"


@pytest.fixture(scope="module")
def client():
    s = requests.Session()
    s.headers.update({"Content-Type": "application/json"})
    return s


def _poll(client, scan_id, timeout_s=120):
    deadline = time.time() + timeout_s
    last = None
    while time.time() < deadline:
        r = client.get(f"{API}/scans/{scan_id}/status")
        assert r.status_code == 200
        last = r.json()
        if last["status"] in ("completed", "failed"):
            return last
        time.sleep(3)
    return last


# ── Health ──────────────────────────────────────────────
class TestHealth:
    def test_root(self, client):
        r = client.get(f"{API}/")
        assert r.status_code == 200
        assert r.json().get("status") == "ok"


# ── Settings (shodan_key) ───────────────────────────────
class TestSettings:
    def test_get_settings_has_shodan_flags(self, client):
        r = client.get(f"{API}/settings")
        assert r.status_code == 200
        d = r.json()
        assert "shodan_key" in d
        assert "shodan_key_set" in d
        assert isinstance(d["shodan_key_set"], bool)

    def test_put_shodan_key_persisted(self, client):
        # Save real key from env via PUT — but do not overwrite env key; we save a dummy and then restore real one.
        payload = {"shodan_key": "TESTshodan_key_1234567890abcd"}
        r = client.put(f"{API}/settings", json=payload)
        assert r.status_code == 200
        assert r.json().get("ok") is True

        g = client.get(f"{API}/settings").json()
        assert g["shodan_key_set"] is True
        assert g["shodan_key"].endswith("abcd")
        # restore real key so E2E Shodan tests still work
        real = os.environ.get("SHODAN_KEY") or "0BXChZZudHwhQPdDGSNRYZJyOUdLP4m6"
        client.put(f"{API}/settings", json={"shodan_key": real})


# ── Mode validation ─────────────────────────────────────
class TestModeValidation:
    def test_ip_mode_accepts_valid_ipv4(self, client):
        r = client.post(f"{API}/scans", json={"target": "8.8.8.8", "mode": "ip"})
        assert r.status_code == 200
        data = r.json()
        assert data["mode"] == "ip"
        assert data["target"] == "8.8.8.8"
        assert data["status"] in ("queued", "running")
        # cleanup
        client.delete(f"{API}/scans/{data['id']}")

    def test_ip_mode_rejects_invalid_ip(self, client):
        r = client.post(f"{API}/scans", json={"target": "8.8.8", "mode": "ip"})
        assert r.status_code == 400

    def test_ip_mode_rejects_domain(self, client):
        r = client.post(f"{API}/scans", json={"target": "example.com", "mode": "ip"})
        assert r.status_code == 400

    def test_website_mode_creates_scan(self, client):
        r = client.post(f"{API}/scans", json={
            "target": "example.com", "mode": "website",
            "skip_screenshots": True, "skip_dorking": True, "skip_directories": True,
        })
        assert r.status_code == 200
        d = r.json()
        assert d["mode"] == "website"
        client.delete(f"{API}/scans/{d['id']}")

    def test_dork_mode_creates_scan(self, client):
        r = client.post(f"{API}/scans", json={
            "target": "example.com", "mode": "dork",
            "dork_queries": ["site:{target} filetype:pdf"],
        })
        assert r.status_code == 200
        d = r.json()
        assert d["mode"] == "dork"
        client.delete(f"{API}/scans/{d['id']}")

    def test_domain_mode_stored(self, client):
        r = client.post(f"{API}/scans", json={
            "target": "example.com", "mode": "domain",
            "skip_screenshots": True, "skip_dorking": True,
        })
        assert r.status_code == 200
        d = r.json()
        assert d["mode"] == "domain"
        scan_id = d["id"]
        # GET single scan returns mode
        full = client.get(f"{API}/scans/{scan_id}").json()
        assert full.get("mode") == "domain"
        client.delete(f"{API}/scans/{scan_id}")


# ── List endpoint contains mode ─────────────────────────
class TestListHasMode:
    def test_list_scans_have_mode(self, client):
        # create one
        r = client.post(f"{API}/scans", json={"target": "8.8.8.8", "mode": "ip"})
        sid = r.json()["id"]
        lst = client.get(f"{API}/scans").json()
        assert isinstance(lst, list) and len(lst) > 0
        row = next((x for x in lst if x["id"] == sid), None)
        assert row is not None
        assert row.get("mode") == "ip"
        client.delete(f"{API}/scans/{sid}")


# ── E2E IP scan ─────────────────────────────────────────
class TestIPScanE2E:
    def test_ip_scan_8888_completes_with_shodan(self, client):
        r = client.post(f"{API}/scans", json={"target": "8.8.8.8", "mode": "ip"})
        assert r.status_code == 200
        sid = r.json()["id"]
        final = _poll(client, sid, timeout_s=120)
        assert final and final["status"] == "completed", f"IP scan did not complete: {final}"

        full = client.get(f"{API}/scans/{sid}").json()
        assert full["mode"] == "ip"
        result = full["result"]
        assert result is not None

        # Shodan
        shodan = result.get("shodan") or []
        assert len(shodan) >= 1, "No shodan result"
        s0 = shodan[0]
        assert s0.get("found") is True, f"Shodan lookup failed: {s0}"
        assert "google" in (s0.get("org") or "").lower(), f"org not Google: {s0.get('org')}"
        ports = s0.get("ports") or []
        assert (443 in ports) or (53 in ports), f"expected 443 or 53 in ports: {ports}"

        # IP WHOIS, passive DNS, services (TCP scan)
        assert result.get("ip_whois"), "ip_whois missing"
        assert isinstance(result.get("passive_dns"), list) and len(result.get("passive_dns")) > 0, \
            "passive_dns empty"
        assert isinstance(result.get("services"), list) and len(result.get("services")) > 0, \
            "services (tcp) empty"

        client.delete(f"{API}/scans/{sid}")


# ── E2E Website scan ────────────────────────────────────
class TestWebsiteScanE2E:
    def test_website_scan_example_com(self, client):
        r = client.post(f"{API}/scans", json={
            "target": "example.com", "mode": "website",
            "skip_screenshots": True, "skip_dorking": True, "skip_directories": True,
        })
        assert r.status_code == 200
        sid = r.json()["id"]
        final = _poll(client, sid, timeout_s=120)
        assert final and final["status"] == "completed", f"Website scan did not complete: {final}"

        full = client.get(f"{API}/scans/{sid}").json()
        assert full["mode"] == "website"
        result = full["result"]
        assert result is not None

        assert isinstance(result.get("live_hosts"), list) and len(result["live_hosts"]) > 0, "live_hosts empty"
        assert isinstance(result.get("tls_certs"), list) and len(result["tls_certs"]) > 0, "tls_certs empty"
        assert isinstance(result.get("tech_fingerprints"), list) and len(result["tech_fingerprints"]) > 0, \
            "tech_fingerprints empty"
        assert result.get("dns_records"), "dns_records empty"
        assert isinstance(result.get("ips"), list) and len(result["ips"]) > 0, "ips empty"
        assert result.get("ip_whois"), "ip_whois empty"
        # website mode should NOT enumerate subdomains
        subs = result.get("subdomains") or []
        assert len(subs) == 0, f"website mode should not have subdomains, got: {subs}"

        client.delete(f"{API}/scans/{sid}")


# ── E2E Full Domain scan ────────────────────────────────
class TestDomainScanE2E:
    def test_domain_scan_example_com(self, client):
        r = client.post(f"{API}/scans", json={
            "target": "example.com", "mode": "domain",
            "skip_screenshots": True, "skip_dorking": True,
        })
        assert r.status_code == 200
        sid = r.json()["id"]
        final = _poll(client, sid, timeout_s=150)
        assert final and final["status"] == "completed", f"Domain scan did not complete: {final}"

        full = client.get(f"{API}/scans/{sid}").json()
        assert full["mode"] == "domain"
        result = full["result"]
        assert result is not None

        assert result.get("domain"), "domain empty"
        assert result.get("dns_records"), "dns_records empty"
        assert isinstance(result.get("subdomains"), list), "subdomains missing"
        # shodan per-IP lookups populated for domain mode
        assert isinstance(result.get("shodan"), list) and len(result["shodan"]) > 0, "shodan empty in domain mode"
        assert result.get("ip_whois"), "ip_whois empty"

        client.delete(f"{API}/scans/{sid}")
