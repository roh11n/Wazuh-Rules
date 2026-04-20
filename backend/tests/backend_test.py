"""Backend tests for OSINT Pipeline multi-mode API (domain/website/ip/dork/shodan_search)."""
import os
import sys
import time
import asyncio
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/")
API = f"{BASE_URL}/api"

# Make backend package importable for NVD adapter direct test
sys.path.insert(0, "/app/backend")


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


# ── Shodan Search mode validation ───────────────────────
class TestShodanSearchValidation:
    def test_shodan_search_rejects_empty(self, client):
        r = client.post(f"{API}/scans", json={"target": "", "mode": "shodan_search"})
        assert r.status_code == 400

    def test_shodan_search_rejects_whitespace(self, client):
        r = client.post(f"{API}/scans", json={"target": "   ", "mode": "shodan_search"})
        assert r.status_code == 400

    def test_shodan_search_accepts_query(self, client):
        r = client.post(f"{API}/scans", json={
            "target": 'port:22 product:"OpenSSH"', "mode": "shodan_search",
        })
        assert r.status_code == 200
        d = r.json()
        assert d["mode"] == "shodan_search"
        # query is preserved (spaces/colons) in target
        assert "port:22" in d["target"]
        client.delete(f"{API}/scans/{d['id']}")


# ── Shodan Search E2E ───────────────────────────────────
class TestShodanSearchE2E:
    def test_shodan_search_apache_nl_port80(self, client):
        r = client.post(f"{API}/scans", json={
            "target": 'apache country:"NL" port:80', "mode": "shodan_search",
        })
        assert r.status_code == 200
        sid = r.json()["id"]
        final = _poll(client, sid, timeout_s=90)
        assert final and final["status"] == "completed", f"shodan_search scan didn't complete: {final}"

        full = client.get(f"{API}/scans/{sid}").json()
        assert full["mode"] == "shodan_search"
        result = full["result"]
        assert result is not None

        ss = result.get("shodan_search")
        assert ss is not None, "shodan_search block missing"
        assert ss.get("error") is None, f"shodan_search error: {ss.get('error')}"
        # Apache-in-NL:port-80 should yield hundreds of hosts
        assert ss.get("total", 0) > 100, f"expected >100 total, got {ss.get('total')}"
        hits = ss.get("hits") or []
        assert len(hits) > 0, "no hits returned"

        h0 = hits[0]
        assert h0.get("ip"), "first hit missing ip"
        assert h0.get("port") == 80, f"expected port 80, got {h0.get('port')}"
        # product name contains Apache (case-insensitive). Shodan sometimes returns "Apache httpd"
        prod = (h0.get("product") or "").lower()
        assert "apache" in prod, f"first hit product not apache-like: {h0.get('product')}"

        # Keep for the HTML report test below
        pytest.shodan_search_scan_id = sid

    def test_shodan_search_html_report(self, client):
        sid = getattr(pytest, "shodan_search_scan_id", None)
        if not sid:
            pytest.skip("shodan_search scan not created by prior test")
        r = client.get(f"{API}/scans/{sid}/report")
        assert r.status_code == 200
        html = r.text
        assert "Shodan Search" in html, "report missing 'Shodan Search' heading"
        assert "apache" in html.lower(), "report missing query/product"
        # cleanup
        client.delete(f"{API}/scans/{sid}")


# ── IP scan: cves field schema exists ───────────────────
class TestCVEsFieldSchema:
    def test_ip_scan_has_cves_field(self, client):
        # 1.1.1.1 Cloudflare typically has no Shodan vulns — cves should be empty list
        r = client.post(f"{API}/scans", json={"target": "1.1.1.1", "mode": "ip"})
        assert r.status_code == 200
        sid = r.json()["id"]
        final = _poll(client, sid, timeout_s=120)
        assert final and final["status"] == "completed", f"ip scan didn't complete: {final}"

        full = client.get(f"{API}/scans/{sid}").json()
        result = full["result"]
        assert result is not None
        # cves is always a list in schema (may be empty)
        assert "cves" in result, "result.cves key missing (schema should always include it)"
        assert isinstance(result["cves"], list), "result.cves should be a list"
        client.delete(f"{API}/scans/{sid}")


# ── Direct NVDAdapter enrichment (Log4Shell + Heartbleed) ─
class TestNVDAdapterDirect:
    def test_log4shell_and_heartbleed(self):
        from osint.enrichment.nvd_adapter import NVDAdapter

        async def _run():
            nvd = NVDAdapter(db=None)  # no cache -> hits NVD live
            return await nvd.enrich(["CVE-2021-44228", "CVE-2014-0160"])

        details = asyncio.run(_run())
        by_id = {d.cve_id: d for d in details}

        # Log4Shell
        assert "CVE-2021-44228" in by_id, f"Log4Shell missing, got: {list(by_id)}"
        log4j = by_id["CVE-2021-44228"]
        assert log4j.severity == "CRITICAL", f"Log4Shell severity={log4j.severity}"
        assert log4j.cvss_score == 10.0, f"Log4Shell CVSS={log4j.cvss_score}"
        assert log4j.nvd_url and "CVE-2021-44228" in log4j.nvd_url
        assert log4j.description and len(log4j.description) > 0
        assert log4j.published is not None

        # Heartbleed
        assert "CVE-2014-0160" in by_id, "Heartbleed missing"
        hb = by_id["CVE-2014-0160"]
        assert hb.severity == "HIGH", f"Heartbleed severity={hb.severity}"
        # NVD reports CVSS v3.1 = 7.5 for Heartbleed
        assert hb.cvss_score == 7.5, f"Heartbleed CVSS={hb.cvss_score}"


# ── Scoring: CRITICAL CVE bumps risk_score by +15 per CVE (cap 30) ─
class TestScoringCritCVE:
    def test_critical_cve_adds_15_points(self):
        from osint.models import ScanResult, CVEDetail
        from osint.scoring import compute_risk

        base = ScanResult(target="example.com")
        baseline_score = compute_risk(base).risk_score

        with_one_crit = ScanResult(
            target="example.com",
            cves=[CVEDetail(cve_id="CVE-2021-44228", cvss_score=10.0, severity="CRITICAL")],
        )
        s1 = compute_risk(with_one_crit).risk_score
        assert s1 - baseline_score == 15, f"expected +15 for 1 CRITICAL, got +{s1 - baseline_score}"

        with_three_crit = ScanResult(
            target="example.com",
            cves=[
                CVEDetail(cve_id="CVE-1", cvss_score=10.0, severity="CRITICAL"),
                CVEDetail(cve_id="CVE-2", cvss_score=9.5, severity="CRITICAL"),
                CVEDetail(cve_id="CVE-3", cvss_score=9.1, severity="CRITICAL"),
            ],
        )
        s3 = compute_risk(with_three_crit).risk_score
        # cap at +30
        assert s3 - baseline_score == 30, f"expected +30 cap for 3 CRITICAL, got +{s3 - baseline_score}"

