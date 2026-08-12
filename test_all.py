"""SentinelGraph — Full Functionality Test"""
import requests
import json

print("=" * 60)
print("  SentinelGraph - Full Functionality Test")
print("=" * 60)

passed = 0
failed = 0


def test(name, url, expected=200):
    global passed, failed
    try:
        r = requests.get(url, timeout=10)
        if r.status_code == expected:
            print(f"  [PASS] {name} -> {r.status_code}")
            passed += 1
            return r
        else:
            print(f"  [FAIL] {name} -> {r.status_code} (expected {expected})")
            failed += 1
            return None
    except Exception as e:
        print(f"  [FAIL] {name} -> {e}")
        failed += 1
        return None


print()
print("[Backend API - http://localhost:8000]")
print("-" * 40)

test("API Root", "http://localhost:8000/")
test("Health Check", "http://localhost:8000/health")
test("Swagger Docs", "http://localhost:8000/docs")
test("Scan Status", "http://localhost:8000/api/v1/scan/status")

r = test("Full Results", "http://localhost:8000/api/v1/results")
if r:
    d = r.json()
    target = d.get("target", "?")
    findings = d.get("total_findings", "?")
    sc = d.get("severity_counts", {})
    print(f"     Target: {target}")
    print(f"     Findings: {findings}")
    crit = sc.get("critical", 0)
    high = sc.get("high", 0)
    med = sc.get("medium", 0)
    low = sc.get("low", 0)
    info = sc.get("info", 0)
    print(f"     Critical:{crit} High:{high} Med:{med} Low:{low} Info:{info}")

test("Summary", "http://localhost:8000/api/v1/results/summary")
test("Filter: critical", "http://localhost:8000/api/v1/results/findings?severity=critical")
test("Filter: medium", "http://localhost:8000/api/v1/results/findings?severity=medium")
test("Filter: ssti", "http://localhost:8000/api/v1/results/findings?category=ssti")
test("HTML Report", "http://localhost:8000/api/v1/report")
test("SARIF Report", "http://localhost:8000/api/v1/report/sarif")

print()
print("[Frontend - http://localhost:3000]")
print("-" * 40)

test("Dashboard", "http://localhost:3000/")
test("Scan Data JSON", "http://localhost:3000/scan_results.json")
test("HTML Report File", "http://localhost:3000/full_report.html")

# Test POST scan trigger (just validation, don't actually run)
print()
print("[Scan Trigger Test]")
print("-" * 40)
try:
    r = requests.post(
        "http://localhost:8000/api/v1/scan",
        json={"target_url": "https://example.com", "scan_type": "quick"},
        timeout=5,
    )
    if r.status_code in (200, 400):
        print(f"  [PASS] POST /api/v1/scan -> {r.status_code}")
        passed += 1
    else:
        print(f"  [FAIL] POST /api/v1/scan -> {r.status_code}")
        failed += 1
except Exception as e:
    print(f"  [FAIL] POST /api/v1/scan -> {e}")
    failed += 1

print()
print("=" * 60)
total = passed + failed
print(f"  TOTAL: {passed} PASSED / {failed} FAILED / {total} tests")
print("=" * 60)
