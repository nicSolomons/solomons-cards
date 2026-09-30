"""The deploy's own last step (deploy-aws.yml): prove what visitors now get, or fail the deploy loudly.

Usage:  python verify_edge.py --repo .

Every published card page loads (200), and a made-up address gets the card-not-found page (404) with the full
security headers and no S3 server name. Retries for up to 4 minutes while CloudFront propagates the function;
then fails, which turns the deploy red and GitHub emails the repo owner.
"""
import http.client
import os
import ssl
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from build_edge import published  # noqa: E402

DOMAIN = "solomonsdigital.com.au"
HEADERS = {"content-security-policy": "default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; font-src data:; "
                                      "base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
           "x-robots-tag": "noindex, nofollow, noarchive", "strict-transport-security": "max-age=31536000; includeSubDomains"}


def get(path):
    c = http.client.HTTPSConnection(DOMAIN, timeout=20, context=ssl.create_default_context())
    c.request("GET", path, headers={"User-Agent": "deploy-verify", "Cache-Control": "no-cache"})
    r = c.getresponse()
    body = r.read()
    h = {k.lower(): v for k, v in r.getheaders()}
    c.close()
    return r.status, h, body


def attempt(repo):
    problems = []
    for f in published(repo):
        if f.endswith("/index.html"):
            s, _, _ = get("/" + f[: -len("index.html")])
            if s != 200:
                problems.append(f"/{f[:-len('index.html')]} answered {s}, expected 200")
    for path in (f"/no-such-card-{uuid.uuid4().hex[:8]}/", f"/{uuid.uuid4().hex[:8]}.png"):
        s, h, body = get(path)
        wrong = {k: h.get(k) for k, v in HEADERS.items() if h.get(k) != v}
        if s != 404 or wrong or h.get("server", "cloudfront").lower() != "cloudfront" or b"This card was not found" not in body:
            problems.append(f"{path}: {s}, header mismatches {wrong}, server {h.get('server')}")
    return problems


def main():
    repo = sys.argv[sys.argv.index("--repo") + 1] if "--repo" in sys.argv else "."
    deadline = time.time() + 240
    while True:
        problems = attempt(repo)
        if not problems:
            print("EDGE VERIFY: PASS (every card loads; unknown addresses get the not-found page with full headers)")
            return
        if time.time() > deadline:
            print("EDGE VERIFY: FAIL\n  " + "\n  ".join(problems))
            raise SystemExit(1)
        time.sleep(15)


if __name__ == "__main__":
    main()
