"""Goal 21 Phase 8 item 3: daily tamper watch. Prints TAMPER WATCH PASS n/n; exits 1 on any difference.

WHAT IT PROVES: every file the deploy repo holds in a card folder, plus robots.txt, is served by
https://solomonsdigital.com.au byte for byte (sha256), from one CloudFront edge. A difference means the
bucket or the delivery network changed a PUBLISHED file.

WHAT IT DOES NOT PROVE (Daniel's audit T10, F15; stated so no reader assumes more):
  - an object ADDED to the bucket (a /phish/ page, an extra file in a card folder) is never requested.
    `--inventory` lists the bucket and fails on any object the repo does not hold; it needs AWS read access
    (a read-only role for the runner is an open decision), so the scheduled run does not use it yet.
  - the reference is the deploy repo itself: a commit pushed to it deploys and then compares equal. That the
    repo matches the human approvals is parity.py's job, run on the laptop that holds the approvals.
  - that the watch still runs: watch_liveness.py reads the last successful scheduled run.
  - the old GitHub Pages copy (nicsolomons.github.io/solomons-cards) is not watched.
Stdlib only (plus the AWS CLI for --inventory), so it runs on the laptop and on a GitHub runner.

Usage:  python tamper_watch.py [--repo PATH] [--inventory]
"""
import hashlib
import http.client
import os
import ssl
import sys
import time

DOMAIN = "solomonsdigital.com.au"
BUCKET = "solomonsdigital-cards-484474575484"
SKIP_TOP = {".git", ".github"}
CHECKS = []


def check(label, ok, detail=""):
    CHECKS.append(bool(ok))
    print(("PASS " if ok else "FAIL ") + label + (f"  ({detail})" if detail and not ok else ""))


def edge_ips():
    """Every edge address the domain resolves to from here (audit F15: the watch used one edge only)."""
    import socket
    return sorted({ai[4][0] for ai in socket.getaddrinfo(DOMAIN, 443, socket.AF_INET, socket.SOCK_STREAM)})


def fetch(path, ip=None, tries=3):
    for i in range(tries):
        try:
            c = http.client.HTTPSConnection(DOMAIN, timeout=20, context=ssl.create_default_context())
            if ip:  # this edge address, certificate still checked for the real name
                import socket
                c.sock = c._context.wrap_socket(socket.create_connection((ip, 443), timeout=20), server_hostname=DOMAIN)
            c.request("GET", path, headers={"User-Agent": "goal21-tamper-watch", "Cache-Control": "no-cache"})
            r = c.getresponse()
            return r.status, r.read()
        except OSError:
            if i == tries - 1:
                raise
            time.sleep(5)


def published_files(repo):
    out = ["robots.txt"] + (["404.html"] if os.path.isfile(os.path.join(repo, "404.html")) else [])
    for top in sorted(os.listdir(repo)):
        full = os.path.join(repo, top)
        if top in SKIP_TOP or not os.path.isdir(full):
            continue
        for root, _, files in os.walk(full):
            for f in sorted(files):
                out.append(os.path.relpath(os.path.join(root, f), repo).replace(os.sep, "/"))
    return out


def main():
    repo = sys.argv[sys.argv.index("--repo") + 1] if "--repo" in sys.argv else (
        "." if os.path.isfile("robots.txt") else os.path.expanduser("~/solomons-cards"))
    files = published_files(repo)
    ips = edge_ips()
    print(f"comparing {len(files)} published files in {os.path.abspath(repo)} with https://{DOMAIN}/ "
          f"through {len(ips)} edge addresses")
    for rel in files:
        want = hashlib.sha256(open(os.path.join(repo, rel), "rb").read()).hexdigest()
        wrong = []
        for ip in ips:
            status, body = fetch("/" + rel, ip)
            got = hashlib.sha256(body).hexdigest()
            if status != 200 or got != want:
                wrong.append(f"{ip}: HTTP {status}, {got[:12]}")
        check(f"/{rel} live matches the published copy at every edge address", ips and not wrong,
              f"committed {want[:12]}; {wrong}")
    # the edge list is current and in force (audit F16, option A): a made-up address is answered at the edge with the
    # not-found page and the full headers. A skipped or failed list refresh, or a removed step, fails here next morning.
    import uuid
    c = http.client.HTTPSConnection(DOMAIN, timeout=20, context=ssl.create_default_context())
    c.request("GET", f"/no-such-card-{uuid.uuid4().hex[:8]}/", headers={"User-Agent": "goal21-tamper-watch"})
    r = c.getresponse()
    body = r.read()
    h = {k.lower(): v for k, v in r.getheaders()}
    check("a made-up address gets the not-found page at the edge, with CSP and noindex, no S3 server name",
          r.status == 404 and b"This card was not found" in body and "default-src 'none'" in h.get("content-security-policy", "")
          and "noindex" in h.get("x-robots-tag", "") and h.get("server", "cloudfront").lower() == "cloudfront",
          f"HTTP {r.status}, csp={h.get('content-security-policy')!r:.40}, server={h.get('server')}")
    if "--inventory" in sys.argv:
        import json
        import subprocess
        r = subprocess.run(["aws", "s3api", "list-objects-v2", "--bucket", BUCKET, "--output", "json"],
                           capture_output=True, text=True)
        if r.returncode != 0:
            check("bucket inventory could be read", False, r.stderr.strip()[:200])
        else:
            objects = {o["Key"]: o["ETag"].strip('"') for o in json.loads(r.stdout or "{}").get("Contents", [])}
            extra = sorted(set(objects) - set(files))
            check(f"the bucket holds nothing the deploy repo does not ({len(objects)} objects)", not extra, extra[:20])
            # the ORIGIN itself: every edge serves from these bytes. The listing carries each object's MD5 (ETag), so a
            # file changed in the bucket shows here whichever edge would have served it (audit F15)
            changed = [k for k in files if k in objects and
                       objects[k] != hashlib.md5(open(os.path.join(repo, k), "rb").read()).hexdigest()]
            check("every object in the bucket has exactly the bytes of its committed file (MD5 from the listing)",
                  not changed and all(f in objects for f in files), changed[:20] or sorted(set(files) - set(objects)))
    n = len(CHECKS)
    print(f"\nTAMPER WATCH ({DOMAIN}): {'PASS' if all(CHECKS) else 'FAIL'} {sum(CHECKS)}/{n}")
    if not all(CHECKS):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
