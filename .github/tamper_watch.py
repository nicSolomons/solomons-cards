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


def fetch(path, tries=3):
    for i in range(tries):
        try:
            c = http.client.HTTPSConnection(DOMAIN, timeout=20, context=ssl.create_default_context())
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
    print(f"comparing {len(files)} published files in {os.path.abspath(repo)} with https://{DOMAIN}/")
    for rel in files:
        want = hashlib.sha256(open(os.path.join(repo, rel), "rb").read()).hexdigest()
        status, body = fetch("/" + rel)
        got = hashlib.sha256(body).hexdigest()
        check(f"/{rel} live matches the published copy", status == 200 and got == want,
              f"HTTP {status}, live {got[:12]} vs committed {want[:12]}")
    if "--inventory" in sys.argv:
        import json
        import subprocess
        r = subprocess.run(["aws", "s3api", "list-objects-v2", "--bucket", BUCKET, "--output", "json"],
                           capture_output=True, text=True)
        if r.returncode != 0:
            check("bucket inventory could be read", False, r.stderr.strip()[:200])
        else:
            keys = {o["Key"] for o in json.loads(r.stdout or "{}").get("Contents", [])}
            extra = sorted(keys - set(files))
            check(f"the bucket holds nothing the deploy repo does not ({len(keys)} objects)", not extra, extra[:20])
    n = len(CHECKS)
    print(f"\nTAMPER WATCH ({DOMAIN}): {'PASS' if all(CHECKS) else 'FAIL'} {sum(CHECKS)}/{n}")
    if not all(CHECKS):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
