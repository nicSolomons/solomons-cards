"""Goal 21 Phase 8 item 3: daily tamper watch. Prints TAMPER WATCH PASS n/n; exits 1 on any difference.

Every file the deploy workflow publishes (every file in a card folder of the solomons-cards checkout,
plus robots.txt) is fetched from https://solomonsdigital.com.au and compared byte for byte (sha256)
with the committed copy. A difference means the bucket or the delivery network serves something Nicole
did not publish. Stdlib only, so it runs unchanged on the laptop and on a GitHub runner.

Usage:  python tamper_watch.py [--repo PATH]      (default: the solomons-cards checkout beside this room,
                                                  or the current folder when run inside it)
Source of truth today = the deploy repo (every commit comes from Nicole's generator publish; main is
locked against rewrite). After the generator-online charter's cutover the approved records move online,
and this watch must be repointed at that copy (recorded in goal 21 Open Items).
"""
import hashlib
import http.client
import os
import ssl
import sys
import time

DOMAIN = "solomonsdigital.com.au"
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
    out = ["robots.txt"]
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
    n = len(CHECKS)
    print(f"\nTAMPER WATCH ({DOMAIN}): {'PASS' if all(CHECKS) else 'FAIL'} {sum(CHECKS)}/{n}")
    if not all(CHECKS):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
