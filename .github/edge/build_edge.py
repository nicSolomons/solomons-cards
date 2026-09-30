"""Build the live viewer-request function from the deploy repo (Daniel's audit F16; Nicole's option A, 2026-09-30).

Usage:  python build_edge.py --repo . --out /tmp/viewer-request.js      (run by deploy-aws.yml on every deploy)

The list of published files is taken from the repo itself, with the same exclusions as the bucket sync, so the
edge list and the bucket can only differ if a deploy step failed (and then the deploy's own verify step fails).
The not-found page is the repo's own 404.html. Refuses to build a function over CloudFront's 10 KB limit.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE = os.path.join(HERE, "cards-viewer-request.template.js")
SKIP_TOP = {".git", ".github"}
SKIP_ROOT_FILES = {"index.html", ".nojekyll", ".gitattributes"}  # the sync's --exclude list (README* too)
MAX_BYTES = 10240


def published(repo):
    """Every file the bucket sync publishes, as paths relative to the repo root with forward slashes."""
    out = set()
    for dirpath, dirnames, filenames in os.walk(repo):
        rel_dir = os.path.relpath(dirpath, repo)
        if rel_dir == ".":
            dirnames[:] = [d for d in dirnames if d not in SKIP_TOP]
        for f in filenames:
            rel = f if rel_dir == "." else os.path.join(rel_dir, f).replace(os.sep, "/")
            if rel_dir == "." and (f in SKIP_ROOT_FILES or f.startswith("README")):
                continue
            out.add(rel)
    return sorted(out)


def build(repo):
    files = published(repo)
    page = open(os.path.join(repo, "404.html"), encoding="utf-8").read()
    src = open(TEMPLATE, encoding="utf-8").read()
    for marker in ("/*PUBLISHED*/{}", "/*NOT_FOUND_HTML*/''"):
        if src.count(marker) != 1:
            raise SystemExit(f"FAIL: template marker {marker} not found exactly once")
    src = src.replace("/*PUBLISHED*/{}", json.dumps({f: 1 for f in files}, separators=(",", ":")))
    src = src.replace("/*NOT_FOUND_HTML*/''", json.dumps(page))
    size = len(src.encode("utf-8"))
    if size > MAX_BYTES:
        raise SystemExit(f"FAIL: built function is {size} bytes, over CloudFront's {MAX_BYTES}-byte limit")
    return src, files, size


def main():
    repo = sys.argv[sys.argv.index("--repo") + 1] if "--repo" in sys.argv else "."
    out = sys.argv[sys.argv.index("--out") + 1]
    src, files, size = build(repo)
    open(out, "w", encoding="utf-8", newline="\n").write(src)
    print(f"edge list: {len(files)} published files; function {size} bytes -> {out}")
    for f in files:
        print("  " + f)


if __name__ == "__main__":
    main()
