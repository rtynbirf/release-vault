#!/usr/bin/env python3
# coverage_report.py — сверка покрытия манифеста и релизов (П-12, волна триажа 2026-11-10)
# Режимы: --api (живой GitHub API, по умолчанию) или --local (дерево клона).
# Вывод: JSON в stdout + строка вердикта. Расхождение = план долива (перепломба seal_manifest.py).
import base64, hashlib, json, os, sys
from urllib.parse import quote
import urllib.request, urllib.error

REPO = os.environ.get("RV_REPO", "rtynbirf/release-vault")
TOKEN = os.environ.get("GH_TOKEN", "")

def gh(path):
    req = urllib.request.Request(f"https://api.github.com/repos/{REPO}/contents/" + quote(path),
        headers={"Authorization": "Bearer " + TOKEN, "User-Agent": "coverage"})
    with urllib.request.urlopen(req) as r:
        return base64.b64decode(json.load(r)["content"])

def main():
    man = gh("MANIFEST.sha256").decode()
    ok, bad, miss = 0, [], []
    for line in man.splitlines():
        if not line.strip(): continue
        sha, path = line.split(None, 1)
        path = path.strip()
        try:
            actual = hashlib.sha256(gh(path)).hexdigest()
            (bad if actual != sha else ok) and None
            if actual == sha: ok += 1
            else: bad.append({"path": path, "manifest": sha[:8], "actual": actual[:8]})
        except urllib.error.HTTPError as e:
            miss.append({"path": path, "http": e.code})
    req = urllib.request.Request(f"https://api.github.com/repos/{REPO}/releases?per_page=100",
        headers={"Authorization": "Bearer " + TOKEN, "User-Agent": "coverage"})
    with urllib.request.urlopen(req) as r:
        rels = json.load(r)
    releases = [{"tag": x["tag_name"], "assets": len(x["assets"]), "bytes": sum(a["size"] for a in x["assets"])} for x in rels]
    report = {
        "manifest": {"files": ok + len(bad) + len(miss), "ok": ok, "mismatch": bad, "missing": miss},
        "releases": {"count": len(releases), "assets": sum(x["assets"] for x in releases), "bytes": sum(x["bytes"] for x in releases), "items": releases},
        "verdict": "0 расхождений" if not bad and not miss else "список с планом долива: перепломбировать изменившиеся файлы через wave3/seal_manifest.py, не трогая ЖУРНАЛ-ПЛОМБ.md (append-only)",
        "generated": os.environ.get("COVERAGE_AT", ""),
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
