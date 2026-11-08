#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Страж релизных ассетов — еженедельная сверка размеров/хешей против манифестов.

ПРЕДЛОЖЕНИЕ issue #4 (волна ×4 W4-C). Эмерджентное из волны FIX-2 (2026-11-08):
релиз weights-v1 репы singulyar-llm обнаружен ПУСТЫМ (0 из 6 ассетов) при живом
манифесте MANIFEST.txt — без дозора такое замечают только при попытке скачивания.

Что делает (факты, не обещания):
  1. Читает конфиг (assets-watchdog.config.json): список реп, релизов и
     манифестов с ожидаемыми именами/размерами/хешами.
  2. Живым API сверяет каждый релиз: число ассетов, размеры, состояния,
     дубликаты; ассеты нулевой длины — в нарушение (случай d41d8cd9… — md5
     пустого входа, пустой ZIP uace-pml #4); «лёгкие» ассеты скачивает и
     сверяет sha256 с манифестом. Ротация выборки по номеру недели: дозор
     обходит все части за несколько недель, не качая всё каждую неделю.
  3. Скан дерева git (trees API): blob'ы нулевой длины — в нарушение.
  4. Нарушения → отчёт + код 1 (воркфлоу заводит append-only авто-issue,
     дедуп по заголовку). Чисто → код 0.

Честные границы:
  - Смотрятся только ПУБЛИЧНЫЕ репы: GITHUB_TOKEN воркфлоу не читает
    приватные (404) — они добавляются при появлении PAT-секрета.
  - Ключей нет и не будет (закон клетки): дозор не расшифровывает ничего.
    Шифротексты сейфа (релизы import/* этой репы) — зона vault-integrity.
  - Манифест без частей — честный ФАКТ (веса ещё не появлялись,
    см. WEIGHTS.MANIFEST.json singulyar-llm): релиз сверяется структурно
    (пустота/нули/состояния), по хешам — только что есть в манифесте.

Режимы:
  (по умолчанию)   прогон по конфигу; --report FILE дополнительно пишет отчёт
  --selftest       офлайн-самотест на фикстурах (без сети)

stdlib-only, Python 3.11.
"""

import hashlib
import json
import os
import posixpath
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

DEFAULT_CONFIG = "assets-watchdog.config.json"
PARTS_LINE_RE = re.compile(r"^(\S+)\s+(\d+)\s+([0-9a-fA-F]{64})\s*$")
EMPTY_MD5 = "d41d8cd98f00b204e9800998ecf8427e"  # метка случая пустого файла


class ApiNotFound(Exception):
    """404 — объект, за которым послан дозор, не существует."""


def api_raw(path, accept):
    """GET api.github.com{path} → bytes. Честно различает 404 и остальное."""
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""
    headers = {
        "Accept": accept,
        "User-Agent": "assets-watchdog (rtynbirf/release-vault, wave4)",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(f"https://api.github.com{path}", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return r.read()
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise ApiNotFound(path) from e
        raise


def api_json(path):
    return json.loads(api_raw(path, "application/vnd.github+json").decode("utf-8"))


def parse_parts_manifest(text):
    """Строки манифеста «путь  размер  sha256» (формат MANIFEST.txt singulyar-llm
    и родни). Всё остальное (заголовки, проза, URL) молча не совпадает —
    парсер честен к dialect'у: что не похоже на часть, то не часть."""
    parts = []
    for raw in text.splitlines():
        m = PARTS_LINE_RE.match(raw.strip())
        if m:
            path, size, sha = m.group(1), int(m.group(2)), m.group(3).lower()
            parts.append({
                "path": path,
                "name": posixpath.basename(path),
                "size": size,
                "sha256": sha,
            })
    return parts


def check_release(rel, expected, fetch, limit_bytes=0, sample=0):
    """Сверка релиза с ожиданиями манифеста. fetch(asset) → bytes (для
    выборочных хешей; в самотесте — подставка). Возвращает (нарушения,
    предупреждения, факты)."""
    violations, warnings, facts = [], [], []
    tag = rel.get("tag_name", "?")
    assets = rel.get("assets", [])
    facts.append(f"релиз `{tag}`: ассетов {len(assets)}"
                 + ("" if expected else " (манифест без частей — сверка структурная)"))
    if expected and not assets:
        violations.append(
            f"`{tag}`: релиз ПУСТ (0 из {len(expected)} ассетов) — "
            "манифест обещает части, скачивать нечего")

    by_name = {}
    for a in assets:
        by_name.setdefault(a.get("name", "?"), []).append(a)
        if a.get("size") == 0:
            violations.append(
                f"`{tag}`: ассет `{a.get('name')}` НУЛЕВОЙ длины "
                f"(md5 пустого входа {EMPTY_MD5}, случай пустого ZIP uace-pml #4)")
        if a.get("state") != "uploaded":
            violations.append(
                f"`{tag}`: ассет `{a.get('name')}` state={a.get('state')!r} — не uploaded")
    for n, lst in sorted(by_name.items()):
        if len(lst) > 1:
            violations.append(f"`{tag}`: дубликат ассета `{n}` ×{len(lst)}")

    for p in expected:
        lst = by_name.get(p["name"])
        if not lst:
            violations.append(
                f"`{tag}`: ассет `{p['name']}` ОТСУТСТВУЕТ "
                f"(манифест: {p['size']} байт, sha256 {p['sha256'][:12]}…)")
            continue
        a = lst[0]
        if a.get("size") != p["size"]:
            violations.append(
                f"`{tag}`: ассет `{p['name']}` ИЗМЕНИЛСЯ: размер "
                f"{a.get('size')} ≠ манифесту {p['size']}")

    if expected:
        extra = sorted(set(by_name) - {p["name"] for p in expected})
        if extra:
            warnings.append(f"`{tag}`: ассеты вне манифеста: {', '.join(f'`{e}`' for e in extra)}")

    # Выборочная сверка хешей «лёгких» ассетов, ротация по номеру недели
    has_hash = {p["name"]: p["sha256"] for p in expected if p.get("sha256")}
    cands = sorted(
        (lst[0]["size"], n)
        for n, lst in by_name.items()
        if n in has_hash and lst[0].get("size", 0) <= limit_bytes
    )
    if sample and cands:
        week = int(datetime.now(timezone.utc).strftime("%W"))
        off = week % len(cands)
        pick = [cands[(off + i) % len(cands)] for i in range(min(sample, len(cands)))]
        facts.append(
            f"`{tag}`: выборочная сверка хешей (ротация недели {week}, "
            f"лимит {limit_bytes} байт): {', '.join(n for _, n in pick)}")
        for size, name in pick:
            data = fetch(by_name[name][0])
            h = hashlib.sha256(data).hexdigest()
            if h == has_hash[name]:
                facts.append(f"`{tag}/{name}`: sha256 сходится ({size} байт)")
            else:
                violations.append(
                    f"`{tag}/{name}`: sha256 НЕ сходится "
                    f"({h[:12]}… ≠ манифесту {has_hash[name][:12]}…)")
    return violations, warnings, facts


def check_tree(tree, repo_label):
    """Дозор нулевых файлов в git-дереве (trees API, recursive)."""
    violations, warnings, facts = [], [], []
    entries = tree.get("tree", [])
    blobs = [e for e in entries if e.get("type") == "blob"]
    zero = [e["path"] for e in blobs if e.get("size") == 0]
    facts.append(f"дерево `{repo_label}`: blob'ов {len(blobs)}, нулевой длины {len(zero)}")
    for p in sorted(zero):
        violations.append(
            f"`{repo_label}`: в git ФАЙЛ НУЛЕВОЙ ДЛИНЫ: `{p}` "
            f"(md5 пустого входа {EMPTY_MD5})")
    if tree.get("truncated"):
        warnings.append(
            f"`{repo_label}`: API обрезал дерево — дозор слеп на хвост "
            "(repo слишком велик для recursive-обхода)")
    return violations, warnings, facts


def run_config(config):
    """Прогон по конфигу: API-слой. Возвращает (violations, warnings, facts)."""
    violations, warnings, facts = [], [], []
    for entry in config.get("watch", []):
        repo = entry["repo"]
        # --- релизы
        for spec in entry.get("releases", []):
            tag = spec["tag"]
            quoted = urllib.request.quote(tag, safe="")
            try:
                rel = api_json(f"/repos/{repo}/releases/tags/{quoted}")
            except ApiNotFound:
                violations.append(
                    f"`{repo}`: релиз `{tag}` НЕ НАЙДЕН (404) — "
                    "манифест смотрит в пустоту")
                continue
            manifest = spec.get("manifest", {})
            expected = []
            if manifest.get("kind") == "repo_file":
                try:
                    raw = api_raw(
                        f"/repos/{repo}/contents/{urllib.request.quote(manifest['path'])}",
                        "application/vnd.github.raw")
                    expected = parse_parts_manifest(raw.decode("utf-8", "replace"))
                    facts.append(f"`{repo}`: манифест `{manifest['path']}` — частей {len(expected)}")
                except ApiNotFound:
                    violations.append(
                        f"`{repo}`: манифест `{manifest['path']}` НЕ НАЙДЕН (404)")
            dl = spec.get("download_check", {})
            v, w, f = check_release(
                rel, expected,
                fetch=lambda a: api_raw(
                    f"/repos/{repo}/releases/assets/{a['id']}",
                    "application/octet-stream"),
                limit_bytes=int(dl.get("limit_mb", 0)) * 1024 * 1024,
                sample=int(dl.get("sample", 0)),
            )
            violations += v
            warnings += w
            facts += f
        # --- дерево git: нулевые файлы
        if entry.get("git_tree_zero_files"):
            try:
                branch = api_json(f"/repos/{repo}")["default_branch"]
                tree = api_json(f"/repos/{repo}/git/trees/{branch}?recursive=1")
            except ApiNotFound:
                violations.append(f"`{repo}`: репа НЕ НАЙДЕНА (404) — приватна или удалена")
                continue
            v, w, f = check_tree(tree, repo)
            violations += v
            warnings += w
            facts += f
    return violations, warnings, facts


def render_report(violations, warnings, facts):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [f"# assets-watchdog — отчёт {now}", ""]
    lines += ["## Факты", ""] + [f"- {f}" for f in facts] + [""]
    if warnings:
        lines += ["## Предупреждения", ""] + [f"- {w}" for w in warnings] + [""]
    if violations:
        lines += ["## НАРУШЕНИЯ", ""] + [f"- {v}" for v in violations] + [""]
    lines.append(
        f"**Итог: {len(violations)} нарушений, {len(warnings)} предупреждений.** "
        + ("СТРАЖ GREEN." if not violations else "Расхождение манифестов с фактом — требуются действия."))
    return "\n".join(lines) + "\n"


def selftest():
    """Офлайн-самотест: подделки обязаны находиться, чистое — проходить."""
    def part(i, size, sha):
        return {"path": f"MODELS/m.part-{i:02d}-of-02.bin", "name": f"m.part-{i:02d}-of-02.bin",
                "size": size, "sha256": sha}
    sha_a = hashlib.sha256(b"A" * 10).hexdigest()
    sha_b = hashlib.sha256(b"B" * 10).hexdigest()
    expected = [part(1, 10, sha_a), part(2, 10, sha_b)]

    def fetch_of(payloads):
        return lambda a: payloads[a["name"]]

    ok = []

    # 1. парсер манифеста: проза + части → ровно 2 части
    text = ("МАНИФЕСТ\n========\nРазмер: 20 байт\nSHA-256: abcd\n"
            "https://example.com — адрес релиза\n"
            "MODELS/m.part-01-of-02.bin  10  " + sha_a + "\n"
            "MODELS/m.part-02-of-02.bin  10  " + sha_b + "\n")
    ok.append(("парсер находит ровно 2 части", len(parse_parts_manifest(text)) == 2))

    # 2. чистый релиз — ноль нарушений
    clean = {"tag_name": "t", "assets": [
        {"name": "m.part-01-of-02.bin", "size": 10, "state": "uploaded", "id": 1},
        {"name": "m.part-02-of-02.bin", "size": 10, "state": "uploaded", "id": 2}]}
    v, w, f = check_release(clean, expected, fetch_of({
        "m.part-01-of-02.bin": b"A" * 10, "m.part-02-of-02.bin": b"B" * 10}),
        limit_bytes=1024, sample=2)
    ok.append(("чистый релиз — 0 нарушений, хеши сходятся", not v and not w))

    # 3. пустой релиз → нарушение «0 из 2»
    v, _, _ = check_release({"tag_name": "t", "assets": []}, expected, fetch_of({}))
    ok.append(("пустой релиз ловится", any("ПУСТ" in x for x in v)))

    # 4. нулевой ассет → нарушение (случай d41d8cd9…)
    zero = {"tag_name": "t", "assets": [
        {"name": "m.part-01-of-02.bin", "size": 0, "state": "uploaded", "id": 1},
        {"name": "m.part-02-of-02.bin", "size": 10, "state": "uploaded", "id": 2}]}
    v, _, _ = check_release(zero, expected, fetch_of({
        "m.part-01-of-02.bin": b"", "m.part-02-of-02.bin": b"B" * 10}),
        limit_bytes=1024, sample=2)
    ok.append(("нулевой ассет ловится", any("НУЛЕВОЙ" in x for x in v)))

    # 5. размер изменился → нарушение
    fat = {"tag_name": "t", "assets": [
        {"name": "m.part-01-of-02.bin", "size": 11, "state": "uploaded", "id": 1},
        {"name": "m.part-02-of-02.bin", "size": 10, "state": "uploaded", "id": 2}]}
    v, _, _ = check_release(fat, expected, fetch_of({}))
    ok.append(("изменение размера ловится", any("ИЗМЕНИЛСЯ" in x for x in v)))

    # 6. хеш подменён (размер тот же) → нарушение при скачивании
    swapped = {"tag_name": "t", "assets": [
        {"name": "m.part-01-of-02.bin", "size": 10, "state": "uploaded", "id": 1},
        {"name": "m.part-02-of-02.bin", "size": 10, "state": "uploaded", "id": 2}]}
    v, _, _ = check_release(swapped, expected, fetch_of({
        "m.part-01-of-02.bin": b"C" * 10, "m.part-02-of-02.bin": b"B" * 10}),
        limit_bytes=1024, sample=2)
    ok.append(("подмена при том же размере ловится", any("НЕ сходится" in x for x in v)))

    # 7. дерево: нулевой blob + truncation → нарушение и предупреждение
    tree = {"tree": [
        {"type": "blob", "path": "a.txt", "size": 3},
        {"type": "blob", "path": "empty.zip", "size": 0},
        {"type": "tree", "path": "d", "size": 0}], "truncated": True}
    v, w, _ = check_tree(tree, "fixture/repo")
    ok.append(("нулевой blob в git ловится", any("empty.zip" in x for x in v)))
    ok.append(("обрезанное дерево — предупреждение", any("обрезал" in x for x in w)))

    failed = [name for name, passed in ok if not passed]
    for name, passed in ok:
        print(f"  {'✓' if passed else '✗'} {name}")
    if failed:
        print(f"САМОТЕСТ КРАСНЫЙ: {failed}")
        return 1
    print("САМОТЕСТ GREEN: подделки находятся, чистое проходит (офлайн, без сети)")
    return 0


def main():
    argv = sys.argv[1:]
    if "--selftest" in argv:
        return selftest()
    cfg_path = DEFAULT_CONFIG
    report_path = None
    if "--config" in argv:
        cfg_path = argv[argv.index("--config") + 1]
    if "--report" in argv:
        report_path = argv[argv.index("--report") + 1]

    with open(cfg_path, encoding="utf-8") as f:
        config = json.load(f)
    violations, warnings, facts = run_config(config)
    report = render_report(violations, warnings, facts)

    print(report)
    if report_path:
        with open(report_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(report)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write(report)
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
