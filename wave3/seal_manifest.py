#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Пломбировщик MANIFEST.sha256 — вторая половина «дня пломбы» (ПРЕДЛОЖЕНИЕ-19,
issue #1, волна ×3 W3-A2). Дополняет drill волны ×3 W3-A (wave3/restore_drill.py):
drill сверяет манифест с фактом — этот скрипт создаёт манифест и держит его
равным факту, иначе сверять не по чему (критерий приёмки «MANIFEST.sha256 ==
факту»).

Режимы:
  (без аргументов) / --check   манифест == факту? Каждая строка
      «<sha256>␣␣<путь>» сверяется с фактическими байтами; отсутствующий или
      подделанный файл, а также файл вне манифеста — расхождение (код 1).
      Нет манифеста — честная подсказка запломбировать (код 0).
  --soft                       мягкий CI-режим: исчезнувший файл = код 1,
      хеш-устаревание между днями пломбы = 🟡 код 0 (ритм без шума)
  --seal                       пересчитать манифест по факту — детерминированно
      (сортировка по пути, LF): повторный прогон без изменений данных даёт
      байт-в-байт тот же файл и НЕ растит журнал (идемпотентность). Реальная
      перепломба пишет append-строку в wave3/ЖУРНАЛ-ПЛОМБ.md (журнал только
      дополняется; ошибочная строка не стирается — рядом пишется
      корректирующая). Манифест — канон равенства факту, поэтому перепломба
      переписывает именно его, а историю пломб хранит журнал.
  --selftest                   временная папка: запломбировать → сверить →
      подделать один байт → сверка обязана упасть → восстановить → зелёная.
Манифест не включает сам MANIFEST.sha256, .git/ и ЖУРНАЛ-ПЛОМБ.md (журнал
append-only и растёт с каждой пломбой — канон равенства факту это данные
хранилища, история пломб живёт в журнале). Ритуал дня пломбы —
wave3/ДЕНЬ-ПЛОМБЫ.md, сертификат копии №2 — wave3/СЕРТИФИКАТ-КОПИЯ-2.md.
stdlib-only, Python 3.11.
"""

import hashlib
import os
import sys
import tempfile
from datetime import datetime, timezone

MANIFEST = "MANIFEST.sha256"
JOURNAL = os.path.join("wave3", "ЖУРНАЛ-ПЛОМБ.md")
SKIP_DIRS = {".git"}


def root_default():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def inventory(root):
    """Все файлы хранилища, детерминированно: без .git/, манифеста и журнала пломб."""
    skip = {MANIFEST, JOURNAL.replace(os.sep, "/")}
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for fn in sorted(filenames):
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if rel not in skip:
                out.append(rel)
    return sorted(out)


def digest(root, rel):
    h = hashlib.sha256()
    with open(os.path.join(root, rel), "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def manifest_bytes(root):
    return ("\n".join("%s  %s" % (digest(root, rel), rel) for rel in inventory(root)) + "\n").encode("utf-8")


def read_manifest(root):
    path = os.path.join(root, MANIFEST)
    if not os.path.exists(path):
        return None
    want = {}
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            s = line.rstrip("\n")
            if not s:
                continue
            p = s.split("  ", 1)
            if len(p) != 2 or len(p[0]) != 64:
                raise SystemExit("МАНИФЕСТ: строка %d не формата «<sha256>  <путь>»" % n)
            want[p[1]] = p[0]
    return want


def cmd_check(root, soft=False):
    """--soft (для живого CI между днями пломбы): структурные потери
    (файл манифеста исчез) = 🔴 код 1 — это подмена или поломка;
    хеш-расхождение на живом дереве = пломба отстала от развития
    (ожидаемо между ритуалами) = 🟡 честный доклад, код 0.
    Полный строгий режим (без --soft) — канон дня пломбы, код 1 при любом
    расхождении. Самотест проверяет ОБА режима."""
    want = read_manifest(root)
    if want is None:
        print("ПЛОМБА: %s нет — запломбируйте: python3 wave3/seal_manifest.py --seal" % MANIFEST)
        return 0
    fact = {rel: digest(root, rel) for rel in inventory(root)}
    gone = sorted(rel for rel in want if rel not in fact)
    stale = sorted(rel for rel in want if rel in fact and want[rel] != fact[rel])
    extra = [rel for rel in sorted(fact) if rel not in want]
    for rel in gone:
        print("ПОТЕРЯ: %s — файла нет (подмена/поломка) 🔴" % rel)
    for rel in stale:
        print("УСТАРЕЛО: %s (в манифесте %s…)" % (rel, want[rel][:12]))
    for rel in extra:
        print("ВНЕ МАНИФЕСТА: %s — перепломбируйте (--seal)" % rel)
    mode = "soft" if soft else "strict"
    if gone:
        print("ПЛОМБА[%s]: файлов %d · потерь %d · устарело %d · вне манифеста %d · вердикт 🔴"
              % (mode, len(fact), len(gone), len(stale), len(extra)))
        return 1
    if stale or extra:
        if soft:
            print("ПЛОМБА[%s]: файлов %d · потерь 0 · устарело %d · вне манифеста %d · вердикт 🟡 пломба отстала от факта — день пломбы: python3 wave3/seal_manifest.py --seal"
                  % (mode, len(fact), len(stale), len(extra)))
            return 0
        print("ПЛОМБА[%s]: файлов %d · потерь 0 · устарело %d · вне манифеста %d · вердикт 🔴"
              % (mode, len(fact), len(stale), len(extra)))
        return 1
    print("ПЛОМБА[%s]: файлов %d · расхождений 0 · вердикт 🟢 равен факту" % (mode, len(fact)))
    return 0


def journal_append(root, text):
    path = os.path.join(root, JOURNAL)
    if not os.path.exists(path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("# Журнал пломб манифеста · append-only (ПРЕДЛОЖЕНИЕ-19, issue #1)\n\n"
                     "Дописывается seal_manifest.py при каждой РЕАЛЬНОЙ перепломбе; строки\n"
                     "не переписываются, ошибочная строка не стирается — рядом пишется\n"
                     "корректирующая. Ритуал дня пломбы — wave3/ДЕНЬ-ПЛОМБЫ.md;\n"
                     "сертификат копии №2 — wave3/СЕРТИФИКАТ-КОПИЯ-2.md.\n\n")
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(text)


def journal_entries(root):
    path = os.path.join(root, JOURNAL)
    if not os.path.exists(path):
        return 0
    return sum(1 for l in open(path, encoding="utf-8") if l.startswith("- "))


def cmd_seal(root):
    blob = manifest_bytes(root)
    path = os.path.join(root, MANIFEST)
    if os.path.exists(path) and open(path, "rb").read() == blob:
        print("ПЛОМБА: без изменений (идемпотентно) · файлов %d · журнал не растёт" % blob.count(b"\n"))
        return 0
    with open(path, "wb") as fh:
        fh.write(blob)
    mh = hashlib.sha256(blob).hexdigest()
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    journal_append(root, "- %s · пломба: %d файлов · SHA256 манифеста %s\n"
                   % (stamp, blob.count(b"\n"), mh[:12]))
    print("ПЛОМБА: запломбировано %d файлов · SHA256 манифеста %s" % (blob.count(b"\n"), mh[:12]))
    print("Журнал: %s (append-only) · SHA256 манифеста — в сертификат копии №2 при дне пломбы" % JOURNAL)
    return 0


def selftest():
    ok = []

    def ck(name, cond):
        ok.append(bool(cond))
        print("САМОПРОБА %s %s" % (name, "✓" if cond else "✗ ПРОВАЛ"))

    with tempfile.TemporaryDirectory() as td:
        os.makedirs(os.path.join(td, "wave3"))
        open(os.path.join(td, "a.txt"), "wb").write(b"alpha\n")
        open(os.path.join(td, "wave3", "b.txt"), "wb").write(b"beta\n")
        cmd_seal(td)
        ck("1 (seal → check зелёный)", cmd_check(td) == 0)
        blob = open(os.path.join(td, MANIFEST), "rb").read()
        cmd_seal(td)
        ck("2 (повторный seal идемпотентен, журнал не растёт)",
           open(os.path.join(td, MANIFEST), "rb").read() == blob and journal_entries(td) == 1)
        p = os.path.join(td, "wave3", "b.txt")
        data = open(p, "rb").read()
        open(p, "wb").write(data[:-1] + bytes([data[-1] ^ 0x01]))   # подмена ровно 1 байта
        ck("3 (подделка 1 байта ловится, код 1)", cmd_check(td) == 1)
        open(p, "wb").write(data)
        ck("4 (восстановление байта → снова зелёный)", cmd_check(td) == 0)
    print("САМОПРОБА: %d/%d ✓" % (sum(ok), len(ok)))
    sys.exit(0 if all(ok) else 1)


def main():
    args = sys.argv[1:]
    if "--selftest" in args:
        selftest()
        return
    root = os.path.abspath(args[args.index("--root") + 1]) if "--root" in args else root_default()
    if "--seal" in args:
        sys.exit(cmd_seal(root))
    sys.exit(cmd_check(root, soft="--soft" in args))


if __name__ == "__main__":
    main()
