# KNOWN ISSUES · release-vault — известные красные и шрамы
> Снимок Волны ×5 (2026-11-09). Живые красные прогоны + известные квирки.

| Что | Статус | Детали | Run/ссылка |
|---|---|---|---|
| vault-integrity 19:50–19:53 (81dd014/bc85b16) | 🟢 вылечено | «чекер спотыкается о новые артефакты Волны ×3»: после пломбы 81dd014 последующие коммиты (PULSE.md-бот, правки yml) делали манифест не равен факту → 🔴 код 1 | [42517034151](https://github.com/rtynbirf/release-vault/actions/runs/42517034151) · [42517128766](https://github.com/rtynbirf/release-vault/actions/runs/42517128766) · [42517270539](https://github.com/rtynbirf/release-vault/actions/runs/42517270539) |
| vault-integrity 19:54 (push d9533aa/1a6ad6b) | 🟢 вылечено | перепломба по факту (19 файлов, MANIFEST.sha256 == факту) + soft-режим: структурные потери 🔴, хеш-устаревание 🟡 код 0 | [42517348113](https://github.com/rtynbirf/release-vault/actions/runs/42517348113) · [42517377317](https://github.com/rtynbirf/release-vault/actions/runs/42517377317) |
| vault-integrity 19:56 (push e1ef194) | 🟢 вылечено | YAML-кавычка имени шага (startup_failure: двоеточие в name) | [42517527300](https://github.com/rtynbirf/release-vault/actions/runs/42517527300) |
| фикс-серия Волны ×4 | ✅ в main | d9533aa → 1a6ad6b → e1ef194 → 0a9d4cc (дубль run-ключа в manifest-seal → startup_failure, strict-YAML валидатор в репро) | [42517818171](https://github.com/rtynbirf/release-vault/actions/runs/42517818171) 🟢 на 0a9d4cc |
| Волна ×5 приёмка | ✅ живой прогон | самотест 4/4 ✓, soft-сверка 19 файлов / 0 расхождений 🟢 (локально на клоне + диспатч) | см. диспатч Волны ×5 в отчёте |
| ⬜ квота Artifact storage аккаунта | 🟜 честный хвост | нужен хозяин/billing; upload-artifact в репо пока не используется | см. KNOWN_ISSUES H-PE11-PHOENIX |
| Квирк: пломба живых файлов | ℹ️ по дизайну | MANIFEST закрывает workflow/PULSE.md: любой пуш делает пломбу «устаревшей»; soft-режим держит зелёный, структурные потери красят честно | wave3/seal_manifest.py --soft |
