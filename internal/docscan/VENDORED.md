# Копії коду DocScan

Ці файли — **дослівні** копії з `yara-docscan` (`docscan-project/watcher-go/`), щоб Hive вирішував так само, як ПК.
Не редагувати. Якщо DocScan змінив оригінал — скопіювати заново й оновити sha256 тут і в `vendored_test.go`.

| Копія | Оригінал | sha256 |
|---|---|---|
| `manifest/manifest.go` | `manifest/manifest.go` | `0050afd63f4877de54c831e316803e5ef6ef10e3a36d94226f27530569be6b5a` |
| `orglists/orglists.go` | `orglists/orglists.go` | `5a08e23c431d40590c1332d0e630870c5cc278fe8ba2f1cf8d99d853e530f60d` |
| `orglists/orglists_test.go` | `orglists/orglists_test.go` | `c88fc959efbd715dd1b50592a41ea61e468480a1c693469d96bcea58a4ac72b0` |

`install/` — **не** копія, а порт шляху встановлення з `updater/rules.go` і `updater/update.go` (`installRulesFile`,
`stageRules`, `unpackVerified`, `compileRules`, `compileCritical`) без служб Windows і без заміни теки правил.
Кожна функція там посилається на свій оригінал; при зміні оригіналу в DocScan — перенести зміну.

Перевірка з чекаутом DocScan: `HIVE_DOCSCAN_GO=<yara-docscan>/docscan-project/watcher-go go test ./internal/docscan/`.
