package vendor

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strings"
)

// dumpPy — константи build_vendor_rules.py як JSON (модуль імпортується без запуску main; python3 -I — без
// змінних середовища й теки скрипта в sys.path, крім самого файлу).
const dumpPy = `
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("bvr", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
drop = []
for k, v in m.DROP.items():
    if isinstance(k, tuple):
        drop.append({"file": k[0], "rule": k[1], "reason": v})
    else:
        drop.append({"file": "", "rule": k, "reason": v})
print(json.dumps({
    "sources": [{"name": k, "url": v[0], "pin": v[1]} for k, v in m.SOURCES.items()],
    "forge_sources": m.FORGE_SOURCES,
    "source_info": {k: v.pattern for k, v in m.SOURCE_INFO.items()},
    "drop": drop,
    "rename": [{"file": k[0], "rule": k[1], "to": v} for k, v in m.RENAME.items()],
    "old_year": m.OLD_YEAR,
    "info": sorted(m.INFO),
    "info_tag": m.INFO_TAG,
    "doc_tag": m.DOC_TAG,
}))
`

// DefaultLicenses — ліцензійні файли джерел у порядку генератора.
var DefaultLicenses = [][2]string{{"signature-base", "LICENSE"}, {"yara-rules-community", "LICENSE"}, {"protections-artifacts", "LICENSE.txt"},
	{"bartblaze", "LICENSE"}, {"inquest", "LICENSE"}, {"ditekshen", "LICENSE.txt"}, {"reversinglabs", "LICENSE"}}

// ImportPython — налаштування з build_vendor_rules.py (потрібен python3).
func ImportPython(script string) (*Config, error) {
	out, err := exec.Command("python3", "-I", "-c", dumpPy, script).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("python3 %s: %s", script, strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(out, &c); err != nil {
		return nil, err
	}
	sort.SliceStable(c.Drop, func(i, j int) bool { return false }) // порядок — як у DROP (значення не важливе)
	c.Licenses = DefaultLicenses
	return &c, nil
}
