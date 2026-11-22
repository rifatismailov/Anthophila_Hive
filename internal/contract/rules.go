// Package contract — перевірка, що ПК з DocScan гарантовано приймуть пакет правил (PLAN.md, розділ 6 і 9.2).
//
// Основа — шлях встановлення updater-а (internal/docscan/install: той самий код, що на ПК); зверху — перевірки, яких
// updater не робить, але без яких пакет зламається на ПК пізніше (VERSION.txt == маніфест, вимоги до critical/,
// версія новіша за ту, що на цілі).
package contract

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/rifatismailov/Anthophila_Hive/internal/docscan/install"
	"github.com/rifatismailov/Anthophila_Hive/internal/docscan/manifest"
	"github.com/rifatismailov/Anthophila_Hive/internal/yaraparse"
)

// Status — результат однієї перевірки.
type Status string

const (
	Pass Status = "PASS"
	Fail Status = "FAIL"
	Warn Status = "WARN"
	Skip Status = "SKIP"
)

// Check — одна перевірка звіту.
type Check struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Status Status `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// Report — звіт перевірки пакета правил.
type Report struct {
	Source  string  `json:"source"`
	Version string  `json:"version,omitempty"`
	KeyID   string  `json:"key_id,omitempty"`
	Files   int     `json:"files,omitempty"`
	Checks  []Check `json:"checks"`
}

// Result — FAIL, якщо хоч одна перевірка червона; INCOMPLETE, якщо щось пропущено; інакше PASS.
func (r *Report) Result() string {
	res := "PASS"
	for _, c := range r.Checks {
		switch c.Status {
		case Fail:
			return "FAIL"
		case Skip:
			res = "INCOMPLETE"
		}
	}
	return res
}

func (r *Report) add(id, title string, st Status, detail string, a ...any) {
	if len(a) > 0 {
		detail = fmt.Sprintf(detail, a...)
	}
	r.Checks = append(r.Checks, Check{ID: id, Title: title, Status: st, Detail: detail})
}

// Options — чим перевіряти.
type Options struct {
	Keys      []string         // ключі, яким довіряють ПК цілі (OfficialKeys + extra_public_keys)
	Compiler  install.Compiler // DocScan yara / yarac; nil — компіляція пропускається (звіт INCOMPLETE)
	NewerThan string           // версія, що вже на цілі (ПК не ставлять ні старішу, ні рівну); "" — не перевіряти
	Token     string           // для http(s): "Authorization: token …" (як lists.token / rules.mirror.token)
	Published bool             // перевірка вже опублікованого: на цілі саме цей пакет, R12 не застосовується
	HTTP      *http.Client
}

// Вимоги до critical/ (cirun/deploy/critical.go і обмеження yara --critical-rules у DocScan).
var CriticalNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\.yar$`)

const (
	MaxCriticalFiles = 256
	MaxCriticalBytes = 64 << 20
)

// versionLineRe — перший рядок VERSION.txt, як його пише cirun/deploy/rules.go (і писатиме Hive).
var versionLineRe = regexp.MustCompile(`^DocScan rules (v\d+\.\d+\.\d+) \(commit [0-9a-f]{4,40}(, critical [0-9a-f]{0,40}: \d+ files)?, \d{4}-\d{2}-\d{2}\)\r?$`)

// VerifyRules — src: DocScan-rules-bundle.zip, тека релізу (rules-manifest.json, .sig, DocScan-rules.zip
// [+ bundle]) або http(s)-адреса теки, з якої читають ПК (rules.mirror.url / releases/download/<тег>).
func VerifyRules(src string, o Options) (*Report, error) {
	r := &Report{Source: src}
	var b *install.Bundle
	var bundleBytes []byte // bundle поруч (тека / адреса) — перевіряється, що в ньому ті самі байти
	strict := false        // джерело — сам bundle: рівно три файли
	switch {
	case strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://"):
		var err error
		if b, bundleBytes, err = fetchRelease(src, o); err != nil {
			return nil, err
		}
	default:
		st, err := os.Stat(src)
		if err != nil {
			return nil, err
		}
		if b, err = install.ReadBundle(src); err != nil {
			return nil, err
		}
		if st.IsDir() {
			bundleBytes = b.Files[install.BundleName]
		} else {
			strict = true
		}
	}

	// R01: склад
	names := sortedKeys(b.Files)
	switch {
	case strict && (len(b.Files) != 3 || len(b.Skipped) > 0):
		r.add("R01", "bundle layout", Fail, "a bundle must hold exactly %s, %s and the package at its top level; found %v, skipped by the updater: %v",
			install.ManifestName, install.SigName, names, b.Skipped)
	case b.Files[install.ManifestName] == nil || b.Files[install.SigName] == nil:
		r.add("R01", "bundle layout", Fail, "no %s / %s (found %v)", install.ManifestName, install.SigName, names)
		return r, nil
	default:
		r.add("R01", "bundle layout", Pass, "%v", names)
	}

	// R02: розміри маніфесту й підпису (служба качає їх з лімітами)
	if n, s := len(b.Files[install.ManifestName]), len(b.Files[install.SigName]); n > install.MaxManifest || s > install.MaxSig {
		r.add("R02", "manifest / signature size", Fail, "manifest %d B (max %d), signature %d B (max %d)", n, install.MaxManifest, s, install.MaxSig)
	} else {
		r.add("R02", "manifest / signature size", Pass, "manifest %d B, signature %d B", n, s)
	}

	// R03: підпис, продукт, формат маніфесту (manifest.VerifyProduct — той самий код, що на ПК)
	m, keyID, pkg, err := install.VerifyManifest(b.Files, o.Keys)
	if m == nil {
		r.add("R03", "signature and manifest", Fail, "%v (trusted keys: %d)", err, len(o.Keys))
		return r.skipRest("R03"), nil
	}
	r.Version, r.KeyID, r.Files = m.Version, keyID, len(m.Files)
	r.add("R03", "signature and manifest", Pass, "%s %s, key %s, %d files", m.Product, m.Version, keyID, len(m.Files))
	if pkg == nil {
		r.add("R04", "package size and sha256", Fail, "%v", err)
		return r.skipRest("R04"), nil
	}

	// R04: пакет
	if err := install.CheckPackage(m, pkg); err != nil {
		r.add("R04", "package size and sha256", Fail, "%v", err)
		return r.skipRest("R04"), nil
	}
	r.add("R04", "package size and sha256", Pass, "%s %d B sha256 %s", m.Package.Name, m.Package.Size, m.Package.SHA256[:16])

	// R05: розпакування з перевіркою кожного файлу (unpackVerified)
	work, err := os.MkdirTemp("", "hive-verify-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(work)
	dir := filepath.Join(work, "rules")
	if err := install.Unpack(pkg, m, dir); err != nil {
		r.add("R05", "every file matches the manifest", Fail, "%v", err)
		return r.skipRest("R05"), nil
	}
	r.add("R05", "every file matches the manifest", Pass, "%d files, sha256 of each checked", len(m.Files))

	// R06: точка входу
	if _, err := os.Stat(filepath.Join(dir, "docscan-index.yar")); err != nil {
		r.add("R06", "docscan-index.yar at the root", Fail, "the rules package has no docscan-index.yar")
		return r.skipRest("R06"), nil
	}
	r.add("R06", "docscan-index.yar at the root", Pass, "")

	// R07: VERSION.txt — саме з нього ПК знають, що встановлено (updater/rules.go: installedRules)
	v, line := install.VersionOfDir(dir)
	switch {
	case v != m.Version:
		r.add("R07", "VERSION.txt = manifest version", Fail, "VERSION.txt says %q (first line %q), the manifest %s: PCs would reinstall or never update", v, line, m.Version)
	case !versionLineRe.MatchString(line):
		r.add("R07", "VERSION.txt = manifest version", Warn, "version %s matches, but the first line %q is not in the cirun format", v, line)
	default:
		r.add("R07", "VERSION.txt = manifest version", Pass, "%s", strings.TrimSpace(line))
	}

	// R08, R09: critical/
	checkCritical(r, filepath.Join(dir, "critical"))

	// R10, R11: компіляція DocScan yarac / yara — як updater перед заміною
	if o.Compiler == nil {
		r.add("R10", "compile with DocScan yarac", Skip, "no DocScan yara / yarac (--yara, --yarac or HIVE_YARA, HIVE_YARAC)")
		r.add("R11", "compile critical/ with DocScan yara", Skip, "no DocScan yara")
	} else {
		if err := o.Compiler.CompileIndex(dir); err != nil {
			r.add("R10", "compile with DocScan yarac", Fail, "%v", err)
		} else {
			r.add("R10", "compile with DocScan yarac", Pass, "docscan-index.yar with the DocScan externals")
		}
		if _, err := os.Stat(filepath.Join(dir, "critical")); err != nil {
			r.add("R11", "compile critical/ with DocScan yara", Pass, "no critical/ in the package")
		} else if err := o.Compiler.CompileCritical(filepath.Join(dir, "critical")); err != nil {
			r.add("R11", "compile critical/ with DocScan yara", Fail, "%v", err)
		} else {
			r.add("R11", "compile critical/ with DocScan yara", Pass, "")
		}
	}

	// R12: версія новіша за ту, що на цілі
	switch {
	case o.NewerThan == "" && o.Published:
		r.add("R12", "newer than the target", Pass, "checked before publishing; this is the package on the target now")
	case o.NewerThan == "":
		r.add("R12", "newer than the target", Skip, "the version on the target is not given (--newer-than)")
	case !manifest.ValidVersion(o.NewerThan):
		r.add("R12", "newer than the target", Fail, "--newer-than %q is not vX.Y.Z", o.NewerThan)
	case manifest.Compare(m.Version, o.NewerThan) <= 0:
		r.add("R12", "newer than the target", Fail, "%s is not newer than %s: PCs do not install an older or the same version", m.Version, o.NewerThan)
	default:
		r.add("R12", "newer than the target", Pass, "%s > %s", m.Version, o.NewerThan)
	}

	// R13: bundle поруч несе ті самі байти
	if bundleBytes != nil {
		checkBundleTwin(r, bundleBytes, b.Files)
	}
	return r, nil
}

func checkCritical(r *Report, dir string) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		r.add("R08", "critical/ layout and limits", Pass, "no critical/ in the package")
		r.add("R09", "critical rule names unique", Pass, "no critical/ in the package")
		return
	}
	var files, bad []string
	var total int64
	for _, e := range ents {
		n := e.Name()
		switch {
		case e.IsDir():
			bad = append(bad, n+"/ (no subfolders)")
		case CriticalNameRe.MatchString(n):
			files = append(files, n)
			if fi, err := e.Info(); err == nil {
				total += fi.Size()
			}
		default:
			bad = append(bad, n)
		}
	}
	switch {
	case len(bad) > 0:
		r.add("R08", "critical/ layout and limits", Fail, "not a rules file (NAME.yar of A-Z a-z 0-9 _ - ., top level only): %s", strings.Join(bad, ", "))
	case len(files) == 0 || len(files) > MaxCriticalFiles:
		r.add("R08", "critical/ layout and limits", Fail, "%d .yar files (1..%d)", len(files), MaxCriticalFiles)
	case total > MaxCriticalBytes:
		r.add("R08", "critical/ layout and limits", Fail, "%d bytes together (max %d)", total, MaxCriticalBytes)
	default:
		r.add("R08", "critical/ layout and limits", Pass, "%d files, %d bytes", len(files), total)
	}
	// у записі для Wazuh і в черзі — лише назва правила, без файлу: назви мають бути унікальні в усіх файлах
	where := map[string][]string{}
	for _, f := range files {
		b, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			continue
		}
		for _, rn := range yaraparse.RuleNames(string(b)) {
			where[rn.Name] = append(where[rn.Name], fmt.Sprintf("%s:%d", f, rn.Line))
		}
	}
	var dups []string
	for n, w := range where {
		if len(w) > 1 {
			dups = append(dups, fmt.Sprintf("%s (%s)", n, strings.Join(w, ", ")))
		}
	}
	sort.Strings(dups)
	if len(dups) > 0 {
		r.add("R09", "critical rule names unique", Fail, "the Wazuh record and the queue carry only the rule name: %s", strings.Join(dups, "; "))
	} else {
		r.add("R09", "critical rule names unique", Pass, "%d rules", len(where))
	}
}

func checkBundleTwin(r *Report, bundle []byte, files map[string][]byte) {
	tmp, err := os.CreateTemp("", "hive-bundle-*.zip")
	if err != nil {
		r.add("R13", "bundle = release files", Fail, "%v", err)
		return
	}
	defer os.Remove(tmp.Name())
	tmp.Write(bundle)
	tmp.Close()
	bb, err := install.ReadBundle(tmp.Name())
	if err != nil {
		r.add("R13", "bundle = release files", Fail, "%s: %v", install.BundleName, err)
		return
	}
	var diff []string
	for _, n := range []string{install.ManifestName, install.SigName, install.PackageName} {
		if !bytes.Equal(bb.Files[n], files[n]) {
			diff = append(diff, n)
		}
	}
	if len(bb.Files) != 3 || len(bb.Skipped) > 0 {
		diff = append(diff, fmt.Sprintf("layout %v skipped %v", sortedKeys(bb.Files), bb.Skipped))
	}
	if len(diff) > 0 {
		r.add("R13", "bundle = release files", Fail, "%s differs from the release files: %s", install.BundleName, strings.Join(diff, ", "))
	} else {
		r.add("R13", "bundle = release files", Pass, "%s carries the same three files", install.BundleName)
	}
}

// skipRest — після фатальної помилки решта перевірок не має сенсу.
func (r *Report) skipRest(after string) *Report {
	for _, c := range []struct{ id, t string }{{"R04", "package size and sha256"}, {"R05", "every file matches the manifest"},
		{"R06", "docscan-index.yar at the root"}, {"R07", "VERSION.txt = manifest version"}, {"R08", "critical/ layout and limits"},
		{"R09", "critical rule names unique"}, {"R10", "compile with DocScan yarac"}, {"R11", "compile critical/ with DocScan yara"},
		{"R12", "newer than the target"}} {
		if c.id > after {
			r.add(c.id, c.t, Skip, "not checked: %s failed", after)
		}
	}
	return r
}

func sortedKeys(m map[string][]byte) []string {
	var k []string
	for n := range m {
		k = append(k, n)
	}
	sort.Strings(k)
	return k
}

// fetchRelease — файли релізу з http(s)-теки так, як їх бере служба (маніфест, підпис, пакет з маніфесту) + bundle,
// якщо він там є (на дзеркалі його може не бути).
func fetchRelease(base string, o Options) (*install.Bundle, []byte, error) {
	c := o.HTTP
	if c == nil {
		c = &http.Client{Timeout: 10 * time.Minute}
	}
	get := func(name string, limit int64, optional bool) ([]byte, error) {
		req, err := http.NewRequest("GET", strings.TrimRight(base, "/")+"/"+name, nil)
		if err != nil {
			return nil, err
		}
		if req.URL.User != nil {
			return nil, fmt.Errorf("a token in the URL leaks into the updater log and Wazuh - use a separate token")
		}
		if o.Token != "" {
			req.Header.Set("Authorization", "token "+o.Token)
		}
		resp, err := c.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode == 404 && optional {
			return nil, nil
		}
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("%s: %s", name, resp.Status)
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
		if err != nil {
			return nil, err
		}
		if int64(len(data)) > limit {
			return nil, fmt.Errorf("%s: larger than %d bytes", name, limit)
		}
		return data, nil
	}
	b := &install.Bundle{Files: map[string][]byte{}}
	var err error
	if b.Files[install.ManifestName], err = get(install.ManifestName, install.MaxManifest, false); err != nil {
		return nil, nil, err
	}
	if b.Files[install.SigName], err = get(install.SigName, install.MaxSig, false); err != nil {
		return nil, nil, err
	}
	// ім'я й розмір пакета — з маніфесту (ще не перевіреного: перевірка — у R03, тут лише щоб знати, що качати)
	var m struct {
		Package manifest.File `json:"package"`
	}
	if err := json.Unmarshal(b.Files[install.ManifestName], &m); err == nil && m.Package.Name != "" && !strings.ContainsAny(m.Package.Name, `/\`) && m.Package.Size > 0 && m.Package.Size <= install.MaxUnpacked {
		if b.Files[m.Package.Name], err = get(m.Package.Name, m.Package.Size, false); err != nil {
			return nil, nil, err
		}
	}
	bundle, err := get(install.BundleName, 3*install.MaxBundleEntry, true)
	if err != nil {
		return nil, nil, err
	}
	return b, bundle, nil
}
