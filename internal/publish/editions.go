package publish

// Редакції (editions-branch / editions-folder): кожна редакція — тека <id>/ з пакетом правил (rules-manifest.json,
// .sig, DocScan-rules.zip, DocScan-rules-bundle.zip) і / або підписаними списками (whitelist.json(.sig),
// blacklist.json(.sig)), плюс README.md; у корені — README.md з таблицею редакцій. ПК: rules.mirror.url =
// lists.url = <адреса цілі>/<id> (updater дописує ім'я файлу до адреси). Гілка — один коміт без батьків (лише
// остання версія; історія — в Hive).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/rifatismailov/Anthophila_Hive/internal/contract"
	"github.com/rifatismailov/Anthophila_Hive/internal/docscan/install"
	"github.com/rifatismailov/Anthophila_Hive/internal/docscan/manifest"
	"github.com/rifatismailov/Anthophila_Hive/internal/docscan/orglists"
	"github.com/rifatismailov/Anthophila_Hive/internal/lists"
	"github.com/rifatismailov/Anthophila_Hive/internal/workspace"
)

// EditionState — що лежить у теці редакції на цілі (підписи не перевіряються: лише нижні межі номерів).
type EditionState struct {
	Version string           // версія пакета правил ("" — немає)
	Serials map[string]int64 // white / black -> serial
}

// EditionFiles — редакція для публікації.
type EditionFiles struct {
	ID, Title, Description, Contents string
	RulesDir                         string          // тека зібраного пакета ("" — редакція без правил)
	Lists                            []*lists.Signed // підписані списки редакції
	Critical, Own, Files             int             // файлів critical/, org/ і всього в пакеті
	PkgSHA                           string
}

// sensitive — чи є в редакції дані організації.
func (e EditionFiles) sensitive() bool { return e.Critical > 0 || e.Own > 0 || len(e.Lists) > 0 }

// EditionsInput — реліз редакцій.
type EditionsInput struct {
	Workspace, Version string
	Created            time.Time
	RulesKey, ListsKey string // публічні ключі (для README і перевірки)
	Hive               string // версія Hive
	Editions           []EditionFiles
	PublicAck          bool // людина явно підтвердила публікацію даних організації в публічну ціль
}

var rulesNames = []string{install.PackageName, install.BundleName, install.SigName, install.ManifestName}

var editionFiles = map[string]bool{install.PackageName: true, install.BundleName: true, install.SigName: true, install.ManifestName: true,
	"whitelist.json": true, "whitelist.json.sig": true, "blacklist.json": true, "blacklist.json.sig": true, "README.md": true}

// CurrentEditions — стан редакцій на цілі.
func CurrentEditions(t workspace.Target, e Env) (map[string]EditionState, error) {
	out := map[string]EditionState{}
	var dirs []string
	var get func(p string) ([]byte, error)
	switch t.Kind {
	case "editions-folder":
		ents, err := os.ReadDir(t.Path)
		if os.IsNotExist(err) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		for _, x := range ents {
			if x.IsDir() {
				dirs = append(dirs, x.Name())
			}
		}
		get = func(p string) ([]byte, error) {
			b, err := os.ReadFile(filepath.Join(t.Path, filepath.FromSlash(p)))
			if os.IsNotExist(err) {
				return nil, nil
			}
			return b, err
		}
	case "editions-branch":
		r, err := e.repo(t)
		if err != nil {
			return nil, err
		}
		head, err := r.RemoteHead(t.Repo, t.Branch)
		if err != nil {
			return nil, err
		}
		if head == "" {
			return out, nil
		}
		c, err := r.FetchBranch(t.Repo, t.Branch)
		if err != nil {
			return nil, err
		}
		if dirs, err = r.Dirs(c); err != nil {
			return nil, err
		}
		get = func(p string) ([]byte, error) { return r.Show(c, p) }
	default:
		return nil, fmt.Errorf("target %s is %s, not an editions target", t.ID, t.Kind)
	}
	for _, d := range dirs {
		st := EditionState{Serials: map[string]int64{}}
		if b, err := get(d + "/" + install.ManifestName); err != nil {
			return nil, err
		} else if b != nil {
			var m manifest.Manifest
			if json.Unmarshal(b, &m) == nil {
				st.Version = m.Version
			}
		}
		for _, k := range lists.Kinds {
			b, err := get(d + "/" + k.File)
			if err != nil {
				return nil, err
			}
			var l orglists.List
			if b != nil && json.Unmarshal(b, &l) == nil {
				st.Serials[k.Kind] = l.Serial
			}
		}
		out[d] = st
	}
	return out, nil
}

// EditionsTree — усі файли цілі (шлях з "/" -> вміст), з README.
func EditionsTree(t workspace.Target, in EditionsInput) (map[string][]byte, error) {
	files := map[string][]byte{}
	for _, ed := range in.Editions {
		if ed.RulesDir != "" {
			for _, n := range rulesNames {
				b, err := os.ReadFile(filepath.Join(ed.RulesDir, n))
				if err != nil {
					return nil, fmt.Errorf("edition %s: %w", ed.ID, err)
				}
				files[ed.ID+"/"+n] = b
			}
		}
		for _, l := range ed.Lists {
			if l == nil {
				return nil, fmt.Errorf("edition %s: list not signed", ed.ID)
			}
			files[ed.ID+"/"+l.File] = l.Data
			files[ed.ID+"/"+l.File+".sig"] = l.Sig
		}
		b, err := render(editionReadme, readmeData(t, in, ed))
		if err != nil {
			return nil, err
		}
		files[ed.ID+"/README.md"] = b
	}
	b, err := render(rootReadme, readmeData(t, in, EditionFiles{}))
	if err != nil {
		return nil, err
	}
	files["README.md"] = b
	return files, nil
}

// Editions — опублікувати редакції і перевірити записане так, як читають ПК.
func Editions(ws workspace.Config, t workspace.Target, in EditionsInput, cur map[string]EditionState, e Env) (*Result, error) {
	if len(in.Editions) == 0 {
		return nil, fmt.Errorf("no editions to publish")
	}
	if strings.Contains(t.PCsURL, "@") && (strings.HasPrefix(t.PCsURL, "http://") || strings.HasPrefix(t.PCsURL, "https://")) {
		return nil, fmt.Errorf("target %s: pcs_url with credentials leaks the token into the updater log and Wazuh - use a separate read token", t.ID)
	}
	if t.Kind == "editions-branch" && !t.Public && !t.PCsTokenSupported {
		for _, ed := range in.Editions {
			if ed.RulesDir != "" {
				return nil, fmt.Errorf("target %s: PCs read rules from a closed repository only with rules.mirror.token (DocScan does not have it yet) - "+
					"make the repository readable for the PCs without a token (public, or an internal server open to the PCs' network) and mark the target public, "+
					"publish to editions-folder, or publish only lists-only editions (lists.token works today)", t.ID)
			}
		}
	}
	if t.Public && ws.Visibility != "public" && !in.PublicAck {
		for _, ed := range in.Editions {
			if ed.sensitive() {
				return nil, fmt.Errorf("target %s is public, workspace %s is private: edition %s carries organisation data - explicit confirmation needed", t.ID, ws.Name, ed.ID)
			}
		}
	}
	for _, ed := range in.Editions {
		c := cur[ed.ID]
		if ed.RulesDir != "" && c.Version != "" && manifest.Compare(in.Version, c.Version) <= 0 {
			return nil, fmt.Errorf("edition %s on %s already has %s - %s would never be installed (PCs do not downgrade)", ed.ID, t.ID, c.Version, in.Version)
		}
		for _, l := range ed.Lists {
			if l != nil && l.Serial <= c.Serials[l.Kind] {
				return nil, fmt.Errorf("edition %s on %s already has %s serial %d - sign again", ed.ID, t.ID, l.File, c.Serials[l.Kind])
			}
		}
	}
	files, err := EditionsTree(t, in)
	if err != nil {
		return nil, err
	}
	res := &Result{}
	var readBack func(p string) ([]byte, error)
	switch t.Kind {
	case "editions-folder":
		if err := os.MkdirAll(t.Path, 0o755); err != nil {
			return nil, err
		}
		for _, ed := range in.Editions {
			d := filepath.Join(t.Path, ed.ID)
			if err := os.MkdirAll(d, 0o755); err != nil {
				return nil, err
			}
			// пакет першим, маніфест останнім; список — підпис, потім файл (як ставить updater)
			order := []string{install.PackageName, install.BundleName, install.SigName, install.ManifestName,
				"whitelist.json.sig", "whitelist.json", "blacklist.json.sig", "blacklist.json", "README.md"}
			for _, n := range order {
				if b, ok := files[ed.ID+"/"+n]; ok {
					if err := writeReplace(filepath.Join(d, n), b); err != nil {
						return nil, err
					}
				}
			}
			// те, чого в редакції більше немає (напр. білий список прибрали) — прибрати з теки
			ents, _ := os.ReadDir(d)
			for _, x := range ents {
				if _, ok := files[ed.ID+"/"+x.Name()]; !ok && editionFiles[x.Name()] {
					os.Remove(filepath.Join(d, x.Name()))
				}
			}
		}
		if err := writeReplace(filepath.Join(t.Path, "README.md"), files["README.md"]); err != nil {
			return nil, err
		}
		res.Location = t.Path
		readBack = func(p string) ([]byte, error) { return os.ReadFile(filepath.Join(t.Path, filepath.FromSlash(p))) }
		var stale []string
		for id := range cur {
			found := false
			for _, ed := range in.Editions {
				found = found || ed.ID == id
			}
			if !found {
				stale = append(stale, id)
			}
		}
		if len(stale) > 0 {
			sort.Strings(stale)
			e.say("folders not touched (not published to this target now): %s", strings.Join(stale, ", "))
		}
	case "editions-branch":
		r, err := e.repo(t)
		if err != nil {
			return nil, err
		}
		expected, err := r.RemoteHead(t.Repo, t.Branch)
		if err != nil {
			return nil, err
		}
		c, err := r.OrphanTreeCommit(files, fmt.Sprintf("DocScan rules %s: %d edition(s) (Anthophila_Hive, %s)", in.Version, len(in.Editions), ws.Name))
		if err != nil {
			return nil, err
		}
		if err := r.ForcePushBranch(t.Repo, c, t.Branch, expected); err != nil {
			return nil, err
		}
		got, err := r.FetchBranch(t.Repo, t.Branch)
		if err != nil {
			return nil, err
		}
		if got != c {
			return nil, fmt.Errorf("branch %s is %s after the push, expected %s", t.Branch, got, c)
		}
		res.Location, res.Commit = t.Repo+" "+t.Branch, c
		e.say("pushed %s to %s %s (one commit, no history)", c[:8], t.Repo, t.Branch)
		readBack = func(p string) ([]byte, error) {
			b, err := r.Show(got, p)
			if err == nil && b == nil {
				return nil, fmt.Errorf("published branch has no %s", p)
			}
			return b, err
		}
	default:
		return nil, fmt.Errorf("target %s is %s, not an editions target", t.ID, t.Kind)
	}

	// перевірка записаного: кожна редакція — контракт DocScan (пакет) і перевірка updater-а (списки)
	tmp, err := os.MkdirTemp("", "hive-editions-")
	if err != nil {
		return res, err
	}
	defer os.RemoveAll(tmp)
	res.Editions = map[string]*contract.Report{}
	for _, ed := range in.Editions {
		if ed.RulesDir != "" {
			d := filepath.Join(tmp, ed.ID)
			os.MkdirAll(d, 0o755)
			for _, n := range []string{install.ManifestName, install.SigName, install.PackageName} {
				b, err := readBack(ed.ID + "/" + n)
				if err != nil {
					return res, err
				}
				os.WriteFile(filepath.Join(d, n), b, 0o644)
			}
			co := e.Verify
			co.Published = true
			rep, err := contract.VerifyRules(d, co)
			if err != nil {
				return res, fmt.Errorf("edition %s: %w", ed.ID, err)
			}
			res.Editions[ed.ID] = rep
			if rep.Result() == "FAIL" {
				return res, fmt.Errorf("edition %s on %s does not pass the DocScan contract", ed.ID, t.ID)
			}
		}
		for _, l := range ed.Lists {
			data, err := readBack(ed.ID + "/" + l.File)
			if err != nil {
				return res, err
			}
			sig, err := readBack(ed.ID + "/" + l.File + ".sig")
			if err != nil {
				return res, err
			}
			if _, _, err := lists.VerifySigned(data, sig, l.Kind, []string{in.ListsKey}, cur[ed.ID].Serials[l.Kind]); err != nil {
				return res, fmt.Errorf("edition %s: published %s does not pass the updater check: %w", ed.ID, l.File, err)
			}
		}
	}
	// так, як читають ПК (pcs_url/<id>): CDN (напр. raw.githubusercontent.com) може віддавати стару версію ще
	// кілька хвилин — тож це попередження, а не помилка публікації
	if t.PCsURL != "" {
		for _, ed := range in.Editions {
			if ed.RulesDir == "" {
				continue
			}
			co := e.Verify
			co.Token, co.Published = e.PCsToken, true
			u := strings.TrimRight(t.PCsURL, "/") + "/" + ed.ID
			rep, err := contract.VerifyRules(u, co)
			switch {
			case err != nil:
				res.Warnings = append(res.Warnings, fmt.Sprintf("%s: %v", u, err))
			case rep.Result() == "FAIL":
				res.Warnings = append(res.Warnings, fmt.Sprintf("%s: the check FAILED (a cache may still serve the old version)", u))
			}
		}
	}
	return res, nil
}

// ---------------------------------------------------------------- README

type readmeEdition struct {
	EditionFiles
	URL                string
	RulesKey, ListsKey string
	Rules              bool
	White, Black       *lists.Signed
	HasLists           bool
}

type readme struct {
	In       EditionsInput
	Date     string
	Base     string // адреса цілі для ПК ("" — невідома)
	Editions []readmeEdition
	Ed       readmeEdition
	Name     string
}

func readmeData(t workspace.Target, in EditionsInput, cur EditionFiles) readme {
	d := readme{In: in, Date: in.Created.UTC().Format("2006-01-02"), Base: strings.TrimRight(t.PCsURL, "/"), Name: t.ID}
	if t.Repo != "" {
		n := strings.TrimSuffix(filepath.Base(t.Repo), ".git")
		if n != "" && n != "." {
			d.Name = n
		}
	}
	conv := func(ed EditionFiles) readmeEdition {
		r := readmeEdition{EditionFiles: ed, Rules: ed.RulesDir != "", HasLists: len(ed.Lists) > 0, RulesKey: in.RulesKey, ListsKey: in.ListsKey}
		if d.Base != "" {
			r.URL = d.Base + "/" + ed.ID
		} else {
			r.URL = "<адреса цієї теки>/" + ed.ID
		}
		for _, l := range ed.Lists {
			if l.Kind == "white" {
				r.White = l
			} else {
				r.Black = l
			}
		}
		return r
	}
	for _, ed := range in.Editions {
		d.Editions = append(d.Editions, conv(ed))
	}
	d.Ed = conv(cur)
	return d
}

func render(t *template.Template, d readme) ([]byte, error) {
	var b bytes.Buffer
	if err := t.Execute(&b, d); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

var readmeFuncs = template.FuncMap{"short": func(s string) string {
	if len(s) > 16 {
		return s[:16]
	}
	return s
}}

var updaterJSON = `{{define "updater"}}` + "```json" + `
{
{{- if .Rules}}
  "mode": "mirror",
  "mirror": { "url": "<дзеркало програми DocScan, як і зараз>" },
  "rules": { "mirror": { "url": "{{.URL}}" } },
  "extra_public_keys": [ "{{.RulesKey}}" ]{{if .HasLists}},{{end}}
{{- end}}
{{- if .HasLists}}
  "lists": { "url": "{{.URL}}", "public_keys": [ "{{.ListsKey}}" ] }
{{- end}}
}
` + "```" + `{{end}}`

var rootReadme = template.Must(template.Must(template.New("root").Funcs(readmeFuncs).Parse(updaterJSON)).Parse(`# {{.Name}}

Правила й списки для **DocScan**, які публікує [Anthophila_Hive](https://github.com/rifatismailov/Anthophila_Hive)
(простір ` + "`{{.In.Workspace}}`" + `). Поточна версія правил: **{{.In.Version}}** ({{.Date}}).

Кожна тека — окрема **редакція**: свій склад і свій підписаний пакет. ПК читають лише теку своєї редакції.

| Редакція | Склад | Тека |
|---|---|---|
{{range .Editions}}| [{{.Title}}]({{.ID}}/) | {{.Contents}} | ` + "`{{.ID}}/`" + ` |
{{end}}
## Як підключити ПК (DocScanUpdater, ` + "`updater.json`" + `)

Адреса редакції для ПК: ` + "`{{if .Base}}{{.Base}}{{else}}<адреса цієї теки>{{end}}/<редакція>`" + `.
Приклад — редакція ` + "`{{(index .Editions 0).ID}}`" + `:

{{with index .Editions 0}}{{template "updater" .}}{{end}}

* Правила з дзеркала DocScanUpdater бере лише в режимі ` + "`\"mode\": \"mirror\"`" + `; у цьому режимі потрібна й адреса
  дзеркала самої програми (` + "`mirror.url`" + `). Списки (` + "`lists.url`" + `) працюють у будь-якому режимі.
* ПК довіряють лише підписаному: пакет правил — ключем ` + "`{{.In.RulesKey}}`" + ` (його додають у ` + "`extra_public_keys`" + `),
  списки — ключем ` + "`{{.In.ListsKey}}`" + ` (` + "`lists.public_keys`" + `). Підпис і sha256 кожного файлу перевіряються до встановлення;
  старішої версії за встановлену ПК не ставлять.
* Встановити вручну: ` + "`docscan-updater.exe -InstallRules DocScan-rules-bundle.zip`" + ` (файл з теки редакції).

Тут завжди лише остання версія кожної редакції; історія релізів — в Anthophila_Hive.
Не змінюйте файли вручну — ПК їх відкинуть; наступна публікація все одно перезапише теку.

<sub>Згенеровано Anthophila_Hive {{.In.Hive}}.</sub>
`))

var editionReadme = template.Must(template.Must(template.New("edition").Funcs(readmeFuncs).Parse(updaterJSON)).Parse(`{{with .Ed}}# {{.Title}} (` + "`{{.ID}}`" + `)
{{with .Description}}
{{.}}
{{end}}
**Склад:** {{.Contents}}.

| | |
|---|---|
{{if .Rules}}| Версія правил | **{{$.In.Version}}** ({{$.Date}}) |
| Файлів у пакеті | {{.Files}}{{if .Critical}} (критичних: {{.Critical}}){{end}}{{if .Own}} (власних: {{.Own}}){{end}} |
| sha256 пакета | ` + "`{{.PkgSHA}}`" + ` |
| Ключ підпису правил | ` + "`{{$.In.RulesKey}}`" + ` |
{{end}}{{with .White}}| Білий список | serial {{.Serial}}, записів: {{.Entries}} |
{{end}}{{with .Black}}| Чорний список | serial {{.Serial}}, записів: {{.Entries}} |
{{end}}{{if .HasLists}}| Ключ підпису списків | ` + "`{{$.In.ListsKey}}`" + ` |
{{end}}
## Файли

| Файл | Що це |
|---|---|
{{if .Rules}}| ` + "`rules-manifest.json`" + ` | маніфест: версія, sha256 пакета і кожного файлу |
| ` + "`rules-manifest.sig`" + ` | підпис маніфесту (ed25519) |
| ` + "`DocScan-rules.zip`" + ` | пакет правил |
| ` + "`DocScan-rules-bundle.zip`" + ` | ці три файли в одному — для ручного встановлення |
{{end}}{{if .White}}| ` + "`whitelist.json`" + ` / ` + "`.sig`" + ` | білий список і його підпис |
{{end}}{{if .Black}}| ` + "`blacklist.json`" + ` / ` + "`.sig`" + ` | чорний список і його підпис |
{{end}}
## Підключити ПК

{{template "updater" .}}
{{if .Rules}}
Вручну на одному ПК: ` + "`docscan-updater.exe -InstallRules DocScan-rules-bundle.zip`" + `.
{{end}}{{if not .Rules}}
У цій редакції немає правил: ПК беруть їх з іншого джерела, а списки — звідси (` + "`lists.url`" + ` працює в будь-якому режимі).
{{end}}
[← усі редакції](../README.md)
{{end}}`))
