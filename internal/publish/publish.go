// Package publish — публікація підписаного пакета правил і підписаних списків туди, звідки їх беруть ПК.
//
//	folder         тека / UNC (rules.mirror.url = ця тека): rules-manifest.json, .sig, DocScan-rules.zip (+ bundle)
//	mirror-branch  гілка git-репозиторію дзеркала: ОДИН коміт без батьків з трьома файлами, force-push з lease
//	               (PLAN.md 7: у гілці лише остання версія, архіви не нагромаджуються)
//	lists-folder / lists-branch — те саме для whitelist.json(.sig) і blacklist.json(.sig)
//
// Перед записом — версія (serial) на цілі має бути меншою; після запису — повна перевірка того, що лежить на цілі
// (контракт DocScan), а якщо задано pcs_url — ще й так, як читають ПК.
// Викликає це лише явна дія людини (веб: підтвердження; CLI: введення версії в терміналі).
package publish

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rifatismailov/Anthophila_Hive/internal/contract"
	"github.com/rifatismailov/Anthophila_Hive/internal/docscan/install"
	"github.com/rifatismailov/Anthophila_Hive/internal/docscan/manifest"
	"github.com/rifatismailov/Anthophila_Hive/internal/docscan/orglists"
	"github.com/rifatismailov/Anthophila_Hive/internal/gitx"
	"github.com/rifatismailov/Anthophila_Hive/internal/lists"
	"github.com/rifatismailov/Anthophila_Hive/internal/workspace"
)

// Env — чим публікувати.
type Env struct {
	WorkDir  string           // тека для bare-репозиторіїв публікації (кеш)
	Auth     *gitx.Auth       // токен запису (push) цілі
	PCsToken string           // токен читання, з яким читають ПК (перевірка pcs_url)
	Verify   contract.Options // ключі й компілятор для перевірки після публікації (Keys, Compiler)
	Say      func(string, ...any)
}

func (e Env) say(f string, a ...any) {
	if e.Say != nil {
		e.Say(f, a...)
	}
}

// Result — що зроблено.
type Result struct {
	Location string
	Commit   string           // mirror-branch
	Report   *contract.Report // перевірка записаного
	PCs      *contract.Report // перевірка за pcs_url
}

// CheckRulesTarget — чи можна публікувати пакет простору ws у ціль t (PLAN.md 9.1 Q1, 9.2.5).
func CheckRulesTarget(ws workspace.Config, t workspace.Target) error {
	switch t.Kind {
	case "folder", "mirror-branch":
	default:
		return fmt.Errorf("target %s is %s, not a rules target (folder | mirror-branch)", t.ID, t.Kind)
	}
	if t.Public && ws.Visibility != "public" {
		return fmt.Errorf("target %s is public, workspace %s is private: its critical rules and organisation rules must not leave it", t.ID, ws.Name)
	}
	if strings.Contains(t.PCsURL, "@") && (strings.HasPrefix(t.PCsURL, "http://") || strings.HasPrefix(t.PCsURL, "https://")) {
		return fmt.Errorf("target %s: pcs_url with credentials leaks the token into the updater log and Wazuh - use a separate read token", t.ID)
	}
	if t.Kind == "mirror-branch" && !t.Public && !t.PCsTokenSupported {
		return fmt.Errorf("target %s: a closed mirror branch needs DocScan with rules.mirror.token on the PCs (not released yet) - "+
			"publish to a folder / UNC share instead, or set pcs_token_supported once the PCs have it", t.ID)
	}
	return nil
}

// CurrentRulesVersion — версія пакета на цілі ("" — порожньо). Підпис тут не перевіряється: це лише нижня межа
// номера (ПК самі не поставлять старішу).
func CurrentRulesVersion(t workspace.Target, e Env) (string, error) {
	var data []byte
	switch t.Kind {
	case "folder":
		b, err := os.ReadFile(filepath.Join(t.Path, install.ManifestName))
		if os.IsNotExist(err) {
			return "", nil
		}
		if err != nil {
			return "", err
		}
		data = b
	case "mirror-branch":
		r, err := e.repo(t)
		if err != nil {
			return "", err
		}
		head, err := r.RemoteHead(t.Repo, t.Branch)
		if err != nil || head == "" {
			return "", err
		}
		c, err := r.FetchBranch(t.Repo, t.Branch)
		if err != nil {
			return "", err
		}
		if data, err = r.Show(c, install.ManifestName); err != nil || data == nil {
			return "", err
		}
	default:
		return "", fmt.Errorf("target %s is not a rules target", t.ID)
	}
	var m manifest.Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return "", fmt.Errorf("target %s: %s is not a manifest: %w", t.ID, install.ManifestName, err)
	}
	return m.Version, nil
}

func (e Env) repo(t workspace.Target) (*gitx.Repo, error) {
	d := filepath.Join(e.WorkDir, "publish-"+t.ID+".git")
	r := &gitx.Repo{Dir: d, Bare: true, Auth: e.Auth}
	if _, err := os.Stat(filepath.Join(d, "HEAD")); err != nil {
		os.MkdirAll(e.WorkDir, 0o755)
		if _, err := (&gitx.Repo{}).Run("init", "-q", "--bare", d); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// Rules — опублікувати пакет з теки збирання dir (rules-manifest.json, .sig, DocScan-rules.zip, bundle).
func Rules(ws workspace.Config, t workspace.Target, dir, version string, e Env) (*Result, error) {
	if err := CheckRulesTarget(ws, t); err != nil {
		return nil, err
	}
	cur, err := CurrentRulesVersion(t, e)
	if err != nil {
		return nil, fmt.Errorf("target %s: cannot read the current version: %w", t.ID, err)
	}
	if cur != "" && manifest.Compare(version, cur) <= 0 {
		return nil, fmt.Errorf("target %s already has %s - %s would never be installed (PCs do not downgrade)", t.ID, cur, version)
	}
	read := func(n string) ([]byte, error) { return os.ReadFile(filepath.Join(dir, n)) }
	files := map[string][]byte{}
	for _, n := range []string{install.ManifestName, install.SigName, install.PackageName, install.BundleName} {
		b, err := read(n)
		if err != nil {
			return nil, err
		}
		files[n] = b
	}
	res := &Result{}
	switch t.Kind {
	case "folder":
		if err := os.MkdirAll(t.Path, 0o755); err != nil {
			return nil, err
		}
		// пакет першим, маніфест останнім: ПК, що читає саме зараз, побачить або стару пару, або невідповідність
		// sha256 (і спробує пізніше) — але не встановить нічого непідписаного
		for _, n := range []string{install.PackageName, install.BundleName, install.SigName, install.ManifestName} {
			if err := writeReplace(filepath.Join(t.Path, n), files[n]); err != nil {
				return nil, err
			}
		}
		res.Location = t.Path
		e.say("written to %s", t.Path)
		co := e.Verify
		co.Published = true
		if res.Report, err = contract.VerifyRules(t.Path, co); err != nil {
			return res, err
		}
	case "mirror-branch":
		r, err := e.repo(t)
		if err != nil {
			return nil, err
		}
		expected, err := r.RemoteHead(t.Repo, t.Branch)
		if err != nil {
			return nil, err
		}
		pcs := map[string][]byte{install.ManifestName: files[install.ManifestName], install.SigName: files[install.SigName], install.PackageName: files[install.PackageName]}
		c, err := r.OrphanCommit(pcs, "DocScan rules "+version+" (Anthophila_Hive, "+ws.Name+")")
		if err != nil {
			return nil, err
		}
		if err := r.ForcePushBranch(t.Repo, c, t.Branch, expected); err != nil {
			return nil, err
		}
		res.Location, res.Commit = t.Repo+" "+t.Branch, c
		e.say("pushed %s to %s %s (one commit, no history)", c[:8], t.Repo, t.Branch)
		got, err := r.FetchBranch(t.Repo, t.Branch)
		if err != nil {
			return res, err
		}
		if got != c {
			return res, fmt.Errorf("branch %s is %s after the push, expected %s", t.Branch, got, c)
		}
		tmp, err := os.MkdirTemp("", "hive-published-")
		if err != nil {
			return res, err
		}
		defer os.RemoveAll(tmp)
		for n := range pcs {
			b, err := r.Show(got, n)
			if err != nil || b == nil {
				return res, fmt.Errorf("published branch has no %s", n)
			}
			os.WriteFile(filepath.Join(tmp, n), b, 0o644)
		}
		co := e.Verify
		co.Published = true
		if res.Report, err = contract.VerifyRules(tmp, co); err != nil {
			return res, err
		}
	}
	if t.PCsURL != "" {
		co := e.Verify
		co.Token, co.Published = e.PCsToken, true
		if res.PCs, err = contract.VerifyRules(t.PCsURL, co); err != nil {
			return res, fmt.Errorf("published, but the PCs' address %s does not serve it: %w", t.PCsURL, err)
		}
	}
	return res, nil
}

// CurrentSerials — serial списків на цілі (0 — немає). Підпис не перевіряється: лише нижня межа номера.
func CurrentSerials(t workspace.Target, e Env) (map[string]int64, error) {
	out := map[string]int64{}
	get := func(n string) ([]byte, error) { return nil, nil }
	switch t.Kind {
	case "lists-folder":
		get = func(n string) ([]byte, error) {
			b, err := os.ReadFile(filepath.Join(t.Path, n))
			if os.IsNotExist(err) {
				return nil, nil
			}
			return b, err
		}
	case "lists-branch":
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
		get = func(n string) ([]byte, error) { return r.Show(c, n) }
	default:
		return nil, fmt.Errorf("target %s is %s, not a lists target (lists-folder | lists-branch)", t.ID, t.Kind)
	}
	for _, k := range lists.Kinds {
		b, err := get(k.File)
		if err != nil {
			return nil, err
		}
		if b == nil {
			continue
		}
		var l orglists.List
		if err := json.Unmarshal(b, &l); err == nil {
			out[k.Kind] = l.Serial
		}
	}
	return out, nil
}

// Lists — опублікувати підписані списки (обидва разом) і перевірити записане так, як це робить updater.
func Lists(ws workspace.Config, t workspace.Target, signed []*lists.Signed, keys []string, e Env) (*Result, error) {
	if t.Public && ws.Visibility != "public" {
		return nil, fmt.Errorf("target %s is public, workspace %s is private", t.ID, ws.Name)
	}
	cur, err := CurrentSerials(t, e)
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{}
	for _, s := range signed {
		if s.Serial <= cur[s.Kind] {
			return nil, fmt.Errorf("target %s already has %s serial %d - sign again (serial %d would not be installed)", t.ID, s.File, cur[s.Kind], s.Serial)
		}
		files[s.File] = s.Data
		files[s.File+".sig"] = s.Sig
	}
	res := &Result{}
	var readBack func(n string) ([]byte, error)
	switch t.Kind {
	case "lists-folder":
		if err := os.MkdirAll(t.Path, 0o755); err != nil {
			return nil, err
		}
		for _, s := range signed { // підпис першим, список другим — як updater ставить (.sig, потім файл)
			if err := writeReplace(filepath.Join(t.Path, s.File+".sig"), s.Sig); err != nil {
				return nil, err
			}
			if err := writeReplace(filepath.Join(t.Path, s.File), s.Data); err != nil {
				return nil, err
			}
		}
		res.Location = t.Path
		readBack = func(n string) ([]byte, error) { return os.ReadFile(filepath.Join(t.Path, n)) }
	case "lists-branch":
		r, err := e.repo(t)
		if err != nil {
			return nil, err
		}
		expected, err := r.RemoteHead(t.Repo, t.Branch)
		if err != nil {
			return nil, err
		}
		c, err := r.OrphanCommit(files, "DocScan lists (Anthophila_Hive, "+ws.Name+")")
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
		res.Location, res.Commit = t.Repo+" "+t.Branch, got
		readBack = func(n string) ([]byte, error) { return r.Show(got, n) }
	}
	for _, s := range signed {
		data, err := readBack(s.File)
		if err != nil {
			return res, err
		}
		sig, err := readBack(s.File + ".sig")
		if err != nil {
			return res, err
		}
		if _, _, err := lists.VerifySigned(data, sig, s.Kind, keys, cur[s.Kind]); err != nil {
			return res, fmt.Errorf("published %s does not pass the updater check: %w", s.File, err)
		}
	}
	return res, nil
}

func writeReplace(p string, b []byte) error {
	tmp := p + ".hive-tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
