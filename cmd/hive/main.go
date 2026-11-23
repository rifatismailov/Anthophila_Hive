// hive — Anthophila_Hive: фабрика правил для DocScan (docs/PLAN.md).
package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/rifatismailov/Anthophila_Hive/internal/auth"
	"github.com/rifatismailov/Anthophila_Hive/internal/checks"
	"github.com/rifatismailov/Anthophila_Hive/internal/contract"
	"github.com/rifatismailov/Anthophila_Hive/internal/docscan/manifest"
	"github.com/rifatismailov/Anthophila_Hive/internal/hive"
	"github.com/rifatismailov/Anthophila_Hive/internal/lab"
	"github.com/rifatismailov/Anthophila_Hive/internal/publish"
	"github.com/rifatismailov/Anthophila_Hive/internal/store"
	"github.com/rifatismailov/Anthophila_Hive/internal/web"
	"github.com/rifatismailov/Anthophila_Hive/internal/workspace"
	"github.com/rifatismailov/Anthophila_Hive/internal/yaraexec"
)

const usageText = `usage: hive <command> [options]

  verify   <bundle.zip | release folder | https://.../folder>   check that DocScan PCs would accept a rules package
  init     --name NAME [--visibility private|public] [--floor vX.Y.Z]   new workspace
  key      new --kind rules|lists --ref env:NAME|keychain:SVC/ACCT|keepassxc:DB#ENTRY
  source   add --id ID --url URL [--ref main] [--commit SHA] [--token REF]
  source   pin --id ID --ref REF            show what changes and pin the source at REF
  import   critical --repo <docscan-critical checkout>
  import   list --kind white|black --file <file.json>
  target   add --id ID --kind folder|mirror-branch|lists-folder|lists-branch [--path P] [--repo URL --branch B]
           [--token REF] [--pcs-url URL] [--pcs-token REF] [--pcs-token-supported] [--public]
           release: --forge github|forgejo --project owner/repo [--api https://forgejo] [--commit-tree --repo URL --branch main]
  vendor   import --script tools/build_vendor_rules.py --selection tools/vendor-selection.txt [--from vendor-sources/]
  vendor   fetch [--from DIR]  |  vendor regenerate  |  vendor report
  vendor   update --source NAME [--ref main]          rule-level diff, then pin (asks to confirm)
  vendor   history [--import --repo DIR --path tools/vendor-report.md] [--rule NAME]
  target   rm --id ID
  settings --floor vX.Y.Z                            version already on the PCs
  lab      set add --id ID --kind clean|malware|critical-match|critical-no-match|critical-labelled|hostile --path DIR [--copy] [--confidential]
  lab      set rm --id ID  |  lab set list
  lab      config --sets id1,id2 [--mode fast|full] [--slower-yellow 30] [--slower-red 100]
  lab      run --candidate vX.Y.Z [--baseline vX.Y.Z|none|<bundle or release folder>] [--mode fast|full]
  lab      report --id N  |  lab runs
  lab      accept --id N --key KEY --reason TEXT      a checked hit: no longer red
  dupes    [--level L0|L1|L4]                         duplicate rules of the library
  dupes    drop-in --pattern general/yara-rules-core.yar   drop the copies from those files (one is kept)
  dupes    keep --level L1 --key KEY --member ORIGIN|FILE|NAME
  rule     check --kind org|critical <file.yar>      lint + compile with DocScan, nothing saved
  rule     save  --kind org|critical <file.yar>      check and save into the workspace
  rule     test  --kind org|critical --name NAME.yar  run the test files of the rules of that file
  build    [--bump patch|minor|major] [--offline]    candidate release: package, signature, contract, critical tests
  publish  --version vX.Y.Z --target ID              publish a built release (asks you to type the version; editions target: per-edition folders)
  lists    publish --target ID                       sign both lists and publish them (asks to confirm)
  releases                                           releases of the workspace
  reproduce --version vX.Y.Z                         rebuild a published release, compare every file
  serve    [--listen 0.0.0.0:8740] [--tls-cert C --tls-key K | --behind-proxy]   web interface of the organisation
  user     add --name N --role viewer|editor|reviewer|publisher|admin   (password asked in the terminal)
  user     passwd --name N  |  user role --name N --role R  |  user disable|enable --name N  |  user list
  keystore init   (keystore passphrase asked in the terminal)  |  keystore list
  health                                                     the local web interface answers (Docker HEALTHCHECK)
  backup   --out FILE.tar.gz [--no-blobs] [--with-sets]        consistent copy of the data folder (keys stay encrypted)
  restore  --from FILE.tar.gz --data NEW_DIR

common options: --data DIR (HIVE_DATA, ~/.anthophila-hive)  --ws NAME  --yara PATH (HIVE_YARA)  --yarac PATH (HIVE_YARAC)
`

func main() {
	if len(os.Args) < 2 || os.Args[1] == "help" || os.Args[1] == "-h" || os.Args[1] == "--help" {
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	if cmd == "verify" {
		os.Exit(cmdVerify(args))
	}
	if cmd == "health" {
		os.Exit(cmdHealth())
	}
	sub := ""
	if (cmd == "key" || cmd == "source" || cmd == "import" || cmd == "target" || cmd == "rule" || cmd == "lists" || cmd == "lab" || cmd == "vendor" || cmd == "user" || cmd == "keystore") && len(args) > 0 {
		sub, args = args[0], args[1:]
		if cmd == "lab" && sub == "set" && len(args) > 0 {
			sub, args = "set "+args[0], args[1:]
		}
	} else if cmd == "dupes" && len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, args = args[0], args[1:]
	}
	if err := run(cmd, sub, args); err != nil {
		fmt.Fprintf(os.Stderr, "hive %s: %v\n", strings.TrimSpace(cmd+" "+sub), err)
		os.Exit(1)
	}
}

type common struct {
	fs          *flag.FlagSet
	data, ws    *string
	yara, yarac *string
}

func newFlags(name string) common {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usageText) }
	return common{fs: fs, data: fs.String("data", hive.DefaultData(), "data folder"), ws: fs.String("ws", "", "workspace"),
		yara: fs.String("yara", os.Getenv("HIVE_YARA"), "DocScan yara"), yarac: fs.String("yarac", os.Getenv("HIVE_YARAC"), "DocScan yarac")}
}

func (c common) app() (*hive.App, error) {
	tools := yaraexec.Tools{Yara: *c.yara, Yarac: *c.yarac}
	if tools.Configured() {
		if _, err := tools.Probe(); err != nil {
			return nil, err
		}
	}
	a, err := hive.Open(*c.data, tools)
	if err != nil {
		return nil, err
	}
	a.Unlock = func(db string) ([]byte, error) {
		if db == "hive" {
			return readSecret("keystore passphrase: ")
		}
		return readSecret(fmt.Sprintf("KeePassXC password for %s: ", db))
	}
	return a, nil
}

func say(f string, a ...any) { fmt.Printf("  "+f+"\n", a...) }

func run(cmd, sub string, args []string) error {
	c := newFlags(cmd)
	who := hive.Who()
	switch cmd + " " + sub {
	case "init ":
		name := c.fs.String("name", "", "workspace name")
		vis := c.fs.String("visibility", "private", "public | private")
		floor := c.fs.String("floor", "", "version already on the PCs (the official one): the first own version is greater")
		c.fs.Parse(args)
		a, err := c.app()
		if err != nil {
			return err
		}
		w, err := a.CreateWS(workspace.Config{Name: *name, Visibility: *vis, VersionFloor: *floor}, who)
		if err != nil {
			return err
		}
		fmt.Printf("workspace %s (%s): %s\nnext: hive key new --kind rules --ref keychain:anthophila-hive/%s-rules\n", *name, *vis, w.Dir, *name)
		return nil

	case "key new":
		kind := c.fs.String("kind", "rules", "rules | lists")
		ref := c.fs.String("ref", "", "where the secret lives: env:NAME | keychain:SERVICE/ACCOUNT | keepassxc:DB#ENTRY")
		c.fs.Parse(args)
		a, w, err := open(c)
		if err != nil {
			return err
		}
		pub, seedOnce, err := a.NewKey(w, *kind, *ref, who)
		if err != nil {
			return err
		}
		pk, _ := manifest.ParseKey(pub)
		fmt.Printf("%s key %s, public part (for the PCs):\n  %s\n", *kind, manifest.KeyID(pk), pub)
		if *kind == "rules" {
			fmt.Println("  PCs: updater.json \"extra_public_keys\": [this key]")
		} else {
			fmt.Println("  PCs: updater.json \"lists\": {\"public_keys\": [this key]}  (DocScan-Install.ps1 -ListsKey)")
		}
		if seedOnce != "" {
			fmt.Printf("\nSECRET (shown once, not stored by Hive) - put it into %s now:\n%s\n", *ref, seedOnce)
		} else {
			fmt.Printf("secret stored in %s\n", *ref)
		}
		return nil

	case "source add":
		var s workspace.Source
		c.fs.StringVar(&s.ID, "id", "docscan-rules", "source id")
		c.fs.StringVar(&s.URL, "url", "", "git URL or path")
		c.fs.StringVar(&s.Ref, "ref", "main", "branch / tag to pin")
		c.fs.StringVar(&s.Commit, "commit", "", "exact commit (instead of the head of --ref)")
		c.fs.StringVar(&s.Token, "token", "", "secret ref of a read token (closed repository)")
		c.fs.StringVar(&s.License, "license", "", "licence note")
		c.fs.Parse(args)
		a, w, err := open(c)
		if err != nil {
			return err
		}
		if err := a.AddSource(w, s, who); err != nil {
			return err
		}
		srcs, _ := w.Sources()
		for _, x := range srcs {
			if x.ID == s.ID {
				fmt.Printf("source %s pinned at %s\n", s.ID, x.Commit)
			}
		}
		_, n, _ := a.DB.FindRules(store.RuleQuery{WS: w.Cfg.Name, Origin: s.ID, Limit: 1})
		fmt.Printf("library: %d rules from %s\n", n, s.ID)
		return nil

	case "source pin":
		id := c.fs.String("id", "docscan-rules", "source id")
		ref := c.fs.String("ref", "", "branch / tag / commit")
		yes := c.fs.Bool("yes", false, "pin without asking")
		c.fs.Parse(args)
		a, w, err := open(c)
		if err != nil {
			return err
		}
		commit, ch, err := a.PinPreview(w, *id, *ref)
		if err != nil {
			return err
		}
		fmt.Printf("%s -> %s: %d rule files changed\n", *id, commit[:8], len(ch))
		for i, x := range ch {
			if i == 40 {
				fmt.Printf("  … %d more\n", len(ch)-40)
				break
			}
			fmt.Printf("  %s %s\n", x.Status, x.Path)
		}
		if !*yes && !confirm("pin it? [y/N] ", "y") {
			return fmt.Errorf("not pinned")
		}
		return a.Pin(w, *id, commit, who)

	case "import critical":
		repo := c.fs.String("repo", "", "checkout of docscan-critical (critical/, tests/match, tests/no-match)")
		c.fs.Parse(args)
		a, w, err := open(c)
		if err != nil {
			return err
		}
		nr, nt, err := a.ImportCritical(w, *repo, who)
		if err != nil {
			return err
		}
		fmt.Printf("critical rules: %d files; test documents: %d (into the blob store, not git)\n", nr, nt)
		return nil

	case "import list":
		kind := c.fs.String("kind", "", "white | black")
		file := c.fs.String("file", "", "whitelist.json / blacklist.json")
		c.fs.Parse(args)
		a, w, err := open(c)
		if err != nil {
			return err
		}
		n, err := a.ImportList(w, *kind, *file, who)
		if err != nil {
			return err
		}
		fmt.Printf("%s list: %d entries\n", *kind, n)
		_, _, warns, _ := a.Lists(w)
		for _, x := range warns {
			fmt.Printf("  warning %s[%d]: %s\n", x.Kind, x.Index, x.Text)
		}
		return nil

	case "target add":
		var t workspace.Target
		c.fs.StringVar(&t.ID, "id", "", "target id")
		c.fs.StringVar(&t.Kind, "kind", "", "folder | mirror-branch | release | lists-folder | lists-branch | editions-branch | editions-folder")
		c.fs.StringVar(&t.Path, "path", "", "folder / UNC (folder, lists-folder)")
		c.fs.StringVar(&t.Repo, "repo", "", "git URL of the mirror (mirror-branch, lists-branch)")
		c.fs.StringVar(&t.Branch, "branch", "", "branch (docscan-rules / docscan-lists)")
		c.fs.StringVar(&t.Token, "token", "", "secret ref of the push token")
		c.fs.StringVar(&t.PCsURL, "pcs-url", "", "address the PCs read (rules.mirror.url / lists.url) - checked after publishing")
		c.fs.StringVar(&t.PCsToken, "pcs-token", "", "secret ref of the READ token the PCs use")
		c.fs.BoolVar(&t.PCsTokenSupported, "pcs-token-supported", false, "the PCs run a DocScan with rules.mirror.token")
		c.fs.BoolVar(&t.Public, "public", false, "a public target")
		c.fs.StringVar(&t.Forge, "forge", "", "release: github | forgejo")
		c.fs.StringVar(&t.Project, "project", "", "release: owner/repo")
		c.fs.StringVar(&t.API, "api", "", "release (forgejo): https://host")
		c.fs.BoolVar(&t.CommitTree, "commit-tree", false, "release: commit the rules tree into --repo / --branch before tagging")
		c.fs.StringVar(&t.DownloadURL, "download-url", "", "release: base of the release file URLs (default: the forge's)")
		editions := c.fs.String("editions", "", "editions-branch / editions-folder: comma-separated edition ids (default: all)")
		c.fs.Parse(args)
		for _, id := range strings.Split(*editions, ",") {
			if id = strings.TrimSpace(id); id != "" {
				t.Editions = append(t.Editions, id)
			}
		}
		a, w, err := open(c)
		if err != nil {
			return err
		}
		return a.SaveTarget(w, t, who)

	case "vendor import":
		script := c.fs.String("script", "", "build_vendor_rules.py (its constants: sources, DROP, INFO …)")
		selection := c.fs.String("selection", "", "vendor-selection.txt")
		from := c.fs.String("from", "", "folder with the sources already downloaded (vendor-sources); empty - download")
		c.fs.Parse(args)
		a, w, err := open(c)
		if err != nil {
			return err
		}
		rep, err := a.ImportVendor(w, *script, *selection, *from, who, say)
		if err != nil {
			return err
		}
		fmt.Printf("vendor generator: %d files, %d rules kept, %d dropped, %d duplicates, %d info, %d doc\n", rep.Files, rep.Rules, len(rep.Dropped), len(rep.Duplicates), len(rep.Info), len(rep.Doc))
		return nil

	case "vendor fetch":
		from := c.fs.String("from", "", "folder with the sources already downloaded")
		c.fs.Parse(args)
		a, w, err := open(c)
		if err != nil {
			return err
		}
		return a.FetchVendor(w, *from, say)

	case "vendor regenerate":
		c.fs.Parse(args)
		a, w, err := open(c)
		if err != nil {
			return err
		}
		rep, err := a.VendorRegenerate(w, "manual", who)
		if err != nil {
			return err
		}
		fmt.Printf("%d files, %d rules kept, %d dropped\n", rep.Files, rep.Rules, len(rep.Dropped))
		return nil

	case "vendor report":
		c.fs.Parse(args)
		a, w, err := open(c)
		if err != nil {
			return err
		}
		r, err := a.VendorReport(w)
		if err != nil {
			return err
		}
		fmt.Print(r)
		return nil

	case "vendor update":
		name := c.fs.String("source", "", "vendor source name (signature-base …)")
		ref := c.fs.String("ref", "HEAD", "branch / tag / commit to move to")
		c.fs.Parse(args)
		a, w, err := open(c)
		if err != nil {
			return err
		}
		u, err := a.VendorUpdatePreview(w, *name, *ref)
		if err != nil {
			return err
		}
		fmt.Printf("%s: %s -> %s\n", u.Source, u.From[:12], u.To[:12])
		n := map[string]int{}
		for _, ch := range u.Changes {
			n[ch.Status]++
		}
		fmt.Printf("selected files: %d rules added, %d changed, %d removed\n", n["added"], n["changed"], n["removed"])
		for i, ch := range u.Changes {
			if i == 30 {
				fmt.Printf("  … %d more\n", len(u.Changes)-30)
				break
			}
			fmt.Printf("  %-8s %s: %s\n", ch.Status, ch.File, ch.Rule)
		}
		fmt.Printf("files of the source not in vendor-selection.txt: %d (candidates)\n", len(u.NewFiles))
		fmt.Printf("generated set: %d -> %d rules (+%d / -%d)\n", u.KeptBefore, u.KeptAfter, len(u.Added), len(u.Removed))
		for i, x := range u.Added {
			if i == 15 {
				break
			}
			fmt.Println("  + " + x)
		}
		for i, x := range u.Removed {
			if i == 15 {
				break
			}
			fmt.Println("  - " + x)
		}
		if u.From == u.To {
			fmt.Println("already pinned there")
			return nil
		}
		if !confirm("pin it? [y/N] ", "y") {
			return fmt.Errorf("not pinned")
		}
		rep, err := a.VendorPin(w, *name, u.To, who)
		if err != nil {
			return err
		}
		fmt.Printf("pinned; generated: %d files, %d rules kept\n", rep.Files, rep.Rules)
		return nil

	case "vendor history":
		imp := c.fs.Bool("import", false, "import the versions of a report from a git repository")
		repo := c.fs.String("repo", "", "git repository (e.g. ~/yara or ~/yara-docscan-rules)")
		path := c.fs.String("path", "tools/vendor-report.md", "path of vendor-report.md in that repository")
		rule := c.fs.String("rule", "", "history of one rule")
		c.fs.Parse(args)
		a, w, err := open(c)
		if err != nil {
			return err
		}
		if *imp {
			n, err := a.ImportVendorHistory(w, *repo, *path, who)
			if err != nil {
				return err
			}
			fmt.Printf("imported %d versions\n", n)
		}
		if *rule != "" {
			hs, err := a.RuleHistory(w, *rule)
			if err != nil {
				return err
			}
			for _, h := range hs {
				fmt.Printf("%s %-20s %-9s %-10s %s %s\n", h.Date[:10], h.Origin+" "+h.Rev[:8], h.Status, h.File, h.Detail, map[bool]string{true: "", false: ""}[true])
			}
			return nil
		}
		vs, err := a.DB.ReportVersions(w.Cfg.Name)
		if err != nil {
			return err
		}
		for _, v := range vs {
			fmt.Printf("%s %-22s files %5d kept %5d dropped %5d info %3d doc %3d  %s\n", v.Date[:10], v.Origin+" "+v.Rev[:8], v.Counts["files"], v.Counts["rules kept"], v.Counts["dropped"], v.Counts["info"], v.Counts["doc"], v.Subject)
		}
		return nil

	case "target rm":
		id := c.fs.String("id", "", "target id")
		c.fs.Parse(args)
		a, w, err := open(c)
		if err != nil {
			return err
		}
		return a.DeleteTarget(w, *id, who)

	case "settings ":
		floor := c.fs.String("floor", "", "version already on the PCs (vX.Y.Z)")
		c.fs.Parse(args)
		a, w, err := open(c)
		if err != nil {
			return err
		}
		return a.SetFloor(w, *floor, who)

	case "lab set add":
		id := c.fs.String("id", "", "set id")
		kind := c.fs.String("kind", "", strings.Join(lab.Kinds, " | "))
		path := c.fs.String("path", "", "folder")
		cp := c.fs.Bool("copy", false, "copy the files into the Hive data folder (otherwise: by reference)")
		conf := c.fs.Bool("confidential", false, "documents of the organisation / customers: never published anywhere")
		c.fs.Parse(args)
		a, err := c.app()
		if err != nil {
			return err
		}
		s, err := a.AddLabSet(*id, *kind, *path, *cp, *conf, who)
		if err != nil {
			return err
		}
		fmt.Printf("set %s (%s, %s): %d files, %.1f MB\n", s.ID, s.Kind, s.Mode, s.Files, float64(s.Bytes)/1e6)
		return nil

	case "lab set rm":
		id := c.fs.String("id", "", "set id")
		c.fs.Parse(args)
		a, err := c.app()
		if err != nil {
			return err
		}
		return a.RemoveLabSet(*id, who)

	case "lab set list":
		c.fs.Parse(args)
		a, err := c.app()
		if err != nil {
			return err
		}
		sets, _ := a.DB.LabSets()
		for _, s := range sets {
			fmt.Printf("%-16s %-18s %-4s %6d files %9.1f MB  %s%s\n", s.ID, s.Kind, s.Mode, s.Files, float64(s.Bytes)/1e6, s.Path, map[bool]string{true: "  [confidential]", false: ""}[s.Confidential])
		}
		return nil

	case "lab config":
		sets := c.fs.String("sets", "", "comma-separated set ids required before publishing")
		mode := c.fs.String("mode", "fast", "fast | full")
		y := c.fs.Int("slower-yellow", 30, "% slower than the baseline: yellow")
		r := c.fs.Int("slower-red", 100, "% slower than the baseline: red")
		c.fs.Parse(args)
		a, w, err := open(c)
		if err != nil {
			return err
		}
		var ids []string
		for _, x := range strings.Split(*sets, ",") {
			if x = strings.TrimSpace(x); x != "" {
				ids = append(ids, x)
			}
		}
		return a.SetLabConfig(w, workspace.Lab{Sets: ids, Mode: *mode, SlowerYellow: *y, SlowerRed: *r}, who)

	case "lab run":
		cand := c.fs.String("candidate", "", "built release vX.Y.Z")
		base := c.fs.String("baseline", "", "vX.Y.Z | none | bundle / release folder (default: the last published release)")
		mode := c.fs.String("mode", "", "fast | full (default: the workspace setting)")
		c.fs.Parse(args)
		a, w, err := open(c)
		if err != nil {
			return err
		}
		lr, err := a.RunLab(w, *cand, *base, *mode, who, say)
		if err != nil {
			return err
		}
		printLab(lr)
		if lr.Report.Result == lab.Red {
			return fmt.Errorf("lab run #%d is red", lr.Run.ID)
		}
		return nil

	case "lab report":
		id := c.fs.Int64("id", 0, "lab run id")
		c.fs.Parse(args)
		a, w, err := open(c)
		if err != nil {
			return err
		}
		lr, err := a.LabReport(w, *id)
		if err != nil {
			return err
		}
		printLab(lr)
		return nil

	case "lab runs":
		c.fs.Parse(args)
		a, w, err := open(c)
		if err != nil {
			return err
		}
		runs, _ := a.DB.LabRuns(w.Cfg.Name)
		for _, r := range runs {
			fmt.Printf("#%-4d %s  %-24s vs %-24s %-4s %-6s %s\n", r.ID, r.Created.Local().Format("2006-01-02 15:04"), r.Candidate, r.Baseline, r.Mode, r.Result, r.By)
		}
		return nil

	case "lab accept":
		id := c.fs.Int64("id", 0, "lab run id")
		key := c.fs.String("key", "", "item key from the report")
		reason := c.fs.String("reason", "", "why this hit is fine")
		c.fs.Parse(args)
		a, w, err := open(c)
		if err != nil {
			return err
		}
		lr, err := a.Accept(w, *id, *key, *reason, who)
		if err != nil {
			return err
		}
		fmt.Printf("accepted; lab run #%d is now %s\n", *id, lr.Report.Result)
		return nil

	case "dupes ", "dupes drop-in", "dupes keep":
		level := c.fs.String("level", "", "L0 | L1 | L4 (list: all)")
		pattern := c.fs.String("pattern", "", "drop-in: file path part")
		key := c.fs.String("key", "", "keep: group key")
		member := c.fs.String("member", "", "keep: ORIGIN|FILE|NAME to keep")
		c.fs.Parse(args)
		a, w, err := open(c)
		if err != nil {
			return err
		}
		switch sub {
		case "drop-in", "keep":
			var n int
			var skipped []string
			if sub == "drop-in" {
				pn, plan, err := a.PlanDropDupesIn(w, *pattern)
				if err != nil {
					return err
				}
				for _, x := range plan {
					fmt.Println("  " + x)
				}
				fmt.Printf("%d rules would be dropped\n", pn)
				if pn == 0 || !confirm(fmt.Sprintf("type %d to drop them: ", pn), fmt.Sprint(pn)) {
					return fmt.Errorf("nothing dropped")
				}
				n, skipped, err = a.DropDupesIn(w, *pattern, who)
			} else {
				n, skipped, err = a.KeepOne(w, *level, *key, *member, who)
			}
			if err != nil {
				return err
			}
			fmt.Printf("dropped %d duplicate rules\n", n)
			for _, x := range skipped {
				fmt.Printf("  kept %s\n", x)
			}
			return nil
		}
		groups, err := a.Dupes(w)
		if err != nil {
			return err
		}
		n := map[string]int{}
		resolved := 0
		for _, g := range groups {
			if *level != "" && g.Level != *level {
				continue
			}
			n[g.Level]++
			if g.Resolved() {
				resolved++
				continue
			}
			fmt.Printf("%s %s\n", g.Level, g.Key)
			for _, m := range g.Members {
				st := ""
				if r := g.Dropped[m.Origin+"|"+m.File+"|"+m.Name]; r != "" {
					st = "  [dropped: " + r + "]"
				}
				fmt.Printf("    %s|%s|%s%s\n", m.Origin, m.File, m.Name, st)
			}
		}
		fmt.Printf("groups: L0 %d, L1 %d, L2 %d, L3 %d, L4 %d; resolved (one rule kept): %d\n", n["L0"], n["L1"], n["L2"], n["L3"], n["L4"], resolved)
		return nil

	case "rule check", "rule save":
		kind := c.fs.String("kind", "org", "org | critical")
		name := c.fs.String("name", "", "file name in the workspace (default: the base name of the file)")
		c.fs.Parse(args)
		if c.fs.NArg() != 1 {
			return fmt.Errorf("give one .yar file")
		}
		a, w, err := open(c)
		if err != nil {
			return err
		}
		b, err := os.ReadFile(c.fs.Arg(0))
		if err != nil {
			return err
		}
		n := *name
		if n == "" {
			n = baseName(c.fs.Arg(0))
		}
		var fs []checks.Finding
		saved := false
		if sub == "check" {
			fs, err = a.OwnRuleCheck(w, *kind, n, string(b))
		} else {
			fs, saved, err = a.SaveOwnRule(w, *kind, n, string(b), who)
		}
		if err != nil {
			return err
		}
		for _, f := range fs {
			fmt.Printf("  %s:%d: %s: %s\n", n, f.Line, f.Level, f.Text)
		}
		switch {
		case checks.HasErrors(fs):
			return fmt.Errorf("%s has errors%s", n, map[bool]string{true: " - not saved", false: ""}[sub == "save"])
		case saved:
			fmt.Printf("saved %s/%s\n", *kind, n)
		default:
			fmt.Println("OK")
		}
		return nil

	case "rule test":
		kind := c.fs.String("kind", "org", "org | critical")
		name := c.fs.String("name", "", "file name in the workspace")
		c.fs.Parse(args)
		a, w, err := open(c)
		if err != nil {
			return err
		}
		res, err := a.RunTests(w, *kind, *name)
		if err != nil {
			return err
		}
		bad := 0
		for _, r := range res {
			st := "OK  "
			if !r.OK {
				st, bad = "FAIL", bad+1
			}
			fmt.Printf("  %s %-20s expect %-8s %s  matched %v\n", st, r.Rule, r.Expect, r.Name, r.Matched)
		}
		if bad > 0 {
			return fmt.Errorf("%d of %d tests failed", bad, len(res))
		}
		fmt.Printf("%d tests passed\n", len(res))
		return nil

	case "build ":
		bump := c.fs.String("bump", "patch", "patch | minor | major")
		offline := c.fs.Bool("offline", false, "do not read the versions on the targets")
		c.fs.Parse(args)
		a, w, err := open(c)
		if err != nil {
			return err
		}
		r, err := a.Build(w, *bump, !*offline, who)
		if err != nil {
			return err
		}
		fmt.Printf("%s %s: %d files, key %s, package sha256 %s\n  %s\n", w.Cfg.Name, r.Version, r.Files, r.KeyID, r.PkgSHA[:16], r.Dir)
		for _, n := range r.Notes {
			fmt.Printf("  note: %s\n", n)
		}
		for _, ch := range r.Contract.Checks {
			fmt.Printf("  %-4s %s  %-38s %s\n", ch.Status, ch.ID, ch.Title, ch.Detail)
		}
		if r.Critical != nil {
			fmt.Printf("  critical tests: %d match / %d no-match\n", r.Critical.Match, r.Critical.NoMatch)
			for _, m := range r.Critical.Missed {
				fmt.Printf("        NOT FOUND   %s\n", m)
			}
			for _, m := range r.Critical.Unwanted {
				fmt.Printf("        FALSE ALARM %s\n", m)
			}
		}
		if !r.OK() {
			return fmt.Errorf("%s is not releasable", r.Version)
		}
		fmt.Printf("PASS - publish: hive publish --version %s --target <id>\n", r.Version)
		return nil

	case "publish ":
		version := c.fs.String("version", "", "built release")
		target := c.fs.String("target", "", "target id")
		c.fs.Parse(args)
		a, w, err := open(c)
		if err != nil {
			return err
		}
		t, err := w.Target(*target)
		if err != nil {
			return err
		}
		where := t.Path
		if where == "" {
			where = t.Repo + " " + t.Branch
		}
		fmt.Printf("publish rules %s of %s to %s (%s%s): %s\n", *version, w.Cfg.Name, t.ID, t.Kind, map[bool]string{true: ", PUBLIC", false: ""}[t.Public], where)
		ack := false
		if hive.IsEditionsTarget(*t) {
			rel, err := a.DB.Release(w.Cfg.Name, *version)
			if err != nil {
				return err
			}
			plan, err := a.PlanEditions(w, rel, t.ID)
			if err != nil {
				return err
			}
			for _, e := range plan.Editions {
				fmt.Printf("  %-14s %s\n", e.ID+"/", e.Contents())
				if s := plan.Sensitive[e.ID]; plan.NeedsAck && len(s) > 0 {
					fmt.Printf("  %-14s ! PUBLIC: %s\n", "", strings.Join(s, "; "))
				}
			}
			if plan.NeedsAck {
				fmt.Println("the target is PUBLIC and the workspace is private: the data marked ! becomes readable by anyone")
				if !confirm("type PUBLIC to agree: ", "PUBLIC") {
					return fmt.Errorf("not published")
				}
				ack = true
			}
		}
		if !confirm("type the version to confirm: ", *version) {
			return fmt.Errorf("not published")
		}
		var res *publish.Result
		if hive.IsEditionsTarget(*t) {
			res, err = a.PublishEditions(w, *version, *target, who, ack, say)
		} else {
			res, err = a.Publish(w, *version, *target, who, say)
		}
		printReports(res)
		if err != nil {
			return err
		}
		fmt.Printf("published %s -> %s\n", *version, *target)
		return nil

	case "lists publish":
		target := c.fs.String("target", "", "lists target id")
		c.fs.Parse(args)
		a, w, err := open(c)
		if err != nil {
			return err
		}
		white, black, warns, err := a.Lists(w)
		if err != nil {
			return err
		}
		fmt.Printf("sign and publish whitelist.json (%d entries) and blacklist.json (%d entries) of %s to %s\n", len(white.Entries), len(black.Entries), w.Cfg.Name, *target)
		for _, x := range warns {
			fmt.Printf("  warning %s[%d]: %s\n", x.Kind, x.Index, x.Text)
		}
		if !confirm("type yes to confirm: ", "yes") {
			return fmt.Errorf("not published")
		}
		res, err := a.PublishLists(w, *target, who, say)
		if err != nil {
			return err
		}
		fmt.Printf("published to %s\n", res.Location)
		return nil

	case "releases ":
		c.fs.Parse(args)
		a, w, err := open(c)
		if err != nil {
			return err
		}
		rs, _ := a.DB.Releases(w.Cfg.Name)
		for _, r := range rs {
			fmt.Printf("%-9s %-10s %-10s %s  %d files  key %s  %s\n", r.Version, r.Status, r.Result, r.Created.Format("2006-01-02 15:04"), r.Files, r.KeyID, r.WSCommit[:8])
		}
		ps, _ := a.DB.Publications(w.Cfg.Name)
		for _, p := range ps {
			fmt.Printf("  %s %-9s %-14s -> %-10s %s  %s\n", p.At.Format("2006-01-02 15:04"), p.What, p.Version, p.Target, p.By, p.Result)
		}
		return nil

	case "reproduce ":
		version := c.fs.String("version", "", "published release")
		c.fs.Parse(args)
		a, w, err := open(c)
		if err != nil {
			return err
		}
		n, diff, err := a.Reproduce(w, *version)
		if err != nil {
			return err
		}
		if len(diff) > 0 {
			for _, d := range diff {
				fmt.Println("  " + d)
			}
			return fmt.Errorf("%s does not reproduce: %d of %d files", *version, len(diff), n)
		}
		fmt.Printf("%s reproduces: all %d files have the sha256 of the signed manifest\n", *version, n)
		return nil

	case "serve ":
		listen := c.fs.String("listen", envOr("HIVE_LISTEN", "127.0.0.1:8740"), "listen address (HIVE_LISTEN)")
		cert := c.fs.String("tls-cert", os.Getenv("HIVE_TLS_CERT"), "HTTPS certificate, PEM (HIVE_TLS_CERT)")
		key := c.fs.String("tls-key", os.Getenv("HIVE_TLS_KEY"), "HTTPS key, PEM (HIVE_TLS_KEY)")
		proxy := c.fs.Bool("behind-proxy", os.Getenv("HIVE_BEHIND_PROXY") == "1", "an HTTPS reverse proxy is in front (HIVE_BEHIND_PROXY=1)")
		c.fs.Parse(args)
		a, err := c.app()
		if err != nil {
			return err
		}
		a.Unlock = nil // у веб пароль сховища — з форми кожної дії
		return web.Serve(a, web.Options{Listen: *listen, TLSCert: *cert, TLSKey: *key, BehindProxy: *proxy, Workspace: *c.ws})

	case "user add", "user passwd", "user role", "user disable", "user enable", "user list":
		name := c.fs.String("name", "", "user name")
		role := c.fs.String("role", "viewer", "viewer | editor | reviewer | publisher | admin")
		c.fs.Parse(args)
		a, err := c.app()
		if err != nil {
			return err
		}
		switch sub {
		case "list":
			us, _ := a.Auth.List()
			for _, u := range us {
				last := ""
				if !u.LastLogin.IsZero() {
					last = u.LastLogin.Local().Format("2006-01-02 15:04")
				}
				fmt.Printf("%-20s %-10s totp=%-5v disabled=%-5v last login %s\n", u.Name, u.Role, u.TOTP, u.Disabled, last)
			}
			return nil
		case "add", "passwd":
			p1, err := readSecret("password for " + *name + ": ")
			if err != nil {
				return err
			}
			p2, err := readSecret("again: ")
			if err != nil {
				return err
			}
			if string(p1) != string(p2) {
				return fmt.Errorf("the passwords differ")
			}
			if sub == "add" {
				r, err := auth.ParseRole(*role)
				if err != nil {
					return err
				}
				err = a.Auth.Add(*name, r, string(p1))
				if err == nil {
					a.DB.Audit("*", who, "user", "add "+*name+" "+r.String()+" (cli)")
				}
				return err
			}
			a.DB.Audit("*", who, "user", "password of "+*name+" (cli)")
			return a.Auth.SetPassword(*name, string(p1))
		case "role":
			r, err := auth.ParseRole(*role)
			if err != nil {
				return err
			}
			return a.Auth.SetRole(*name, r)
		default:
			return a.Auth.SetDisabled(*name, sub == "disable")
		}

	case "keystore init", "keystore list":
		c.fs.Parse(args)
		a, err := c.app()
		if err != nil {
			return err
		}
		if sub == "list" {
			for _, e := range a.Keys.List() {
				fmt.Printf("hive:%-24s %-14s %s %s\n", e.Name, e.Kind, e.Public, e.Created)
			}
			return nil
		}
		p1, err := readSecret("new keystore passphrase (16+ characters): ")
		if err != nil {
			return err
		}
		p2, err := readSecret("again: ")
		if err != nil {
			return err
		}
		if string(p1) != string(p2) {
			return fmt.Errorf("the passphrases differ")
		}
		if err := a.Keys.Init(p1); err != nil {
			return err
		}
		fmt.Println("keystore passphrase set - keep it in the organisation's safe: without it the signing keys cannot be decrypted")
		return nil

	case "backup ":
		out := c.fs.String("out", "", "backup file (.tar.gz), must not exist")
		noBlobs := c.fs.Bool("no-blobs", false, "leave out the blob store (test documents, release assets)")
		withSets := c.fs.Bool("with-sets", false, "include the copied lab sets (may contain malware samples)")
		c.fs.Parse(args)
		a, err := c.app()
		if err != nil {
			return err
		}
		n, err := a.Backup(*out, !*noBlobs, *withSets)
		if err != nil {
			return err
		}
		fmt.Printf("backup %s: %d files (keys stay encrypted with the keystore passphrase)\n", *out, n)
		return nil

	case "restore ":
		from := c.fs.String("from", "", "backup file")
		c.fs.Parse(args)
		n, err := hive.Restore(*from, *c.data)
		if err != nil {
			return err
		}
		fmt.Printf("restored %d files into %s\n", n, *c.data)
		return nil
	}
	fmt.Fprint(os.Stderr, usageText)
	return fmt.Errorf("unknown command")
}

func printLab(lr *hive.LabResult) {
	r := lr.Report
	fmt.Printf("lab run #%d: %s vs %s (%s) - %s\n", lr.Run.ID, r.Candidate, r.Baseline, r.Mode, strings.ToUpper(r.Result))
	for _, t := range r.Times {
		base := ""
		if t.HasBase {
			base = fmt.Sprintf(" (baseline %.1fs)", t.Base)
		}
		fmt.Printf("  set %-14s %6d files  %.1fs%s  sandbox %s%s\n", t.Set, t.Files, t.Cand, base, t.Sandbox, map[bool]string{true: " [cached]", false: ""}[t.Cached])
	}
	for _, g := range r.Gates {
		fmt.Printf("  %-6s %s  %s: %s\n", strings.ToUpper(g.Status), g.ID, g.Title, g.Detail)
		for i, it := range g.Items {
			if i == 15 {
				fmt.Printf("           … %d more (web: /lab/report)\n", g.Total-15)
				break
			}
			acc := ""
			if it.Accepted != "" {
				acc = "  [accepted: " + it.Accepted + "]"
			} else if it.Key != "" && g.Status == "red" {
				acc = "  key " + it.Key
			}
			fmt.Printf("           %s %s %s %s%s\n", it.Set, it.File, it.Rule, it.Detail, acc)
		}
	}
	for _, c := range r.Categories {
		fmt.Printf("  %-10s %-12s found %3d missed %3d false %3d", c.Set, c.Category, c.Found, c.Missed, c.False)
		if c.HasBase {
			fmt.Printf("   (baseline %d / %d / %d)", c.BaseFound, c.BaseMissed, c.BaseFalse)
		}
		fmt.Println()
	}
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func open(c common) (*hive.App, *workspace.WS, error) {
	a, err := c.app()
	if err != nil {
		return nil, nil, err
	}
	w, err := a.WS(*c.ws)
	return a, w, err
}

func baseName(p string) string {
	i := strings.LastIndexAny(p, `/\`)
	return p[i+1:]
}

func printReports(res *publish.Result) {
	if res == nil {
		return
	}
	for _, r := range []*contract.Report{res.Report, res.PCs} {
		if r != nil {
			printReport(r)
		}
	}
	ids := make([]string, 0, len(res.Editions))
	for id := range res.Editions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		fmt.Printf("edition %s: %s\n", id, res.Editions[id].Result())
	}
	for _, w := range res.Warnings {
		fmt.Println("warning:", w)
	}
}

// confirm — явна дія людини: лише з терміналу, людина вводить want.
func confirm(prompt, want string) bool {
	if st, err := os.Stdin.Stat(); err != nil || st.Mode()&os.ModeCharDevice == 0 {
		fmt.Fprintln(os.Stderr, "confirmation needs a terminal (publishing is never automatic)")
		return false
	}
	fmt.Print(prompt)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimSpace(line) == want
}

// readSecret — пароль з терміналу без відлуння.
func readSecret(prompt string) ([]byte, error) {
	tty, err := os.Open("/dev/tty")
	if err != nil {
		return nil, fmt.Errorf("a password is needed and there is no terminal")
	}
	defer tty.Close()
	fmt.Fprint(os.Stderr, prompt)
	off := exec.Command("stty", "-echo")
	off.Stdin = tty
	off.Run()
	line, err := bufio.NewReader(tty).ReadBytes('\n')
	on := exec.Command("stty", "echo")
	on.Stdin = tty
	on.Run()
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	return []byte(strings.TrimRight(string(line), "\r\n")), nil
}

// ---------------------------------------------------------------- verify (етап 0)

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(s string) error { *m = append(*m, s); return nil }

func cmdVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	var keys multi
	fs.Var(&keys, "key", "trusted public key ed25519:<base64> (repeat; the extra_public_keys of the target PCs)")
	official := fs.Bool("official", false, "also trust manifest.OfficialKeys (the DocScan CI key); default when no -key is given")
	yara := fs.String("yara", os.Getenv("HIVE_YARA"), "DocScan's yara (with the docscan module); env HIVE_YARA")
	yarac := fs.String("yarac", os.Getenv("HIVE_YARAC"), "DocScan's yarac; env HIVE_YARAC")
	newer := fs.String("newer-than", "", "version on the target now (vX.Y.Z): the package must be newer")
	tokenEnv := fs.String("token-env", "", "name of an environment variable holding the read token of a closed mirror (never the token itself)")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usageText); fs.PrintDefaults() }
	fs.Parse(args)
	if fs.NArg() != 1 {
		fs.Usage()
		return 2
	}
	trusted := []string(keys)
	if *official || len(trusted) == 0 {
		trusted = append(trusted, manifest.OfficialKeys...)
	}
	for _, k := range trusted {
		if _, err := manifest.ParseKey(k); err != nil {
			fmt.Fprintf(os.Stderr, "hive verify: %v\n", err)
			return 2
		}
	}
	o := contract.Options{Keys: trusted, NewerThan: *newer}
	if *tokenEnv != "" {
		if o.Token = os.Getenv(*tokenEnv); o.Token == "" {
			fmt.Fprintf(os.Stderr, "hive verify: %s is empty\n", *tokenEnv)
			return 2
		}
	}
	tools := yaraexec.Tools{Yara: *yara, Yarac: *yarac}
	if tools.Configured() {
		inf, err := tools.Probe()
		if err != nil {
			fmt.Fprintf(os.Stderr, "hive verify: %v\n", err)
			return 2
		}
		o.Compiler = tools
		if !*asJSON {
			fmt.Printf("DocScan yara %s: %s, %s\n", inf.Version, *yara, *yarac)
		}
	}
	rep, err := contract.VerifyRules(fs.Arg(0), o)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hive verify: %v\n", err)
		return 2
	}
	res := rep.Result()
	if *asJSON {
		out, _ := json.MarshalIndent(struct {
			*contract.Report
			Result string `json:"result"`
		}{rep, res}, "", "  ")
		fmt.Println(string(out))
	} else {
		printReport(rep)
	}
	switch res {
	case "PASS":
		return 0
	case "FAIL":
		return 1
	}
	return 2
}

func printReport(rep *contract.Report) {
	fmt.Printf("%s\n", rep.Source)
	if rep.Version != "" {
		fmt.Printf("rules %s, signed by key %s, %d files\n", rep.Version, rep.KeyID, rep.Files)
	}
	for _, c := range rep.Checks {
		fmt.Printf("  %-4s %s  %-38s %s\n", c.Status, c.ID, c.Title, c.Detail)
	}
	fmt.Println(rep.Result())
}

// cmdHealth — веб-інтерфейс на цьому сервері відповідає (сторінка входу): спершу HTTPS, потім HTTP.
func cmdHealth() int {
	_, port, err := net.SplitHostPort(envOr("HIVE_LISTEN", "127.0.0.1:8740"))
	if err != nil {
		port = "8740"
	}
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} // лише локальна перевірка
	for _, scheme := range []string{"https", "http"} {
		resp, err := c.Get(scheme + "://127.0.0.1:" + port + "/login")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return 0
			}
		}
	}
	fmt.Fprintln(os.Stderr, "hive health: the web interface does not answer")
	return 1
}
