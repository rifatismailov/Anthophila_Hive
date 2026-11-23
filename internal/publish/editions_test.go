package publish

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rifatismailov/Anthophila_Hive/internal/docscan/manifest"
	"github.com/rifatismailov/Anthophila_Hive/internal/docscan/orglists"
	"github.com/rifatismailov/Anthophila_Hive/internal/lists"
	"github.com/rifatismailov/Anthophila_Hive/internal/workspace"
)

func signedLists(t *testing.T, prev map[string]int64) (white, black *lists.Signed, pub string) {
	t.Helper()
	seed, pub, _ := manifest.NewSeed()
	for _, k := range lists.Kinds {
		l := &orglists.List{Schema: 1, Entries: []orglists.Entry{{SHA256: strings.Repeat("b", 64), Comment: k.Kind}}}
		s, err := lists.Sign(l, k.Kind, seed, pub, prev[k.Kind], time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if k.Kind == "white" {
			white = s
		} else {
			black = s
		}
	}
	return
}

func editionsInput(t *testing.T, version, seed, pub string, prev map[string]int64) EditionsInput {
	dir := release(t, seed, pub, version)
	white, black, lpub := signedLists(t, prev)
	return EditionsInput{Workspace: "org", Version: version, Created: time.Now(), RulesKey: pub, ListsKey: lpub, Hive: "test",
		Editions: []EditionFiles{
			{ID: "full", Title: "Повна", Description: "усе", Contents: "правила, списки", RulesDir: dir, Lists: []*lists.Signed{white, black}, Files: 3},
			{ID: "nocrit", Title: "Лише виявлення", Contents: "правила", RulesDir: dir, Files: 3},
			{ID: "lists", Title: "Лише списки", Contents: "списки", Lists: []*lists.Signed{white, black}},
		}}
}

func TestEditionsFolderAndBranch(t *testing.T) {
	seed, pub, _ := manifest.NewSeed()
	bare := filepath.Join(t.TempDir(), "pollen.git")
	if out, err := exec.Command("git", "init", "-q", "--bare", bare).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	for _, tg := range []workspace.Target{
		{ID: "pollen-dir", Kind: "editions-folder", Path: filepath.Join(t.TempDir(), "pollen")},
		{ID: "pollen", Kind: "editions-branch", Repo: bare, Branch: "main", Public: true},
	} {
		ws := workspace.Config{Name: "org", Visibility: "private"}
		e := env(t, pub)
		cur, err := CurrentEditions(tg, e)
		if err != nil || len(cur) != 0 {
			t.Fatalf("%s: empty target %v %v", tg.ID, cur, err)
		}
		if tg.Kind == "editions-branch" {
			closed := tg
			closed.Public = false
			if _, err := Editions(ws, closed, editionsInput(t, "v1.0.1", seed, pub, nil), cur, e); err == nil || !strings.Contains(err.Error(), "rules.mirror.token") {
				t.Fatalf("closed branch for rules: %v", err)
			}
		}
		in := editionsInput(t, "v1.0.1", seed, pub, nil)
		if tg.Public {
			// публічна ціль, приватний простір, у редакціях дані організації — лише з явним підтвердженням
			if _, err := Editions(ws, tg, in, cur, e); err == nil || !strings.Contains(err.Error(), "explicit confirmation") {
				t.Fatalf("public without ack: %v", err)
			}
			in.PublicAck = true
		}
		res, err := Editions(ws, tg, in, cur, e)
		if err != nil {
			t.Fatalf("%s: %v", tg.ID, err)
		}
		for id, rep := range res.Editions {
			if failed(rep) {
				t.Fatalf("%s/%s: %v", tg.ID, id, rep)
			}
		}
		if len(res.Editions) != 2 {
			t.Fatalf("%s: checked %d rules editions", tg.ID, len(res.Editions))
		}
		cur, err = CurrentEditions(tg, e)
		if err != nil {
			t.Fatal(err)
		}
		if cur["full"].Version != "v1.0.1" || cur["lists"].Version != "" || cur["lists"].Serials["white"] == 0 || cur["nocrit"].Serials["white"] != 0 {
			t.Fatalf("%s: state %+v", tg.ID, cur)
		}
		// README: корінь з таблицею, редакція з updater.json
		get := func(p string) string {
			if tg.Kind == "editions-folder" {
				b, _ := os.ReadFile(filepath.Join(tg.Path, p))
				return string(b)
			}
			b, _ := exec.Command("git", "--git-dir", bare, "show", "main:"+p).Output()
			return string(b)
		}
		if r := get("README.md"); !strings.Contains(r, "| [Повна](full/)") || !strings.Contains(r, `"mode": "mirror"`) {
			t.Fatalf("%s: root README:\n%s", tg.ID, r)
		}
		if r := get("lists/README.md"); strings.Contains(r, `"rules"`) || !strings.Contains(r, `"lists": { "url"`) {
			t.Fatalf("%s: lists README:\n%s", tg.ID, r)
		}
		if get("nocrit/whitelist.json") != "" || get("nocrit/DocScan-rules-bundle.zip") == "" {
			t.Fatalf("%s: nocrit content", tg.ID)
		}
		// та сама версія ще раз — ні (ПК не ставлять рівну)
		in2 := editionsInput(t, "v1.0.1", seed, pub, map[string]int64{"white": cur["full"].Serials["white"], "black": cur["full"].Serials["black"]})
		in2.PublicAck = true
		if _, err := Editions(ws, tg, in2, cur, e); err == nil || !strings.Contains(err.Error(), "downgrade") {
			t.Fatalf("%s: same version again: %v", tg.ID, err)
		}
		// новіша, і білого списку в full більше немає — у теці його теж немає
		in3 := editionsInput(t, "v1.0.2", seed, pub, map[string]int64{"white": cur["full"].Serials["white"], "black": cur["full"].Serials["black"]})
		in3.PublicAck = true
		in3.Editions[0].Lists = in3.Editions[0].Lists[1:]
		if _, err := Editions(ws, tg, in3, cur, e); err != nil {
			t.Fatalf("%s: v1.0.2: %v", tg.ID, err)
		}
		if get("full/whitelist.json") != "" || get("full/blacklist.json") == "" {
			t.Fatalf("%s: removed whitelist still there", tg.ID)
		}
	}
}
