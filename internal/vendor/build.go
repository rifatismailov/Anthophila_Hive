package vendor

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/rifatismailov/Anthophila_Hive/internal/yaraexec"
)

func (r *rule) head() string {
	if r.hoff >= 0 && r.hoff <= len(r.text) {
		return r.text[r.hoff:]
	}
	return ""
}

var (
	forgeSrcRe = re(`source_url\s*=\s*"https?://github\.com/([^/"]+/[^/"]+)`)
	wsRe       = re(`\s+`)

	peOK     = regexp.MustCompile(`uint16\(0\)==0x5a4d|uint16be\(0\)==0x4d5a|\bpe\.`)
	zipOK    = regexp.MustCompile(`uint16\(0\)==0x4b50|uint32\(0\)==0x04034b50|uint32be\(0\)==0x504b0304`)
	elfRe    = regexp.MustCompile(`==0x464c457f|==0x7f454c46|\belf\.`)
	machoRe  = regexp.MustCompile(`==0xfeedfac[ef]|==0xcffaedfe|==0xcefaedfe|uint16\(0\)==0xfacf|\bmacho\.`)
	cafeRe   = regexp.MustCompile(`==0xbebafeca|==0xcafebabe|uint16\(0\)==0xfeca`)
	dexRe    = regexp.MustCompile(`\bdex\.`)
	nameOSRe = regexp.MustCompile(`(^|_)(lnx|linux|elf|esxi|esxiargs|macos|osx|sh|py)(_|$)`)
	shellRe  = regexp.MustCompile(`<\?php|<%@|<%=|runat=|\$_(post|get|request)\[`)
	hayRe    = regexp.MustCompile(`(^|_)(lnx|linux|unix|solaris|aix|freebsd|bsd|esx|vcenter|vmware|macos|osx|ios|` +
		`cisco|asa|juniper|junos|fortinet|fortigate|fortios|ivanti|pulse|citrix|netscaler|` +
		`confluence|jira|atlassian|barracuda|esg|zimbra|moveit|sonicwall|paloalto|panos|` +
		`globalprotect|f5|bigip|mikrotik|router|iot|php|jsp|java|tomcat|weblogic|perl|python|` +
		`bash|nginx|apache)(_|$)`)
	modRe = re(`\b(?:modified|last_modified|updated_date)\s*=\s*"(\d{4})`)
	datRe = re(`\b(?:date|creation_date|first_imported|created)\s*=\s*"(\d{4})`)
)

// platformReason — чому правило не може спрацювати на Windows-ПК ("" — лишити). platform_reason().
func platformReason(fname string, r *rule) string {
	c := wsRe.ReplaceAllString(strings.ToLower(r.cond), "")
	s := strings.ToLower(r.strs)
	n := strings.ToLower(r.name)
	if peOK.MatchString(c) || zipOK.MatchString(c) || strings.Contains(n, "jar") {
		return ""
	}
	elf, macho, cafe := elfRe.MatchString(c), machoRe.MatchString(c), cafeRe.MatchString(c)
	switch {
	case cafe && !elf && !macho:
		return "Java .class / Mach-O fat only (not scanned)"
	case elf && macho:
		return "ELF/Mach-O only"
	case elf:
		return "ELF only"
	case macho:
		return "Mach-O only"
	case dexRe.MatchString(c) || strings.Contains(n, "android"):
		return "Android"
	case nameOSRe.MatchString(n):
		return "Linux/ESXi/macOS (by rule name)"
	case (strings.Contains(n, "webshell") || shellRe.MatchString(s)) && !strings.Contains(n, "compiled"):
		return "webshell source (PHP/JSP/ASPX; not scanned on workstations)"
	}
	base := strings.ToLower(fname)
	if i := strings.LastIndex(base, "."); i >= 0 {
		base = base[:i]
	}
	if m := hayRe.FindStringSubmatch(n + "_" + base); m != nil {
		return fmt.Sprintf("not a Windows workstation file (%s, no PE check)", m[2])
	}
	return ""
}

func oldReason(r *rule, oldYear int) string {
	meta := r.head()
	m := modRe.FindStringSubmatch(meta)
	if m == nil {
		m = datRe.FindStringSubmatch(meta)
	}
	if m != nil {
		if y, _ := strconv.Atoi(m[1]); y <= oldYear {
			return "old: last change " + m[1]
		}
	}
	return ""
}

func (c *Config) forgeReason(src string, r *rule) string {
	if src != "yara-forge" {
		return ""
	}
	repo := "?"
	if m := forgeSrcRe.FindStringSubmatch(r.head()); m != nil {
		repo = m[1]
	}
	if _, ok := c.ForgeSources[repo]; ok {
		return ""
	}
	return "yara-forge: source " + repo + " not taken (already a source here / licence)"
}

// addTag — тег у заголовок правила (add_tag).
func addTag(text string, hoff int, tag string) string {
	m := headerAt.FindStringSubmatchIndex(mask(text)[hoff:])
	if m == nil {
		return text
	}
	end := hoff + m[1]
	head := text[hoff:end]
	var nw string
	if m[6] >= 0 && m[6] < m[7] {
		nw = pyRstrip(head[:len(head)-1]) + " " + tag + " {"
	} else {
		nw = tagRe.ReplaceAllString(head, "${1} : "+tag+" {")
	}
	return text[:hoff] + nw + text[end:]
}

var tagRe = regexp.MustCompile(`([A-Za-z0-9_]+)[ \t\r\n]*\{$`)

func renameRule(text string, hoff int, old, nw string) string {
	m := headerAt.FindStringSubmatchIndex(mask(text)[hoff:])
	if m == nil {
		return text
	}
	end := hoff + m[1]
	head := text[hoff:end]
	r := regexp.MustCompile(`\brule([ \t]+)` + old + `\b`)
	loc := r.FindStringSubmatchIndex(head)
	if loc != nil {
		head = head[:loc[0]] + "rule" + head[loc[2]:loc[3]] + nw + head[loc[1]:]
	}
	return text[:hoff] + head + text[end:]
}

// Report — що зроблено (vendor-report.md).
type Report struct {
	Dropped, Duplicates, Renamed, Info, Doc, FilesSkipped []string
	Files, Rules                                          int
}

// Inputs — де лежать дерева джерел (назва -> тека на закріпленому коміті / розпакований реліз) і власне правило
// DocScan maldoc/vba_plaintext.yar (з дерева правил).
type Inputs struct {
	Sources      map[string]string
	VBAPlaintext string
}

// Build — згенерувати дерево в out (general/, maldoc/…, file-index.yar, LICENSE-*, tools/vendor-report.md) і
// перевірити компіляцію DocScan yarac (tools не задано — без перевірки).
func Build(c *Config, sel []Selection, in Inputs, out string, tools yaraexec.Tools) (*Report, error) {
	rep := &Report{}
	seen, bodies := map[string]string{}, map[string]string{}
	var clashes, index []string
	dropBy := map[string]string{}
	for _, d := range c.Drop {
		dropBy[d.File+"\x00"+d.Rule] = d.Reason
	}
	renameBy := map[string]string{}
	for _, r := range c.Rename {
		renameBy[r.File+"\x00"+r.Rule] = r.To
	}
	info := map[string]bool{}
	for _, x := range c.Info {
		info[x] = true
	}
	srcInfo := map[string]*regexp.Regexp{}
	for k, v := range c.SourceInfo {
		srcInfo[k] = re(v)
	}
	for _, s := range sel {
		src, ok := c.source(s.Source)
		if !ok {
			return nil, fmt.Errorf("selection: unknown source %q", s.Source)
		}
		root, ok := in.Sources[s.Source]
		if !ok {
			return nil, fmt.Errorf("source %s is not fetched", s.Source)
		}
		text, err := readText(filepath.Join(root, filepath.FromSlash(s.Path)))
		if err != nil {
			return nil, err
		}
		pre, rules, tail := splitRules(text)
		fname := filepath.Base(s.Path)
		for _, r := range rules {
			if r.private {
				continue
			}
			r.drop = firstNonEmpty(dropBy["\x00"+r.name], dropBy[s.Path+"\x00"+r.name], c.forgeReason(s.Source, r),
				platformReason(fname, r), oldReason(r, c.OldYear))
		}
		var keptConds []string
		for _, r := range rules {
			if r.drop == "" {
				keptConds = append(keptConds, r.cond)
			}
		}
		kc := strings.Join(keptConds, " ")
		for _, r := range rules {
			if r.drop != "" && regexp.MustCompile(`\b`+r.name+`\b`).MatchString(kc) {
				r.drop = "" // на нього посилається взяте правило
			}
		}
		var keep []string
		for _, r := range rules {
			if r.drop != "" {
				rep.Dropped = append(rep.Dropped, fmt.Sprintf("%s/%s: %s — %s", s.Source, s.Path, r.name, r.drop))
				continue
			}
			t, name := r.text, r.name
			if nw, ok := renameBy[s.Path+"\x00"+name]; ok {
				t = renameRule(t, r.hoff, name, nw)
				rep.Renamed = append(rep.Renamed, fmt.Sprintf("%s/%s: %s -> %s", s.Source, s.Path, r.name, nw))
				name = nw
			}
			isSrcInfo := false
			if x, ok := srcInfo[s.Source]; ok && x.MatchString(r.head()) {
				isSrcInfo = true
			}
			if info[name] || isSrcInfo {
				t = addTag(t, r.hoff, c.InfoTag)
				suf := ""
				if isSrcInfo {
					suf = " (source: informational)"
				}
				rep.Info = append(rep.Info, fmt.Sprintf("%s/%s: %s%s", s.Source, s.Path, name, suf))
			} else if strings.HasPrefix(s.OutDir, "maldoc") && !r.private {
				t = addTag(t, r.hoff, c.DocTag)
				rep.Doc = append(rep.Doc, fmt.Sprintf("%s/%s: %s", s.Source, s.Path, name))
			}
			body := strings.TrimFunc(wsRe.ReplaceAllString(r.strs+" "+r.cond, " "), func(x rune) bool { return x == ' ' })
			body = strings.TrimSpace(body)
			if prev, ok := seen[name]; ok && !r.private {
				if bodies[name] == body {
					rep.Duplicates = append(rep.Duplicates, fmt.Sprintf("%s/%s: %s — same as %s", s.Source, s.Path, name, prev))
					continue
				}
				clashes = append(clashes, fmt.Sprintf("%s: %s vs %s/%s", name, prev, s.Source, s.Path))
				continue
			}
			seen[name] = s.Source + "/" + s.Path
			bodies[name] = body
			keep = append(keep, t)
		}
		any := false
		for _, r := range rules {
			if r.drop == "" && !r.private {
				any = true
			}
		}
		if !any {
			rep.FilesSkipped = append(rep.FilesSkipped, fmt.Sprintf("%s/%s — no rule left", s.Source, s.Path))
			continue
		}
		dst := filepath.Join(out, filepath.FromSlash(s.OutDir), fname)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return nil, err
		}
		hdr := fmt.Sprintf("// GENERATED by rules/tools/build_vendor_rules.py — do not edit.\n// source: %s @ %s : %s\n", src.URL, first(src.Pin, 12), s.Path)
		if err := os.WriteFile(dst, []byte(hdr+pre+strings.Join(keep, "")+tail), 0o644); err != nil {
			return nil, err
		}
		index = append(index, s.OutDir+"/"+fname)
	}
	if len(clashes) > 0 {
		return nil, fmt.Errorf("rule name clashes (different rules, same name) — add RENAME entries:\n  %s", strings.Join(clashes, "\n  "))
	}
	// ліцензії джерел (байт у байт)
	for _, l := range c.Licenses {
		p := filepath.Join(in.Sources[l[0]], l[1])
		if _, err := os.Stat(p); err == nil {
			if err := copyFile(p, filepath.Join(out, "LICENSE-"+l[0])); err != nil {
				return nil, err
			}
		}
	}
	// YARA-Forge: ліцензія кожного взятого джерела
	if forge, ok := c.source("yara-forge"); ok {
		tag := strings.SplitN(forge.Pin, ":", 2)[1]
		parts := []string{"Rules in general/yara-rules-core.yar come from YARA-Forge (https://yarahq.github.io/), release " +
			tag + ". Each rule keeps its author / reference / source_url meta. Only these sources are taken; their licences follow.\n"}
		var repos []string
		for r := range c.ForgeSources {
			repos = append(repos, r)
		}
		sort.Strings(repos)
		bar := strings.Repeat("=", 78)
		for _, repo := range repos {
			f := filepath.Join(in.Sources["yara-forge"], "licenses", strings.ReplaceAll(repo, "/", "_")+".txt")
			body := "see https://github.com/" + repo + "\n"
			if t, err := readText(f); err == nil {
				body = t
			}
			parts = append(parts, bar+"\n"+repo+" ("+c.ForgeSources[repo]+") - https://github.com/"+repo+"\n"+bar+"\n"+body)
		}
		if err := os.WriteFile(filepath.Join(out, "LICENSE-yara-forge"), []byte(strings.Join(parts, "\n")), 0o644); err != nil {
			return nil, err
		}
	}
	idx := []string{"// GENERATED by rules/tools/build_vendor_rules.py from tools/vendor-selection.txt — do not edit.",
		"// Vendor rules (no meta.severity) for docscan: applied to the raw file -> yara_file_matches,",
		"// and to decompressed VBA -> yara_matches. Rules tagged docscan_info -> yara_info_matches",
		"// (indicators: reported, never raise the verdict). See tools/vendor-report.md.", ""}
	for _, p := range index {
		idx = append(idx, `include "`+p+`"`)
	}
	idx = append(idx, "", "// DocScan's own rules", `include "maldoc/vba_plaintext.yar"`, "")
	if err := os.WriteFile(filepath.Join(out, "file-index.yar"), []byte(strings.Join(idx, "\n")), 0o644); err != nil {
		return nil, err
	}
	if in.VBAPlaintext != "" {
		os.MkdirAll(filepath.Join(out, "maldoc"), 0o755)
		if err := copyFile(in.VBAPlaintext, filepath.Join(out, "maldoc", "vba_plaintext.yar")); err != nil {
			return nil, err
		}
	}
	if tools.Configured() {
		args := []string{"-w"}
		for _, e := range yaraexec.Externals {
			args = append(args, "-d", e+"=")
		}
		r, err := tools.RunYarac(out, append(args, filepath.Join(out, "file-index.yar"), os.DevNull)...)
		if err != nil {
			return nil, err
		}
		if r.ExitCode != 0 {
			o := r.Output
			if len(o) > 3000 {
				o = o[:3000]
			}
			return nil, fmt.Errorf("COMPILE FAILED:\n%s", o)
		}
	}
	rep.Files, rep.Rules = len(index), len(seen)
	lines := []string{"# Vendor rules — build report", "", "Generated by `rules/tools/build_vendor_rules.py`. Sources:", ""}
	for _, s := range c.Sources {
		lines = append(lines, fmt.Sprintf("- %s: %s @ `%s`", s.Name, s.URL, first(s.Pin, 12)))
	}
	lines = append(lines, "", fmt.Sprintf("Files: %d, rules kept: %d, dropped: %d, duplicates skipped: %d, renamed: %d, info: %d, doc: %d",
		len(index), len(seen), len(rep.Dropped), len(rep.Duplicates), len(rep.Renamed), len(rep.Info), len(rep.Doc)), "")
	for _, sec := range []struct {
		items []string
		title string
	}{
		{rep.Dropped, "Dropped (cannot fire on a Windows workstation / DROP list)"},
		{rep.Duplicates, "Duplicates skipped (identical rule already taken from another file)"},
		{rep.FilesSkipped, "Files with no rule left"},
		{rep.Renamed, "Renamed (identifier clashes)"},
		{rep.Info, fmt.Sprintf("Tagged `%s` (indicators, do not raise the verdict)", c.InfoTag)},
		{rep.Doc, fmt.Sprintf("Tagged `%s` (document rules: indicators only on non-documents)", c.DocTag)},
	} {
		lines = append(lines, fmt.Sprintf("## %s (%d)", sec.title, len(sec.items)), "")
		for _, x := range sec.items {
			lines = append(lines, "- "+x)
		}
		lines = append(lines, "")
	}
	os.MkdirAll(filepath.Join(out, "tools"), 0o755)
	if err := os.WriteFile(filepath.Join(out, "tools", "vendor-report.md"), []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		return nil, err
	}
	return rep, nil
}

// GeneratedDirs — що генератор переписує в дереві правил (main(): rmtree перед збиранням) — під час збирання
// пакета ці частини дерева беруться з генератора, а не з джерела.
var GeneratedDirs = []string{"general", "maldoc/signature-base", "maldoc/community", "maldoc/bartblaze", "maldoc/inquest", "maldoc/ditekshen"}

func firstNonEmpty(s ...string) string {
	for _, x := range s {
		if x != "" {
			return x
		}
	}
	return ""
}

// first — перші n символів (Python s[:n]).
func first(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	return err
}
