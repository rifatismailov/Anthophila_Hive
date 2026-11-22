package vendor

import (
	"regexp"
	"strconv"
	"strings"
)

// ReportEntry — рядок звіту генератора про одне правило.
type ReportEntry struct {
	Status string // dropped | duplicate | renamed | info | doc
	File   string // <джерело>/<шлях>
	Rule   string
	Detail string // причина / «same as …» / нова назва
}

// ParsedReport — vendor-report.md: лічильники і правила з особливим статусом (решта — взяті без змін).
type ParsedReport struct {
	Counts  map[string]int // files, rules kept, dropped, duplicates skipped, renamed, info, doc
	Entries []ReportEntry
}

var countRe = regexp.MustCompile(`([a-z ]+): (\d+)`)

// ParseReport — розбір vendor-report.md будь-якої версії генератора.
func ParseReport(text string) ParsedReport {
	pr := ParsedReport{Counts: map[string]int{}}
	section := ""
	for _, l := range strings.Split(universal(text), "\n") {
		switch {
		case strings.HasPrefix(l, "Files:"):
			for _, m := range countRe.FindAllStringSubmatch(strings.ToLower(l), -1) {
				n, _ := strconv.Atoi(m[2])
				pr.Counts[strings.TrimSpace(m[1])] = n
			}
		case strings.HasPrefix(l, "## "):
			t := strings.ToLower(l)
			switch {
			case strings.HasPrefix(t, "## dropped"):
				section = "dropped"
			case strings.HasPrefix(t, "## duplicates"):
				section = "duplicate"
			case strings.HasPrefix(t, "## renamed"):
				section = "renamed"
			case strings.Contains(t, "docscan_info"):
				section = "info"
			case strings.Contains(t, "docscan_doc"):
				section = "doc"
			default:
				section = ""
			}
		case strings.HasPrefix(l, "- ") && section != "":
			body := l[2:]
			file, rest, ok := strings.Cut(body, ": ")
			if !ok {
				continue
			}
			e := ReportEntry{Status: section, File: file}
			switch section {
			case "dropped", "duplicate":
				e.Rule, e.Detail, _ = strings.Cut(rest, " — ")
			case "renamed":
				e.Rule, e.Detail, _ = strings.Cut(rest, " -> ")
			default:
				e.Rule, e.Detail, _ = strings.Cut(rest, " (")
				if e.Detail != "" {
					e.Detail = strings.TrimSuffix(e.Detail, ")")
				}
			}
			pr.Entries = append(pr.Entries, e)
		}
	}
	return pr
}
