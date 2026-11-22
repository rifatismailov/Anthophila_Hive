// Package store — SQLite Hive: індекс правил (відновлюється з git і знімків), релізи, публікації, журнал аудиту.
// Те, що вирішує людина, живе в git робочого простору; тут — те, що потрібно шукати й показувати.
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// DB — відкрита база.
type DB struct{ *sql.DB }

const schema = `
CREATE TABLE IF NOT EXISTS rules (
  ws TEXT NOT NULL, origin TEXT NOT NULL, file TEXT NOT NULL, name TEXT NOT NULL,
  kind TEXT NOT NULL, private INTEGER NOT NULL, tags TEXT NOT NULL, meta TEXT NOT NULL,
  line INTEGER NOT NULL, text_hash TEXT NOT NULL,
  PRIMARY KEY (ws, origin, file, name)
);
CREATE INDEX IF NOT EXISTS rules_name ON rules(ws, name);
CREATE TABLE IF NOT EXISTS releases (
  ws TEXT NOT NULL, version TEXT NOT NULL, status TEXT NOT NULL, created TEXT NOT NULL,
  ws_commit TEXT NOT NULL, key_id TEXT NOT NULL, files INTEGER NOT NULL, pkg_sha TEXT NOT NULL,
  dir TEXT NOT NULL, result TEXT NOT NULL, report TEXT NOT NULL,
  PRIMARY KEY (ws, version)
);
CREATE TABLE IF NOT EXISTS publications (
  ws TEXT NOT NULL, what TEXT NOT NULL, version TEXT NOT NULL, target TEXT NOT NULL,
  at TEXT NOT NULL, by TEXT NOT NULL, location TEXT NOT NULL, result TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS lab_sets (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, mode TEXT NOT NULL, path TEXT NOT NULL, confidential INTEGER NOT NULL,
  files INTEGER NOT NULL, bytes INTEGER NOT NULL, added TEXT NOT NULL, by TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS lab_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ws TEXT NOT NULL, candidate TEXT NOT NULL, cand_sha TEXT NOT NULL,
  baseline TEXT NOT NULL, base_sha TEXT NOT NULL, mode TEXT NOT NULL, created TEXT NOT NULL, result TEXT NOT NULL,
  report TEXT NOT NULL, by TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS vendor_history (
  ws TEXT NOT NULL, origin TEXT NOT NULL, rev TEXT NOT NULL, date TEXT NOT NULL, subject TEXT NOT NULL, counts TEXT NOT NULL,
  PRIMARY KEY (ws, origin, rev)
);
CREATE TABLE IF NOT EXISTS vendor_history_rules (
  ws TEXT NOT NULL, origin TEXT NOT NULL, rev TEXT NOT NULL, rule TEXT NOT NULL, file TEXT NOT NULL,
  status TEXT NOT NULL, detail TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS vhr_rule ON vendor_history_rules(ws, rule);
CREATE TABLE IF NOT EXISTS audit (
  at TEXT NOT NULL, ws TEXT NOT NULL, who TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL
);
`

// Open — база в path (створюється).
func Open(path string) (*DB, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	// міграції: нові стовпці (помилка «duplicate column» — стовпець уже є)
	db.Exec(`ALTER TABLE rules ADD COLUMN body_hash TEXT NOT NULL DEFAULT ''`)
	db.Exec(`ALTER TABLE rules ADD COLUMN strings_sig TEXT NOT NULL DEFAULT ''`)
	db.Exec(`ALTER TABLE rules ADD COLUMN cond_canon TEXT NOT NULL DEFAULT ''`)
	db.Exec(`ALTER TABLE rules ADD COLUMN idx_ver INTEGER NOT NULL DEFAULT 0`)
	db.Exec(`ALTER TABLE releases ADD COLUMN built_by TEXT NOT NULL DEFAULT ''`)
	db.Exec(`CREATE TABLE IF NOT EXISTS approvals (ws TEXT NOT NULL, version TEXT NOT NULL, pkg_sha TEXT NOT NULL, by TEXT NOT NULL, at TEXT NOT NULL, note TEXT NOT NULL)`)
	return &DB{db}, nil
}

// Rule — запис індексу правил.
type Rule struct {
	WS, Origin, File, Name string // origin: id джерела, "org" або "critical"
	Kind                   string // detection | critical | policy
	Private                bool
	Tags                   []string
	Meta                   map[string]string
	Line                   int
	TextHash               string   // L0: текст без коментарів (dupes.TextHash)
	BodyHash               string   // L1: канонічне тіло (dupes.BodyHash)
	Strings                []string // L2 / L3: канонічні рядки (dupes.Signature)
	Cond                   string   // L3: канонічна умова
}

// IndexVersion — версія формату індексу правил; старіший — перебудовується (hive.Open).
const IndexVersion = 3 // 3: файли .rule (InQuest)

// ReplaceRules — замінити індекс правил одного походження (джерело / власні).
func (d *DB) ReplaceRules(ws, origin string, rules []Rule) error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM rules WHERE ws=? AND origin=?`, ws, origin); err != nil {
		return err
	}
	st, err := tx.Prepare(`INSERT OR REPLACE INTO rules (ws,origin,file,name,kind,private,tags,meta,line,text_hash,body_hash,strings_sig,cond_canon,idx_ver) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer st.Close()
	for _, r := range rules {
		meta, _ := json.Marshal(r.Meta)
		if _, err := st.Exec(ws, origin, r.File, r.Name, r.Kind, r.Private, strings.Join(r.Tags, " "), string(meta), r.Line, r.TextHash, r.BodyHash, strings.Join(r.Strings, " "), r.Cond, IndexVersion); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// RuleQuery — пошук у бібліотеці.
type RuleQuery struct {
	WS     string
	Text   string // частина назви, шляху файлу або тегу
	Origin string
	Kind   string
	Limit  int
	Offset int
}

// FindRules — правила за запитом (і загальна кількість).
func (d *DB) FindRules(q RuleQuery) ([]Rule, int, error) {
	where := []string{"ws=?"}
	args := []any{q.WS}
	if q.Text != "" {
		where = append(where, "(name LIKE ? OR file LIKE ? OR tags LIKE ? OR meta LIKE ?)")
		like := "%" + q.Text + "%"
		args = append(args, like, like, like, like)
	}
	if q.Origin != "" {
		where = append(where, "origin=?")
		args = append(args, q.Origin)
	}
	if q.Kind != "" {
		where = append(where, "kind=?")
		args = append(args, q.Kind)
	}
	w := strings.Join(where, " AND ")
	var total int
	if err := d.QueryRow(`SELECT count(*) FROM rules WHERE `+w, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if q.Limit <= 0 {
		q.Limit = 100
	}
	rows, err := d.Query(`SELECT ws,origin,file,name,kind,private,tags,meta,line,text_hash FROM rules WHERE `+w+
		` ORDER BY origin, file, line LIMIT ? OFFSET ?`, append(args, q.Limit, q.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Rule
	for rows.Next() {
		var r Rule
		var tags, meta string
		if err := rows.Scan(&r.WS, &r.Origin, &r.File, &r.Name, &r.Kind, &r.Private, &tags, &meta, &r.Line, &r.TextHash); err != nil {
			return nil, 0, err
		}
		r.Tags = strings.Fields(tags)
		json.Unmarshal([]byte(meta), &r.Meta)
		out = append(out, r)
	}
	return out, total, rows.Err()
}

// RulesNamed — усі правила з назвою name у просторі.
func (d *DB) RulesNamed(ws, name string) ([]Rule, error) {
	rows, err := d.Query(`SELECT origin,file,kind FROM rules WHERE ws=? AND name=?`, ws, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Rule
	for rows.Next() {
		r := Rule{WS: ws, Name: name}
		rows.Scan(&r.Origin, &r.File, &r.Kind)
		out = append(out, r)
	}
	return out, rows.Err()
}

// Release — зібраний (кандидат) або опублікований пакет.
type Release struct {
	WS, Version, Status string // built | published
	Created             time.Time
	WSCommit, KeyID     string
	Files               int
	PkgSHA, Dir         string
	Result              string // результат контракту
	Report              string // JSON звіту контракту
	BuiltBy             string // хто зібрав («чотири ока»: публікує інший)
}

// PutRelease — записати / замінити (кандидат тієї самої версії замінюється; опублікований — ніколи).
func (d *DB) PutRelease(r Release) error {
	var st string
	err := d.QueryRow(`SELECT status FROM releases WHERE ws=? AND version=?`, r.WS, r.Version).Scan(&st)
	if err == nil && st == "published" && r.Status != "published" {
		return fmt.Errorf("%s %s is already published - it is never rebuilt", r.WS, r.Version)
	}
	_, err = d.Exec(`INSERT OR REPLACE INTO releases (ws,version,status,created,ws_commit,key_id,files,pkg_sha,dir,result,report,built_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`, r.WS, r.Version, r.Status,
		r.Created.UTC().Format(time.RFC3339), r.WSCommit, r.KeyID, r.Files, r.PkgSHA, r.Dir, r.Result, r.Report, r.BuiltBy)
	return err
}

// Releases — релізи простору, новіші першими.
func (d *DB) Releases(ws string) ([]Release, error) {
	rows, err := d.Query(`SELECT ws,version,status,created,ws_commit,key_id,files,pkg_sha,dir,result,report,built_by FROM releases WHERE ws=? ORDER BY created DESC`, ws)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Release
	for rows.Next() {
		var r Release
		var c string
		if err := rows.Scan(&r.WS, &r.Version, &r.Status, &c, &r.WSCommit, &r.KeyID, &r.Files, &r.PkgSHA, &r.Dir, &r.Result, &r.Report, &r.BuiltBy); err != nil {
			return nil, err
		}
		r.Created, _ = time.Parse(time.RFC3339, c)
		out = append(out, r)
	}
	return out, rows.Err()
}

// Release — один реліз.
func (d *DB) Release(ws, version string) (*Release, error) {
	rs, err := d.Releases(ws)
	if err != nil {
		return nil, err
	}
	for i := range rs {
		if rs[i].Version == version {
			return &rs[i], nil
		}
	}
	return nil, fmt.Errorf("%s: no release %s", ws, version)
}

// Publication — запис публікації.
type Publication struct {
	WS, What, Version, Target string // what: rules | whitelist | blacklist; version: vX.Y.Z або serial
	At                        time.Time
	By, Location, Result      string
}

// AddPublication — записати.
func (d *DB) AddPublication(p Publication) error {
	_, err := d.Exec(`INSERT INTO publications VALUES (?,?,?,?,?,?,?,?)`, p.WS, p.What, p.Version, p.Target,
		p.At.UTC().Format(time.RFC3339), p.By, p.Location, p.Result)
	return err
}

// Publications — публікації простору, новіші першими.
func (d *DB) Publications(ws string) ([]Publication, error) {
	rows, err := d.Query(`SELECT ws,what,version,target,at,by,location,result FROM publications WHERE ws=? ORDER BY at DESC, rowid DESC`, ws)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Publication
	for rows.Next() {
		var p Publication
		var at string
		rows.Scan(&p.WS, &p.What, &p.Version, &p.Target, &at, &p.By, &p.Location, &p.Result)
		p.At, _ = time.Parse(time.RFC3339, at)
		out = append(out, p)
	}
	return out, rows.Err()
}

// Audit — запис журналу (лише додавання).
func (d *DB) Audit(ws, who, action, detail string) {
	d.Exec(`INSERT INTO audit VALUES (?,?,?,?,?)`, time.Now().UTC().Format(time.RFC3339), ws, who, action, detail)
}

// AuditEntry — запис журналу.
type AuditEntry struct{ At, WS, Who, Action, Detail string }

// AuditLog — останні n записів простору.
func (d *DB) AuditLog(ws string, n int) ([]AuditEntry, error) {
	rows, err := d.Query(`SELECT at,ws,who,action,detail FROM audit WHERE ws=? ORDER BY rowid DESC LIMIT ?`, ws, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var a AuditEntry
		rows.Scan(&a.At, &a.WS, &a.Who, &a.Action, &a.Detail)
		out = append(out, a)
	}
	return out, rows.Err()
}

// AllRules — усі правила простору (для дублікатів).
func (d *DB) AllRules(ws string) ([]Rule, error) {
	rows, err := d.Query(`SELECT origin,file,name,kind,private,text_hash,body_hash,strings_sig,cond_canon FROM rules WHERE ws=?`, ws)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Rule
	for rows.Next() {
		r := Rule{WS: ws}
		var sig string
		if err := rows.Scan(&r.Origin, &r.File, &r.Name, &r.Kind, &r.Private, &r.TextHash, &r.BodyHash, &sig, &r.Cond); err != nil {
			return nil, err
		}
		r.Strings = strings.Fields(sig)
		out = append(out, r)
	}
	return out, rows.Err()
}

// LabSet — набір лабораторії (спільний для всіх просторів Hive).
type LabSet struct {
	ID, Kind, Mode, Path string
	Confidential         bool
	Files                int
	Bytes                int64
	Added, By            string
}

// PutLabSet — записати набір.
func (d *DB) PutLabSet(s LabSet) error {
	_, err := d.Exec(`INSERT OR REPLACE INTO lab_sets VALUES (?,?,?,?,?,?,?,?,?)`, s.ID, s.Kind, s.Mode, s.Path, s.Confidential, s.Files, s.Bytes, s.Added, s.By)
	return err
}

// DeleteLabSet — прибрати набір.
func (d *DB) DeleteLabSet(id string) error {
	_, err := d.Exec(`DELETE FROM lab_sets WHERE id=?`, id)
	return err
}

// LabSets — усі набори.
func (d *DB) LabSets() ([]LabSet, error) {
	rows, err := d.Query(`SELECT id,kind,mode,path,confidential,files,bytes,added,by FROM lab_sets ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LabSet
	for rows.Next() {
		var s LabSet
		rows.Scan(&s.ID, &s.Kind, &s.Mode, &s.Path, &s.Confidential, &s.Files, &s.Bytes, &s.Added, &s.By)
		out = append(out, s)
	}
	return out, rows.Err()
}

// LabRun — прогін лабораторії (report — шлях до звіту JSON у теці даних).
type LabRun struct {
	ID                      int64
	WS, Candidate, CandSHA  string
	Baseline, BaseSHA, Mode string
	Created                 time.Time
	Result, Report, By      string
}

// AddLabRun — записати прогін; повертає id.
func (d *DB) AddLabRun(r LabRun) (int64, error) {
	res, err := d.Exec(`INSERT INTO lab_runs (ws,candidate,cand_sha,baseline,base_sha,mode,created,result,report,by) VALUES (?,?,?,?,?,?,?,?,?,?)`,
		r.WS, r.Candidate, r.CandSHA, r.Baseline, r.BaseSHA, r.Mode, r.Created.UTC().Format(time.RFC3339), r.Result, r.Report, r.By)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// SetLabRunResult — новий результат (після прийняття спрацювання).
func (d *DB) SetLabRunResult(id int64, result string) error {
	_, err := d.Exec(`UPDATE lab_runs SET result=? WHERE id=?`, result, id)
	return err
}

// LabRuns — прогони простору, новіші першими.
func (d *DB) LabRuns(ws string) ([]LabRun, error) {
	rows, err := d.Query(`SELECT id,ws,candidate,cand_sha,baseline,base_sha,mode,created,result,report,by FROM lab_runs WHERE ws=? ORDER BY id DESC`, ws)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LabRun
	for rows.Next() {
		var r LabRun
		var c string
		rows.Scan(&r.ID, &r.WS, &r.Candidate, &r.CandSHA, &r.Baseline, &r.BaseSHA, &r.Mode, &c, &r.Result, &r.Report, &r.By)
		r.Created, _ = time.Parse(time.RFC3339, c)
		out = append(out, r)
	}
	return out, rows.Err()
}

// LabRunByID — один прогін.
func (d *DB) LabRunByID(ws string, id int64) (*LabRun, error) {
	rs, err := d.LabRuns(ws)
	if err != nil {
		return nil, err
	}
	for i := range rs {
		if rs[i].ID == id {
			return &rs[i], nil
		}
	}
	return nil, fmt.Errorf("no lab run %d", id)
}

// StaleRules — скільки правил простору проіндексовано без хешів дублікатів (старий формат індексу).
func (d *DB) StaleRules(ws string) (int, error) {
	var n int
	err := d.QueryRow(`SELECT count(*) FROM rules WHERE ws=? AND idx_ver<?`, ws, IndexVersion).Scan(&n)
	return n, err
}

// ReportVersion — одна версія звіту генератора.
type ReportVersion struct {
	Origin, Rev, Date, Subject string
	Counts                     map[string]int
}

// ReportRule — статус правила у версії звіту.
type ReportRule struct {
	Rule, File, Status, Detail string
}

// PutReportVersion — записати версію звіту (замінює ту саму версію).
func (d *DB) PutReportVersion(ws string, v ReportVersion, rules []ReportRule) error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	c, _ := json.Marshal(v.Counts)
	if _, err := tx.Exec(`INSERT OR REPLACE INTO vendor_history VALUES (?,?,?,?,?,?)`, ws, v.Origin, v.Rev, v.Date, v.Subject, string(c)); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM vendor_history_rules WHERE ws=? AND origin=? AND rev=?`, ws, v.Origin, v.Rev); err != nil {
		return err
	}
	st, err := tx.Prepare(`INSERT INTO vendor_history_rules VALUES (?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer st.Close()
	for _, r := range rules {
		if _, err := st.Exec(ws, v.Origin, v.Rev, r.Rule, r.File, r.Status, r.Detail); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ReportVersions — версії звіту, старіші першими.
func (d *DB) ReportVersions(ws string) ([]ReportVersion, error) {
	rows, err := d.Query(`SELECT origin,rev,date,subject,counts FROM vendor_history WHERE ws=? ORDER BY date, rowid`, ws)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ReportVersion
	for rows.Next() {
		var v ReportVersion
		var c string
		rows.Scan(&v.Origin, &v.Rev, &v.Date, &v.Subject, &c)
		json.Unmarshal([]byte(c), &v.Counts)
		out = append(out, v)
	}
	return out, rows.Err()
}

// RuleInReports — статуси правила в усіх версіях звіту (origin|rev -> статус).
func (d *DB) RuleInReports(ws, rule string) (map[string]ReportRule, error) {
	rows, err := d.Query(`SELECT origin,rev,rule,file,status,detail FROM vendor_history_rules WHERE ws=? AND rule=?`, ws, rule)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]ReportRule{}
	for rows.Next() {
		var o, rev string
		var r ReportRule
		rows.Scan(&o, &rev, &r.Rule, &r.File, &r.Status, &r.Detail)
		out[o+"|"+rev] = r
	}
	return out, rows.Err()
}

// Approval — схвалення релізу рецензентом.
type Approval struct {
	WS, Version, PkgSHA, By, Note string
	At                            time.Time
}

// AddApproval — записати схвалення.
func (d *DB) AddApproval(a Approval) error {
	_, err := d.Exec(`INSERT INTO approvals VALUES (?,?,?,?,?,?)`, a.WS, a.Version, a.PkgSHA, a.By, a.At.UTC().Format(time.RFC3339), a.Note)
	return err
}

// Approvals — схвалення саме цього пакета (sha) релізу.
func (d *DB) Approvals(ws, version, pkgSHA string) ([]Approval, error) {
	rows, err := d.Query(`SELECT ws,version,pkg_sha,by,at,note FROM approvals WHERE ws=? AND version=? AND pkg_sha=? ORDER BY at`, ws, version, pkgSHA)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Approval
	for rows.Next() {
		var a Approval
		var at string
		rows.Scan(&a.WS, &a.Version, &a.PkgSHA, &a.By, &at, &a.Note)
		a.At, _ = time.Parse(time.RFC3339, at)
		out = append(out, a)
	}
	return out, rows.Err()
}
