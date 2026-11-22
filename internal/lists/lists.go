// Package lists — білий і чорний списки організації (whitelist.json / blacklist.json).
//
// Перевірка — тим самим кодом, що на ПК (orglists.Parse, дослівна копія з DocScan). Підпис — так само, як
// docscan-updater -SignList (updater/listsign.go: signList): Parse → новий serial → канонічний JSON
// (MarshalIndent + "\n") → підпис саме цих байтів. Інакше на сервері лежатиме не те, що бачила людина.
package lists

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rifatismailov/Anthophila_Hive/internal/docscan/manifest"
	"github.com/rifatismailov/Anthophila_Hive/internal/docscan/orglists"
)

// Kinds — вид списку -> ім'я файлу.
var Kinds = []struct{ Kind, File string }{{"white", "whitelist.json"}, {"black", "blacklist.json"}}

// FileName — ім'я файлу списку.
func FileName(kind string) string {
	if kind == "white" {
		return "whitelist.json"
	}
	return "blacklist.json"
}

// MaxSize — updater бере список не більший за 8 МіБ (updater/lists.go: fetchOpt(…, 8<<20)).
const MaxSize = 8 << 20

// Load — список з теки lists/ простору; файлу немає — порожній список.
func Load(dir, kind string) (*orglists.List, error) {
	b, err := os.ReadFile(filepath.Join(dir, FileName(kind)))
	if os.IsNotExist(err) {
		return &orglists.List{Schema: orglists.Schema, Entries: []orglists.Entry{}}, nil
	}
	if err != nil {
		return nil, err
	}
	return orglists.Parse(b, kind)
}

// Canonical — байти списку так, як їх підписує DocScan: Parse (нормалізація записів) → MarshalIndent + "\n".
func Canonical(l *orglists.List, kind string) ([]byte, *orglists.List, error) {
	raw, err := json.Marshal(l)
	if err != nil {
		return nil, nil, err
	}
	n, err := orglists.Parse(raw, kind)
	if err != nil {
		return nil, nil, err
	}
	if n.Entries == nil {
		n.Entries = []orglists.Entry{}
	}
	data, err := json.MarshalIndent(n, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	data = append(data, '\n')
	if len(data) > MaxSize {
		return nil, nil, fmt.Errorf("%s: %d bytes, PCs take at most %d", FileName(kind), len(data), MaxSize)
	}
	return data, n, nil
}

// Save — робоча копія (непідписана, без зміни serial) у теці lists/ простору.
func Save(dir, kind string, l *orglists.List) error {
	data, _, err := Canonical(l, kind)
	if err != nil {
		return err
	}
	os.MkdirAll(dir, 0o755)
	return os.WriteFile(filepath.Join(dir, FileName(kind)), data, 0o644)
}

// NextSerial — як signList: UTC РРРРММДДггххсс, але щонайменше на 1 більший за кожен з prev (опублікований на
// цілі, у самому списку).
func NextSerial(now time.Time, prev ...int64) int64 {
	s, _ := strconv.ParseInt(now.UTC().Format("20060102150405"), 10, 64)
	for _, p := range prev {
		if s <= p {
			s = p + 1
		}
	}
	return s
}

// Signed — підписаний список.
type Signed struct {
	Kind, File string
	Data, Sig  []byte
	Serial     int64
	KeyID      string
	Entries    int
}

// Sign — новий serial (більший за published і за serial списку), канонічні байти, підпис seed і самоперевірка
// manifest.VerifySig публічним ключем pub (тим, що стоїть на ПК у lists.public_keys).
func Sign(l *orglists.List, kind, seedB64, pub string, published int64, now time.Time) (*Signed, error) {
	c := *l
	c.Entries = append([]orglists.Entry(nil), l.Entries...)
	c.Serial = NextSerial(now, published, l.Serial)
	data, n, err := Canonical(&c, kind)
	if err != nil {
		return nil, err
	}
	got, err := manifest.PublicKeyOf(seedB64)
	if err != nil {
		return nil, err
	}
	if got != pub {
		return nil, fmt.Errorf("the lists signing key is %s, the workspace says %s - PCs would reject the list", got, pub)
	}
	sig, err := manifest.Sign(data, seedB64)
	if err != nil {
		return nil, err
	}
	kid, err := manifest.VerifySig(data, sig, []string{pub})
	if err != nil {
		return nil, fmt.Errorf("self-check: %w", err)
	}
	return &Signed{Kind: kind, File: FileName(kind), Data: data, Sig: []byte(sig), Serial: n.Serial, KeyID: kid, Entries: len(n.Entries)}, nil
}

// VerifySigned — те, що робить updater/lists.go: checkList: підпис ключем з keys, формат, serial > 0 і > prev.
func VerifySigned(data, sig []byte, kind string, keys []string, prev int64) (*orglists.List, string, error) {
	if len(data) > MaxSize || len(sig) > 4096 {
		return nil, "", fmt.Errorf("%s: larger than PCs take", FileName(kind))
	}
	kid, err := manifest.VerifySig(data, string(sig), keys)
	if err != nil {
		return nil, "", err
	}
	l, err := orglists.Parse(data, kind)
	if err != nil {
		return nil, kid, fmt.Errorf("signed, but not a valid list: %w", err)
	}
	if l.Serial <= 0 {
		return l, kid, fmt.Errorf(`signed, but without "serial"`)
	}
	if l.Serial <= prev {
		return l, kid, fmt.Errorf("serial %d is not newer than %d", l.Serial, prev)
	}
	return l, kid, nil
}

// SHA256 — хеш вмісту (для запису sha256 із завантаженого файлу; сам файл не зберігається).
func SHA256(r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Warning — зауваження, що не блокує (людина вирішує).
type Warning struct {
	Kind  string // white | black
	Index int    // номер запису (-1 — весь список)
	Text  string
}

var fileLike = regexp.MustCompile(`\.[A-Za-z0-9]{1,5}$`)

// Warnings — те, що orglists.Parse пропускає, але що майже напевно помилка (PLAN.md F5) або послаблення захисту.
func Warnings(white, black *orglists.List) []Warning {
	var w []Warning
	for _, x := range []struct {
		kind string
		l    *orglists.List
	}{{"white", white}, {"black", black}} {
		if x.l == nil {
			continue
		}
		seen := map[string]int{}
		for i, e := range x.l.Entries {
			if t := strings.TrimRight(strings.ReplaceAll(e.LnkTarget, "/", `\`), `\`); t != "" {
				last := t[strings.LastIndex(t, `\`)+1:]
				if fileLike.MatchString(last) {
					w = append(w, Warning{x.kind, i, fmt.Sprintf("lnk_target %q схожий на файл: це тека-префікс (\\\\сервер\\шара\\тека\\), ціль ярлика %s з ним не збігається — запис не спрацює", e.LnkTarget, last)})
				}
			}
			if x.kind == "white" && e.Path != "" && e.SHA256 == "" && e.LnkTarget == "" {
				w = append(w, Warning{x.kind, i, fmt.Sprintf("маска %q без sha256 / lnk_target пропускає БУДЬ-ЯКИЙ файл з такою назвою в такій теці без перевірки", e.Path)})
			}
			if strings.TrimSpace(e.Comment) == "" {
				w = append(w, Warning{x.kind, i, "немає comment: навіщо цей запис?"})
			}
			k := strings.ToLower(e.Path + "|" + e.LnkTarget + "|" + e.SHA256)
			if j, ok := seen[k]; ok {
				w = append(w, Warning{x.kind, i, fmt.Sprintf("повтор запису %d", j)})
			}
			seen[k] = i
		}
	}
	if white != nil && black != nil {
		bl := map[string]int{}
		for i, e := range black.Entries {
			if e.SHA256 != "" {
				bl[strings.ToLower(e.SHA256)] = i
			}
		}
		for i, e := range white.Entries {
			if j, ok := bl[strings.ToLower(e.SHA256)]; ok && e.SHA256 != "" {
				w = append(w, Warning{"white", i, fmt.Sprintf("той самий sha256 у чорному списку (запис %d): чорний за sha256 перемагає — файл завжди в карантині", j)})
			}
		}
	}
	return w
}
