package workspace

import "fmt"

// Edition — редакція пакета: який склад отримують ПК, що читають теку цієї редакції. Усі редакції релізу vX.Y.Z
// збираються з того самого коміту простору; кожна — окремий підписаний пакет (свій маніфест і .sig) зі своїм
// складом, і / або підписані списки. У цілі editions-* кожна редакція — тека <id>/ (rules.mirror.url = lists.url
// = <адреса цілі>/<id>).
type Edition struct {
	ID          string `yaml:"id"`
	Title       string `yaml:"title"`
	Description string `yaml:"description,omitempty"`
	Rules       bool   `yaml:"rules"`    // пакет правил (правила виявлення джерел завжди, якщо Rules)
	Own         bool   `yaml:"own"`      // власні правила виявлення організації (rules/org)
	Critical    bool   `yaml:"critical"` // правила критичної інформації (critical/)
	White       bool   `yaml:"white"`    // білий список
	Black       bool   `yaml:"black"`    // чорний список
}

// Sensitive — що в редакції є даними організації (для публічної цілі — лише з явним підтвердженням).
func (e Edition) Sensitive() []string {
	var out []string
	if e.Rules && e.Own {
		out = append(out, "власні правила виявлення")
	}
	if e.Rules && e.Critical {
		out = append(out, "правила критичної інформації (що саме шукає DLP)")
	}
	if e.White {
		out = append(out, "білий список (чому ПК довіряють без перевірки)")
	}
	if e.Black {
		out = append(out, "чорний список")
	}
	return out
}

// Variant — склад пакета правил: редакції з тим самим складом мають той самий пакет (збирається один раз).
func (e Edition) Variant() string {
	if !e.Rules {
		return ""
	}
	v := "rules"
	if e.Own {
		v += "+own"
	}
	if e.Critical {
		v += "+critical"
	}
	return v
}

// Contents — склад одним рядком (для людей).
func (e Edition) Contents() string {
	s := ""
	add := func(x string) {
		if s != "" {
			s += ", "
		}
		s += x
	}
	if e.Rules {
		add("правила виявлення джерел")
		if e.Own {
			add("власні правила")
		}
		if e.Critical {
			add("критичні правила")
		}
	}
	if e.White {
		add("білий список")
	}
	if e.Black {
		add("чорний список")
	}
	if s == "" {
		return "порожньо"
	}
	return s
}

// DefaultEditions — набір за замовчуванням (змінюється на сторінці «Редакції»).
func DefaultEditions() []Edition {
	return []Edition{
		{ID: "full", Title: "Повна", Rules: true, Own: true, Critical: true, White: true, Black: true,
			Description: "Усе: правила виявлення джерел і власні, правила критичної інформації, білий і чорний списки. Для ПК організації."},
		{ID: "full-black", Title: "Повна без білого списку", Rules: true, Own: true, Critical: true, Black: true,
			Description: "Усі правила і чорний список, без білого: кожен файл сканується, винятків немає."},
		{ID: "nocrit-black", Title: "Без критичних правил, з чорним списком", Rules: true, Own: true, Black: true,
			Description: "Правила виявлення ШПЗ (джерела і власні) і чорний список; без пошуку критичної інформації в документах."},
		{ID: "nocrit", Title: "Лише виявлення ШПЗ", Rules: true, Own: true,
			Description: "Правила виявлення ШПЗ (джерела і власні), без критичних правил і без списків."},
		{ID: "vendor", Title: "Лише правила джерел", Rules: true,
			Description: "Тільки правила виявлення з відкритих джерел (signature-base, YARA-Forge тощо) з рішеннями організації; нічого власного."},
		{ID: "lists", Title: "Лише списки", White: true, Black: true,
			Description: "Тільки білий і чорний списки — для ПК, що беруть правила з іншого місця."},
	}
}

// EditionList — редакції простору (налаштовані або за замовчуванням).
func (c Config) EditionList() []Edition {
	if len(c.Editions) > 0 {
		return c.Editions
	}
	return DefaultEditions()
}

// Edition — редакція за id.
func (c Config) Edition(id string) (*Edition, error) {
	for _, e := range c.EditionList() {
		if e.ID == id {
			return &e, nil
		}
	}
	return nil, fmt.Errorf("no edition %q in workspace %s", id, c.Name)
}

// CheckEditions — перевірка набору редакцій.
func CheckEditions(es []Edition) error {
	seen := map[string]bool{}
	for _, e := range es {
		if !ValidID(e.ID) {
			return fmt.Errorf("edition id %q: lowercase latin letters, digits, . _ -", e.ID)
		}
		if seen[e.ID] {
			return fmt.Errorf("edition %s twice", e.ID)
		}
		seen[e.ID] = true
		if e.Title == "" {
			return fmt.Errorf("edition %s: a title is needed", e.ID)
		}
		if !e.Rules && !e.White && !e.Black {
			return fmt.Errorf("edition %s: neither rules nor lists", e.ID)
		}
		if !e.Rules && (e.Own || e.Critical) {
			return fmt.Errorf("edition %s: own / critical rules need the rules package", e.ID)
		}
	}
	return nil
}

// TargetEditions — редакції, які публікуються в ціль.
func (c Config) TargetEditions(t Target) ([]Edition, error) {
	all := c.EditionList()
	if len(t.Editions) == 0 {
		return all, nil
	}
	var out []Edition
	for _, id := range t.Editions {
		e, err := c.Edition(id)
		if err != nil {
			return nil, fmt.Errorf("target %s: %w", t.ID, err)
		}
		out = append(out, *e)
	}
	return out, nil
}
