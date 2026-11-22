// Package install — порт того, як docscan-updater перевіряє і розкладає пакет правил перед встановленням
// (updater/rules.go, updater/update.go), без служб Windows і без заміни <InstallDir>\rules.
//
// Кожна функція — копія логіки свого оригіналу (вказано в коментарі). Змінився оригінал у DocScan — перенести
// зміну сюди: контракт Hive вартий рівно стільки, наскільки цей код збігається з кодом на ПК.
package install

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/rifatismailov/Anthophila_Hive/internal/docscan/manifest"
)

// Імена й ліміти — як в updater.
const (
	ManifestName = "rules-manifest.json" // updater/rules.go: rulesManifestName
	SigName      = "rules-manifest.sig"  // rulesSigName
	PackageName  = "DocScan-rules.zip"   // cirun/deploy/rules.go: RulesPkgAsset
	BundleName   = "DocScan-rules-bundle.zip"

	MaxManifest    = 4 << 20   // updater/update.go: maxManifest (служба качає маніфест з цим лімітом)
	MaxSig         = 4096      // updater/rules.go: fetch(base, rulesSigName, 4096)
	MaxUnpacked    = 4 << 30   // updater/update.go: maxUnpacked
	MaxBundleEntry = 512 << 20 // updater/rules.go: installRulesFile — більші файли bundle пропускаються
)

// Bundle — файли верхнього рівня пакета для ручного встановлення і те, що updater мовчки пропустив би.
type Bundle struct {
	Files   map[string][]byte
	Skipped []string // підтеки, файли в підтеках, завеликі файли (на ПК — пропуск без помилки)
}

// ReadBundle — updater/rules.go: installRulesFile (читання): тека — її файли верхнього рівня; інакше zip — лише
// файли верхнього рівня, не більші за 512 МіБ.
func ReadBundle(src string) (*Bundle, error) {
	b := &Bundle{Files: map[string][]byte{}}
	if st, err := os.Stat(src); err == nil && st.IsDir() {
		ents, _ := os.ReadDir(src)
		for _, e := range ents {
			if e.IsDir() {
				b.Skipped = append(b.Skipped, e.Name()+"/")
				continue
			}
			if data, err := os.ReadFile(filepath.Join(src, e.Name())); err == nil {
				b.Files[e.Name()] = data
			}
		}
		return b, nil
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return nil, err
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("%s: not a zip: %w", src, err)
	}
	for _, e := range zr.File {
		if e.FileInfo().IsDir() || strings.ContainsAny(e.Name, `/\`) || e.UncompressedSize64 > MaxBundleEntry {
			b.Skipped = append(b.Skipped, e.Name)
			continue
		}
		rc, err := e.Open()
		if err != nil {
			return nil, err
		}
		b.Files[e.Name], err = io.ReadAll(io.LimitReader(rc, MaxBundleEntry))
		rc.Close()
		if err != nil {
			return nil, err
		}
	}
	return b, nil
}

// VerifyManifest — updater/rules.go: installRulesFile (перевірка): маніфест і підпис є, підпис дійсний для одного з
// keys, продукт — docscan-rules, пакет названий у маніфесті є. Повертає маніфест, key_id і байти пакета.
func VerifyManifest(files map[string][]byte, keys []string) (*manifest.Manifest, string, []byte, error) {
	data, sig := files[ManifestName], files[SigName]
	if data == nil || sig == nil {
		return nil, "", nil, fmt.Errorf("no %s / %s", ManifestName, SigName)
	}
	m, keyID, err := manifest.VerifyProduct(data, string(sig), keys, manifest.ProductRules)
	if err != nil {
		return nil, "", nil, err
	}
	pkg := files[m.Package.Name]
	if pkg == nil {
		return m, keyID, nil, fmt.Errorf("no %s", m.Package.Name)
	}
	return m, keyID, pkg, nil
}

// CheckPackage — updater/rules.go: stageRules (перша частина): розмір і sha256 пакета — з маніфесту.
func CheckPackage(m *manifest.Manifest, pkg []byte) error {
	h := sha256.Sum256(pkg)
	if int64(len(pkg)) != m.Package.Size || hex.EncodeToString(h[:]) != m.Package.SHA256 {
		return fmt.Errorf("%s: size / sha256 differ from the signed manifest", m.Package.Name)
	}
	return nil
}

// Unpack — updater/update.go: unpackVerified: кожен файл zip має бути в маніфесті, безпечний шлях, без повторів,
// sha256 збігається, разом не більше 4 ГіБ, і в zip є ВСІ файли маніфесту. Розпаковує в dir (через dir.tmp).
func Unpack(pkg []byte, m *manifest.Manifest, dir string) error {
	zr, err := zip.NewReader(bytes.NewReader(pkg), int64(len(pkg)))
	if err != nil {
		return err
	}
	tmp := dir + ".tmp"
	os.RemoveAll(tmp)
	ok := false
	defer func() {
		if !ok {
			os.RemoveAll(tmp)
		}
	}()
	seen := map[string]bool{}
	var total int64
	for _, e := range zr.File {
		if e.FileInfo().IsDir() {
			continue
		}
		want, listed := m.Files[e.Name]
		if !listed || !manifest.SafePath(e.Name) {
			return fmt.Errorf("unexpected file in the package: %q", e.Name)
		}
		if seen[e.Name] {
			return fmt.Errorf("file twice in the package: %q", e.Name)
		}
		seen[e.Name] = true
		dst := filepath.Join(tmp, filepath.FromSlash(e.Name))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		rc, err := e.Open()
		if err != nil {
			return err
		}
		f, err := os.Create(dst)
		if err != nil {
			rc.Close()
			return err
		}
		h := sha256.New()
		n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(rc, MaxUnpacked-total+1))
		rc.Close()
		f.Close()
		if err != nil {
			return err
		}
		if total += n; total > MaxUnpacked {
			return fmt.Errorf("the package unpacks to more than %d bytes", int64(MaxUnpacked))
		}
		if hex.EncodeToString(h.Sum(nil)) != want {
			return fmt.Errorf("%s: sha256 differs from the signed manifest", e.Name)
		}
	}
	if len(seen) != len(m.Files) {
		return fmt.Errorf("the package has %d of %d files of the manifest", len(seen), len(m.Files))
	}
	os.RemoveAll(dir)
	if err := os.Rename(tmp, dir); err != nil {
		return err
	}
	ok = true
	return nil
}

// Stage — updater/rules.go: stageRules: пакет → розпакування з перевіркою → є docscan-index.yar.
func Stage(m *manifest.Manifest, pkg []byte, dir string) error {
	if err := CheckPackage(m, pkg); err != nil {
		return err
	}
	if err := Unpack(pkg, m, dir); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(dir, "docscan-index.yar")); err != nil {
		os.RemoveAll(dir)
		return fmt.Errorf("the rules package has no docscan-index.yar")
	}
	return nil
}

// Compiler — пробна компіляція (yaraexec.Tools; у тестах — заглушка).
type Compiler interface {
	CompileIndex(dir string) error    // yarac + зовнішні змінні DocScan, docscan-index.yar
	CompileCritical(dir string) error // yara --critical-rules=<dir>
}

// Compile — updater/rules.go: compileRules: основні правила, потім critical/ пакета.
func Compile(c Compiler, dir string) error {
	if err := c.CompileIndex(dir); err != nil {
		return err
	}
	return c.CompileCritical(filepath.Join(dir, "critical"))
}

// VersionOfDir — updater/rules.go: installedRules / versionOfDir: vX.Y.Z з першого рядка VERSION.txt (BOM
// прибирається). Саме так ПК дізнаються, яку версію правил встановлено.
func VersionOfDir(dir string) (version, firstLine string) {
	b, err := os.ReadFile(filepath.Join(dir, "VERSION.txt"))
	if err != nil {
		return "", ""
	}
	firstLine = strings.SplitN(strings.TrimPrefix(string(b), "\ufeff"), "\n", 2)[0]
	return manifest.VersionFromTitle(firstLine), firstLine
}
