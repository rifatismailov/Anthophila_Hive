package dupes

import (
	"hash/fnv"
	"sort"
	"strings"
)

// SimMember — правило для L2 / L3 (Member + канонічні рядки й умова).
type SimMember struct {
	Member
	Strings []string // dupes.Signature
	Cond    string
}

const (
	minStrings = 3   // L2: менше рядків — Жаккар нічого не каже
	threshold  = 0.8 // L2: частка спільних рядків
	bands      = 16
	rows       = 4
)

func jaccard(a, b []string) float64 {
	set := map[string]bool{}
	for _, x := range a {
		set[x] = true
	}
	inter := 0
	for _, x := range b {
		if set[x] {
			inter++
		}
	}
	union := len(set) + len(b) - inter
	if union == 0 {
		return 0
	}
	return float64(inter) / float64(union)
}

func minhash(items []string) []uint64 {
	sig := make([]uint64, bands*rows)
	for i := range sig {
		sig[i] = ^uint64(0)
	}
	for _, it := range items {
		for i := range sig {
			h := fnv.New64a()
			h.Write([]byte{byte(i), byte(i >> 8)})
			h.Write([]byte(it))
			if v := h.Sum64(); v < sig[i] {
				sig[i] = v
			}
		}
	}
	return sig
}

type uf struct{ p []int }

func (u *uf) find(x int) int {
	for u.p[x] != x {
		u.p[x] = u.p[u.p[x]]
		x = u.p[x]
	}
	return x
}
func (u *uf) union(a, b int) { u.p[u.find(a)] = u.find(b) }

// Similar — L2 (схожі: Жаккар рядків ≥ 0.8, тіла різні) і L3 (варіант: рядки варіанта — надмножина, а умова —
// умова базового правила and ще щось: спрацює лише там, де вже спрацьовує базове). MinHash + LSH: O(n), не O(n²).
func Similar(ms []SimMember) []Group {
	var idx []int
	for i, m := range ms {
		if !m.Private && m.BodyHash != "" && len(m.Strings) >= minStrings {
			idx = append(idx, i)
		}
	}
	buckets := map[string][]int{}
	for _, i := range idx {
		sig := minhash(ms[i].Strings)
		for b := 0; b < bands; b++ {
			var sb strings.Builder
			sb.WriteString(ms[i].Kind)
			for r := 0; r < rows; r++ {
				sb.WriteString("|")
				sb.WriteString(uitoa(sig[b*rows+r]))
			}
			k := uitoa(uint64(b)) + sb.String()
			buckets[k] = append(buckets[k], i)
		}
	}
	pairs := map[[2]int]bool{}
	for _, b := range buckets {
		if len(b) < 2 || len(b) > 200 {
			continue
		}
		for x := 0; x < len(b); x++ {
			for y := x + 1; y < len(b); y++ {
				i, j := b[x], b[y]
				if i > j {
					i, j = j, i
				}
				pairs[[2]int{i, j}] = true
			}
		}
	}
	var out []Group
	// L3: рядки варіанта ⊇ рядки базового, частини умови варіанта ⊇ частини умови базового, і є додаткові
	cands := map[[2]int]bool{}
	byStrings := map[string][]int{}
	for i, m := range ms {
		if !m.Private && m.BodyHash != "" && len(m.Strings) > 0 {
			byStrings[m.Kind+"|"+strings.Join(m.Strings, " ")] = append(byStrings[m.Kind+"|"+strings.Join(m.Strings, " ")], i)
		}
	}
	for _, b := range byStrings {
		for x := range b {
			for y := range b {
				if x != y {
					cands[[2]int{b[x], b[y]}] = true
				}
			}
		}
	}
	for p := range pairs {
		cands[p] = true
		cands[[2]int{p[1], p[0]}] = true
	}
	variant := map[[2]int]bool{}
	for p := range cands {
		base, v := ms[p[0]], ms[p[1]]
		if base.BodyHash == v.BodyHash || !subset(base.Strings, v.Strings) {
			continue
		}
		bp, vp := AndParts(base.Cond), AndParts(v.Cond)
		if len(vp) > len(bp) && subset(bp, vp) {
			out = append(out, Group{Level: "L3", Key: "L3|" + base.BodyHash + "|" + v.BodyHash, Members: []Member{base.Member, v.Member}})
			variant[[2]int{min(p[0], p[1]), max(p[0], p[1])}] = true
		}
	}
	// L2: схожі пари (не варіанти) — об'єднання в групи
	u := &uf{p: make([]int, len(ms))}
	for i := range u.p {
		u.p[i] = i
	}
	inGroup := map[int]bool{}
	for p := range pairs {
		i, j := p[0], p[1]
		if variant[p] || ms[i].BodyHash == ms[j].BodyHash || jaccard(ms[i].Strings, ms[j].Strings) < threshold {
			continue
		}
		u.union(i, j)
		inGroup[i], inGroup[j] = true, true
	}
	groups := map[int][]Member{}
	for i := range inGroup {
		groups[u.find(i)] = append(groups[u.find(i)], ms[i].Member)
	}
	for _, g := range groups {
		if len(g) > 1 {
			sort.Slice(g, func(a, b int) bool { return g[a].File+g[a].Name < g[b].File+g[b].Name })
			out = append(out, Group{Level: "L2", Key: "L2|" + g[0].BodyHash, Members: g})
		}
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].Level != out[b].Level {
			return out[a].Level < out[b].Level
		}
		return out[a].Members[0].Name < out[b].Members[0].Name
	})
	return out
}

func subset(a, b []string) bool {
	set := map[string]int{}
	for _, x := range b {
		set[x]++
	}
	for _, x := range a {
		if set[x] == 0 {
			return false
		}
		set[x]--
	}
	return true
}

func uitoa(v uint64) string {
	const digits = "0123456789abcdef"
	var b [16]byte
	for i := 15; i >= 0; i-- {
		b[i] = digits[v&15]
		v >>= 4
	}
	return string(b[:])
}
