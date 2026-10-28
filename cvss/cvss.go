// Package cvss — CVSS v3.1 基准分计算。
// 直接移植自 Full-Chain-Sentinel-System packages/web/src/cvss.ts (MIT)：
// 权重表、Roundup（整数运算防 8.6 算成 8.5）、PR 随 Scope 变化，全部照搬。
// 模型只判指标，分数永远由本包计算。
package cvss

// Metrics CVSS v3.1 八个基准指标（值为规范缩写）。
type Metrics struct {
	Av, Ac, Pr, Ui, S, C, I, A string
}

var avWeight = map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
var acWeight = map[string]float64{"L": 0.77, "H": 0.44}
var uiWeight = map[string]float64{"N": 0.85, "R": 0.62}
var impactWeight = map[string]float64{"H": 0.56, "L": 0.22, "N": 0}

func prWeight(pr string, scopeChanged bool) float64 {
	switch pr {
	case "N":
		return 0.85
	case "L":
		if scopeChanged {
			return 0.68
		}
		return 0.62
	default:
		if scopeChanged {
			return 0.5
		}
		return 0.27
	}
}

// Valid 校验八指标取值合法。
func (m Metrics) Valid() bool {
	in := func(v string, set ...string) bool {
		for _, s := range set {
			if v == s {
				return true
			}
		}
		return false
	}
	return in(m.Av, "N", "A", "L", "P") && in(m.Ac, "L", "H") && in(m.Pr, "N", "L", "H") &&
		in(m.Ui, "N", "R") && in(m.S, "U", "C") &&
		in(m.C, "H", "L", "N") && in(m.I, "H", "L", "N") && in(m.A, "H", "L", "N")
}

// Vector 规范向量串（UI 与导出共用同一格式）。
func (m Metrics) Vector() string {
	return "CVSS:3.1/AV:" + m.Av + "/AC:" + m.Ac + "/PR:" + m.Pr + "/UI:" + m.Ui +
		"/S:" + m.S + "/C:" + m.C + "/I:" + m.I + "/A:" + m.A
}

// roundUp 规范的 Roundup：整数运算，一位小数向上取整。
func roundUp(value float64) float64 {
	scaled := value * 100000
	r := scaled - float64(int64(scaled)/10000*10000) // 余数部分
	base := float64(int64(scaled) / 10000)
	if r > 1e-9 {
		return (base + 1) / 10
	}
	return base / 10
}

// BaseScore CVSS v3.1 基准分 0.0-10.0，一位小数。
func BaseScore(m Metrics) float64 {
	if !m.Valid() {
		return 0
	}
	scopeChanged := m.S == "C"
	iss := 1 - (1-impactWeight[m.C])*(1-impactWeight[m.I])*(1-impactWeight[m.A])
	var impact float64
	if scopeChanged {
		d1 := iss - 0.029
		d2 := iss - 0.02
		pow := 1.0
		for i := 0; i < 15; i++ {
			pow *= d2
		}
		impact = 7.52*d1 - 3.25*pow
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0
	}
	exploitability := 8.22 * avWeight[m.Av] * acWeight[m.Ac] * prWeight(m.Pr, scopeChanged) * uiWeight[m.Ui]
	var raw float64
	if scopeChanged {
		raw = 1.08 * (impact + exploitability)
	} else {
		raw = impact + exploitability
	}
	score := roundUp(raw)
	if score > 10 {
		return 10
	}
	return score
}

// SeverityForCvss 分数对应的五级档位（哨兵原版阈值）。
func SeverityForCvss(cvss float64) string {
	switch {
	case cvss >= 9:
		return "critical"
	case cvss >= 7:
		return "high"
	case cvss >= 4:
		return "medium"
	case cvss > 0:
		return "low"
	default:
		return "info"
	}
}
