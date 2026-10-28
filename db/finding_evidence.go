package db

// FindingEvidence 一条发现证据（finding_evidence 表）。
// kind: command（命令+输出）/ file（工作目录文件）/ screenshot（截图）。
type FindingEvidence struct {
	Kind    string `json:"kind"`
	Command string `json:"command,omitempty"`
	Output  string `json:"output,omitempty"`
	Path    string `json:"path,omitempty"`
	Note    string `json:"note,omitempty"`
}

// FindingReview LLM 评审员结论（findings.review JSONB）。
// State: queued/running/done/failed。Dubious 记录封顶中危。
type FindingReview struct {
	State        string            `json:"state"`
	Metrics      map[string]string `json:"metrics,omitempty"`
	Capabilities map[string]string `json:"capabilities,omitempty"`
	Dubious      bool              `json:"dubious"`
	Reason       string            `json:"reason,omitempty"`
	Cvss         float64           `json:"cvss,omitempty"`
	Vector       string            `json:"vector,omitempty"`
	At           string            `json:"at,omitempty"`
}
