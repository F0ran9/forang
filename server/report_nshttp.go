package server

// report_nsformat.go 中的 HTTP 处理器（原 taskReportDocx 改为 NS 格式入口）。
import (
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/Autumn-27/artex/db"
)

// taskReportNS GET /api/tasks/{id}/report/docx — 行业模板渗透测试报告。
func (s *Server) taskReportNS(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	t, ok := s.m.Task(idStr)
	if !ok {
		writeErr(w, 404, "任务不存在")
		return
	}
	fs, err := s.m.pg.ListFindingsForExport(db.FindingFilter{}, nil)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	var own []*db.DBFinding
	for _, f := range fs {
		if f.TaskID != nil && fmt.Sprint(*f.TaskID) == t.ID {
			own = append(own, f)
		}
	}
	sort.Slice(own, func(i, j int) bool { return sevOrder[own[i].Severity] < sevOrder[own[j].Severity] })
	if len(own) == 0 {
		writeErr(w, 400, "该任务暂无漏洞中台发现，无法生成报告")
		return
	}
	doc := s.buildNSReport(t, own)
	data, err := doc.Build()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	stamp := time.Now().Format("20060102-150405")
	w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="forang-pentest-report-%s-%s.docx"`, t.ID, stamp))
	_, _ = w.Write(data)
}
