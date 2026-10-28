package server

// apimodels_api.go — 业务建模 HTTP API：列表/详情/下载 OpenAPI/删除。

import (
	"net/http"
	"strconv"
)

func (s *Server) registerApiModelRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/apimodels", s.apiModelList)
	mux.HandleFunc("GET /api/apimodels/{id}", s.apiModelGet)
	mux.HandleFunc("GET /api/apimodels/{id}/openapi", s.apiModelDownload)
	mux.HandleFunc("DELETE /api/apimodels/{id}", s.apiModelDelete)
}

func (s *Server) apiModelList(w http.ResponseWriter, r *http.Request) {
	taskID, _ := strconv.ParseInt(r.URL.Query().Get("task_id"), 10, 64)
	list, err := s.m.pg.ApiModels().List(taskID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if list == nil {
		writeJSON(w, 200, map[string]any{"items": []any{}})
		return
	}
	writeJSON(w, 200, map[string]any{"items": list})
}

func (s *Server) apiModelGet(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	m, err := s.m.pg.ApiModels().Get(id)
	if err != nil {
		writeErr(w, 404, "记录不存在")
		return
	}
	writeJSON(w, 200, m)
}

func (s *Server) apiModelDownload(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	m, err := s.m.pg.ApiModels().Get(id)
	if err != nil {
		writeErr(w, 404, "记录不存在")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="openapi-`+strconv.FormatInt(id, 10)+`.json"`)
	_, _ = w.Write(m.Doc)
}

func (s *Server) apiModelDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := s.m.pg.ApiModels().Delete(id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
