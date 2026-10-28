package db

// apimodels.go — 业务建模存储（移植自哨兵 apimodels：分片合并 OpenAPI + 实体替换）。

import (
	"encoding/json"
	"time"
)

// ApiModelStore 持久化业务建模记录。
type ApiModelStore struct{ db *DB }

// ApiModels returns the store.
func (d *DB) ApiModels() *ApiModelStore { return &ApiModelStore{db: d} }

// ApiModels returns the store bound to this asset store's DB.
func (s *AssetStore) ApiModels() *ApiModelStore { return &ApiModelStore{db: s.db} }

// ApiModel 一条建模记录。
type ApiModel struct {
	ID        int64           `json:"id"`
	TaskID    int64           `json:"task_id"`
	Title     string          `json:"title"`
	Target    string          `json:"target"`
	Status    string          `json:"status"`
	Doc       json.RawMessage `json:"doc"`
	Entities  json.RawMessage `json:"entities"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// ApiEntity 业务实体（哨兵 entitySchema）。
type ApiEntity struct {
	Name        string        `json:"name"`
	Description string        `json:"description,omitempty"`
	Fields      []ApiField    `json:"fields,omitempty"`
	Relations   []ApiRelation `json:"relations,omitempty"`
}
type ApiField struct {
	Name        string `json:"name"`
	Type        string `json:"type,omitempty"`
	Description string `json:"description,omitempty"`
}
type ApiRelation struct {
	Target      string `json:"target"`
	Kind        string `json:"kind,omitempty"`
	Description string `json:"description,omitempty"`
}

// List 按任务列（task_id=0 表示全部）。
func (s *ApiModelStore) List(taskID int64) ([]*ApiModel, error) {
	q := `SELECT id, task_id, title, target, status, doc, entities, created_at, updated_at FROM api_models`
	var args []any
	if taskID != 0 {
		args = append(args, taskID)
		q += ` WHERE task_id=$` + itoa(int64(len(args)))
	}
	q += ` ORDER BY id DESC LIMIT 100`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ApiModel
	for rows.Next() {
		m, err := scanApiModel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

// Get 取单条。
func (s *ApiModelStore) Get(id int64) (*ApiModel, error) {
	row := s.db.QueryRow(`SELECT id, task_id, title, target, status, doc, entities, created_at, updated_at FROM api_models WHERE id=$1`, id)
	return scanApiModel(row)
}

func scanApiModel(row interface{ Scan(...any) error }) (*ApiModel, error) {
	var m ApiModel
	if err := row.Scan(&m.ID, &m.TaskID, &m.Title, &m.Target, &m.Status, &m.Doc, &m.Entities, &m.CreatedAt, &m.UpdatedAt); err != nil {
		return nil, err
	}
	if len(m.Entities) == 0 {
		m.Entities = json.RawMessage("[]")
	}
	return &m, nil
}

// EnsureDraft 取/建本任务的 draft（建模 run 的载体；done 后再 submit 开新 draft）。
func (s *ApiModelStore) EnsureDraft(taskID int64, title, target string) (*ApiModel, error) {
	var id int64
	err := s.db.QueryRow(`SELECT id FROM api_models WHERE task_id=$1 AND status='draft' ORDER BY id DESC LIMIT 1`, taskID).Scan(&id)
	if err == nil {
		return s.Get(id)
	}
	if err.Error() != "sql: no rows in result set" {
		return nil, err
	}
	if err := s.db.QueryRow(`INSERT INTO api_models (task_id, title, target, doc, entities)
VALUES ($1,$2,$3,'{"openapi":"3.0.3","info":{"title":"Draft"},"paths":{}}','[]') RETURNING id`,
		taskID, title, target).Scan(&id); err != nil {
		return nil, err
	}
	return s.Get(id)
}

// SubmitMerge 分片合并（哨兵语义）：paths 按路径合并（同路径对象整体替换）、
// components 按段内名称合并、openapi 整文档按顶层键覆盖、entities 整份替换。
// 返回合并后的 paths/operations/entities 计数与告警。
func (s *ApiModelStore) SubmitMerge(id int64, whole, paths, components json.RawMessage, entities json.RawMessage, title, target string) (pathCount, opCount, entityCount int, warnings []string, err error) {
	m, err := s.Get(id)
	if err != nil {
		return 0, 0, 0, nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal(m.Doc, &doc); err != nil || doc == nil {
		doc = map[string]any{"openapi": "3.0.3", "info": map[string]any{"title": m.Title}, "paths": map[string]any{}}
	}
	if doc["paths"] == nil {
		doc["paths"] = map[string]any{}
	}
	if len(whole) > 0 {
		var w map[string]any
		if jerr := json.Unmarshal(whole, &w); jerr == nil {
			for k, v := range w {
				doc[k] = v
			}
		} else {
			warnings = append(warnings, "openapi 整文档解析失败，已忽略")
		}
	}
	if len(paths) > 0 {
		var p map[string]any
		if jerr := json.Unmarshal(paths, &p); jerr == nil {
			docPaths, _ := doc["paths"].(map[string]any)
			if docPaths == nil {
				docPaths = map[string]any{}
			}
			for k, v := range p {
				docPaths[k] = v // 同路径整体替换
			}
			doc["paths"] = docPaths
		} else {
			warnings = append(warnings, "paths 分片解析失败，已忽略")
		}
	}
	if len(components) > 0 {
		var c map[string]any
		if jerr := json.Unmarshal(components, &c); jerr == nil {
			docComp, _ := doc["components"].(map[string]any)
			if docComp == nil {
				docComp = map[string]any{}
			}
			for section, v := range c {
				secMap, ok := v.(map[string]any)
				if !ok {
					docComp[section] = v
					continue
				}
				existing, _ := docComp[section].(map[string]any)
				if existing == nil {
					existing = map[string]any{}
				}
				for name, item := range secMap {
					existing[name] = item
				}
				docComp[section] = existing
			}
			doc["components"] = docComp
		} else {
			warnings = append(warnings, "components 分片解析失败，已忽略")
		}
	}
	// 计数
	if docPaths, ok := doc["paths"].(map[string]any); ok {
		pathCount = len(docPaths)
		for _, v := range docPaths {
			if ops, ok := v.(map[string]any); ok {
				for _, op := range []string{"get", "post", "put", "delete", "patch", "head", "options"} {
					if _, has := ops[op]; has {
						opCount++
					}
				}
			}
		}
		if pathCount == 0 {
			warnings = append(warnings, "paths 仍为空")
		}
	}
	docJSON, _ := json.Marshal(doc)
	entJSON := m.Entities
	if len(entities) > 0 {
		var ents []ApiEntity
		if jerr := json.Unmarshal(entities, &ents); jerr == nil {
			entJSON, _ = json.Marshal(ents)
			entityCount = len(ents)
		} else {
			warnings = append(warnings, "entities 解析失败，保留原值")
			var keep []ApiEntity
			_ = json.Unmarshal(m.Entities, &keep)
			entityCount = len(keep)
		}
	} else {
		var keep []ApiEntity
		_ = json.Unmarshal(m.Entities, &keep)
		entityCount = len(keep)
	}
	newTitle, newTarget := m.Title, m.Target
	if title != "" {
		newTitle = title
	}
	if target != "" {
		newTarget = target
	}
	_, err = s.db.Exec(`UPDATE api_models SET doc=$2, entities=$3, title=$4, target=$5, updated_at=now() WHERE id=$1`,
		id, string(docJSON), string(entJSON), newTitle, newTarget)
	return pathCount, opCount, entityCount, warnings, err
}

// Finish 收口 draft→done。
func (s *ApiModelStore) Finish(id int64) error {
	_, err := s.db.Exec(`UPDATE api_models SET status='done', updated_at=now() WHERE id=$1`, id)
	return err
}

// Delete 删除记录。
func (s *ApiModelStore) Delete(id int64) error {
	_, err := s.db.Exec(`DELETE FROM api_models WHERE id=$1`, id)
	return err
}
