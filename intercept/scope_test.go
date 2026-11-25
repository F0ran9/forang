package intercept

// 线上 #1634 回归：裁判不知道任务有授权范围，把对目标的认证探测判成 D4。
// 这里验证 scope 会被注入到裁判输入。

import (
	"context"
	"encoding/json"
	"testing"
)

func TestBuildReviewInputInjectsScope(t *testing.T) {
	old := ScopeResolver
	defer func() { ScopeResolver = old }()

	ScopeResolver = func(taskID string) (ReviewScope, bool) {
		if taskID != "18" {
			return ReviewScope{}, false
		}
		return ReviewScope{
			TaskID:       "18",
			Goal:         "尽可能的发现高危漏洞",
			InScope:      []string{"www.zjmiit.com", "211.90.247.185"},
			InScopeTotal: 2,
			Note:         "授权范围",
		}, true
	}

	ctx := WithTaskID(context.Background(), 18)
	args, _ := json.Marshal(map[string]string{"command": "curl -sI https://www.zjmiit.com"})
	in, err := BuildReviewInput(ctx, "Bash", args)
	if err != nil {
		t.Fatal(err)
	}
	if in.Scope == nil || in.Scope.InScopeTotal != 2 || len(in.Scope.InScope) != 2 {
		t.Fatalf("scope 未注入: %+v", in.Scope)
	}

	// 没有 taskID 的上下文不应带 scope（避免把闲聊会话当成授权任务）
	in2, _ := BuildReviewInput(context.Background(), "Bash", args)
	if in2.Scope != nil {
		t.Fatal("无 taskID 时不应带 scope")
	}
}
