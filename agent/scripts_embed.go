package agent

// scripts_embed.go — 内嵌截图助手脚本（webshot/annotate），运行时释放到工作目录。

import (
	_ "embed"
)

//go:embed scripts/webshot.py
var webshotScript string

//go:embed scripts/annotate.py
var annotateScript string
