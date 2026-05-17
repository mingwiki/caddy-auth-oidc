# 项目清理 Spec: caddy-auth-oidc

## 背景

caddy-auth-oidc 项目已开发完毕并交付，代码库中包含大量来自 Trae IDE 开发环境的临时文件和不必要的配置，需要清理以保持仓库整洁。

## 清理目标

删除不再需要的 IDE 产物和配置，精简 .gitignore，保持源码和文档完整不受影响。

## 变更列表

### 删除

| 路径 | 说明 |
|------|------|
| `.trae/` | Trae IDE 构建计划、任务清单、技能描述、规则文件 — 全部已完成，与运行时无关 |
| `.vscode/settings.json` | VSCode Python 环境配置 — Go 项目无关 |
| `AGENTS.md` | Trae IDE 的 Agent 开发流程文档 — 项目已交付无需保留 |
| `.gitignore`（原有） | 替换为 Go 项目专用精简版 |

### 修改

**`.gitignore`** — 从 305 行（Python/Node 模板）精简为 Go 项目核心规则：
- 保留: 构建产物（`dist/`, `build/`）、日志、环境配置、OS 特殊文件
- 去掉: Python/Node/Ruby/Java 等无关语言的忽略规则

### 不动

- `go.mod`, `go.sum`, `plugin.go`, `authoidc/*` — 所有源码和测试
- `README.md`, `.gitattributes`, `.git/` — 文档和版本历史

## 影响评估

- 不影响模块: 无任何代码或配置修改
- 不影响 API: 无
- 不影响数据库: 无
- 不影响构建: 无
- 风险: 极低 — 只删除 IDE 产物和精简 gitignore

## 验收标准

1. `git status` 显示所有预期变更
2. `go test ./...` 仍通过
3. 仓库根目录只保留：Go 源码、README、git 配置、精简 gitignore
