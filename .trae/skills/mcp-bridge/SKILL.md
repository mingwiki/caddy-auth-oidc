---
name: "mcp-bridge"
description: "Uses existing MCP tools/servers. Invoke when tasks require external MCP capabilities."
---

# MCP Bridge

This skill coordinates calls to already-configured MCP tools and servers in the current Trae workspace.

## What this skill does

- Uses existing MCP tools (e.g. Git, knowledge graph, task manager, Context7 docs, file system, etc.).
- Chooses the appropriate MCP tool based on the user's request and current context.
- Avoids re-implementing behavior that an MCP tool already supports.

## When to invoke this skill

- When the user explicitly mentions **MCP** or an external tool/server exposed via MCP.
- When the task clearly maps to an existing MCP capability, for example:
  - Git operations on the current repo（如查看状态、diff、提交等）.
  - Managing or querying a persistent knowledge graph / memory.
  - Using Context7 to read external library documentation.
  - Managing multi-step task workflows via the task manager.
  - Reading special files exposed only through MCP.
- When complex workflows require combining several MCP tools together.

## Usage guidelines

- Prefer MCP tools over ad‑hoc shell commands when both are available.
- Keep calls focused: each MCP call should have a clear, single purpose.
- For multi-step flows, document intermediate results briefly before the next MCP call.

