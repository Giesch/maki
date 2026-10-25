# 03: Scope subagent tools and directories

[Feature overview](../polytoken_features.md)

## Goal

Let an extension select which MCP capabilities a subagent can reach and explicitly set its launch directory. Keep capability selection separate from filesystem confinement and operating-system sandboxing.

## Current behavior

Lua subagents accept selected ordinary tool definitions and local Lua tools. Direct MCP delegation is controlled by an opt-in boolean, not a server/tool allowlist. MCP definitions must not be inserted into the ordinary `tools` array.

Lua subagent creation has no cwd/worktree option. Bash supports a per-call `workdir`, but that does not set the agent's environment, instruction discovery, or all other tools' path base.

## Scope

Implement two reviewable pieces under one consistent session capability policy:

1. Explicit MCP server/tool selection, enforced during discovery and dispatch.
2. Explicit launch-directory configuration, with documented path-resolution and permission behavior.

Automatic Git worktree creation, merge policy, cleanup, and an OS sandbox are out of scope. A directory option must not be advertised as isolation.

## Proposed API direction

Retain compatibility with `mcp = false` and `mcp = true`. Add a structured policy form or a separate option for selected server and tool identities. Define absent versus empty policies, precedence, and behavior when servers reconnect or add tools.

Add an explicit launch-directory option, likely `cwd`. Require an existing directory and validate access before creating the agent. Resolve it once rather than changing the process-wide working directory.

If directory bounds are included later, use a separate explicit option. Define the tools and access paths it covers. Do not imply that unrestricted shell or external MCP tools are confined by path validation.

## Implementation steps

### MCP capability policy

1. Trace MCP discovery, deferred search, direct dispatch, and nested `code_execution`/`batch` calls.
2. Define one effective policy derived from parent reachability, plugin permissions, and requested narrowing. A child cannot grant itself capabilities unavailable to its parent.
3. Filter tool discovery and schemas using that policy.
4. Enforce the same policy at dispatch, including calls that guess a hidden tool name and nested calls.
5. Specify whether MCP resources and prompts are covered; do not leave an undocumented alternate access route.
6. Handle reconnects and newly discovered tools according to the declared policy without modifying an existing request prefix unsafely.

### Launch directory

1. Audit agent environment construction, instruction discovery, file-tool path resolution, shell defaults, and nested subagent inheritance.
2. Carry the resolved directory in session context rather than global process state.
3. Apply existing permissions to external-directory access and reject invalid paths before starting a model turn.
4. Define which project instructions and project configuration apply. Do not accidentally load executable project plugins merely because a worker targets another directory.
5. Document the shared-filesystem model and recommend explicit worktrees when independent edits are required.

## Invariants

- Hidden MCP tools are also uncallable through direct and nested dispatch.
- Tool discovery and execution use the same effective policy.
- A narrowed child cannot regain excluded capabilities by spawning another child.
- Relative paths resolve consistently from the selected launch directory.
- No operation changes the process-wide cwd.
- Directory selection alone makes no security-confinement claim.

## Acceptance criteria

- A reviewer can access one MCP server or selected tools without receiving all parent MCP access.
- Guessed names, deferred searches, nested calls, and reconnects cannot bypass the policy.
- Existing boolean MCP behavior remains compatible.
- Two agents can run concurrently with different launch directories and resolve relative paths correctly.
- Invalid and unauthorized directories fail before provider work begins.
- Tests cover symlinks and traversal according to the documented directory-access policy.
- Any claimed directory restriction includes explicit tests and documented limitations for shell, MCP, and local plugin tools.

## References

- [Polytoken facet tool policies](https://docs.polytoken.dev/harness-engineering/facets/)
- [Polytoken subagent launch metadata](https://docs.polytoken.dev/harness-engineering/subagents/)
- `maki-lua/src/api/agent.rs`
- `plugins/bash/init.lua`
- `maki-acp/src/server.rs`
- `site/docs/content/mcp/_index.md`
