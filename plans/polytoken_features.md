# Polytoken feature comparison and plans

## Purpose

Compare Polytoken's documented capabilities with Maki's current extension APIs and identify focused changes that enable richer agent workflows. This assessment was made on 2026-10-21 from Polytoken documentation and the Maki checkout. It is not a claim of tested runtime parity.

A feature is an extension gap here when Maki's supported Lua API cannot provide the same behavior while retaining the normal agent runtime. Launching an external harness or implementing a separate provider loop may bypass a gap, but is not equivalent to extending the existing session.

## Planned improvements

| Plan | Goal |
| --- | --- |
| [01: Fork subagent history](polytoken_features/01_fork_subagent_history.md) | Create independent subagents from an existing conversation snapshot. |
| [02: Steer running subagents](polytoken_features/02_steer_running_subagents.md) | Expose boundary-delivered inbox messages through Lua. |
| [03: Scope subagent tools and directories](polytoken_features/03_scope_subagent_tools_and_directories.md) | Add explicit MCP allowlists and launch-directory options. |
| [04: Transition main-agent profiles](polytoken_features/04_transition_main_agent_profiles.md) | Define a safe profile transition without mutating an active request prefix. |

The first three extend existing agent capabilities. The fourth requires a product and architecture decision about context carryover and provider compatibility. API names in the individual plans are proposals, not existing interfaces.

## Features requiring core support for equivalent behavior

### Main-conversation facet switching

Polytoken facets replace the system prompt and available tools while retaining the conversation. Its documentation explicitly acknowledges the resulting cache miss. Facets also configure skills, models, and presentation.

Maki supports initial prompt templates, context updates, tool hooks, and specialized subagents. Its active request prefix is append-only. A hook that denies a tool is not equivalent to removing that tool from the advertised definitions. Arbitrary same-conversation prompt/toolset replacement is not a public Lua operation.

See plan 04 for an explicit new-frame alternative. Do not implement profile changes by rewriting earlier system, tool, or message data.

### Native subagent conversation forks

Polytoken's `resume_from` forks a completed subagent's full conversation, including tool results and earlier reasoning, into an independent run. Maki sessions retain their own history across `Session:prompt()` calls, but new Lua sessions start empty. Copying transcript text is not a native history fork.

See plan 01. Fork compatibility must account for provider-bound reasoning and tool availability.

### Provider-native compaction

Polytoken documents provider-native compaction for supported Codex configurations, plus conversion to portable text when a model or facet change makes native state incompatible.

Maki exposes text-compaction instructions, continuation text, and tool-result collapse controls. No equivalent native-compaction integration was found. Supporting opaque continuation state requires provider and history-layer work, outside these four plans.

### Event-aware rewind

Polytoken can rewind across prompts, facet switches, compaction, context clears, and structured questions. It restores relevant todo state and can reissue a question's original options. Its rewind is destructive, not an undo tree, and the cited documentation does not promise filesystem rollback.

Maki has prompt-based rewind and session forks. Lua does not expose general transcript replacement or coordinated event-state restoration. Matching Polytoken's richer rewind needs host support and is outside these plans.

### Detachable daemon and reconnect-safe clients

Polytoken separates the daemon from the TUI. Its protocol provides authenticated snapshots, replay cursors, epochs, and deduplicated operation results.

Maki has ACP and streaming-JSON SDK interfaces, but no equivalent standalone reconnectable daemon service was found. Background Lua agents remain tied to chat/plugin lifetime. Equivalent durability needs an external service or core lifecycle changes, outside these plans.

## Partial equivalents and API gaps

| Feature | Current Maki boundary |
| --- | --- |
| Messages to running subagents | The TUI already supplies an inbox. Lua lacks a dedicated steering method; concurrent `:prompt()` calls serialize. See plan 02. |
| Per-agent MCP policies | Direct MCP delegation is an opt-in boolean. Selected wrapper tools are possible, but native server/tool allowlists are missing. See plan 03. |
| Launch directory and directory bounds | Lua subagent creation has no cwd/worktree option. Tool-specific working directories do not establish confinement. See plan 03. |
| Stateful model-group failover | Plugins can start work on alternate models, but transparent continuation with ordered candidates, sticky routing, and shared cooldowns is not a supplied session API. |
| Before-every-model-turn hooks | There is no general agent-level equivalent of Polytoken's `pre_model_turn`. Provider plugins do have request-body customization for supported codecs. |

## Features feasible as extensions

- Review/fix loops: coordinate separate stateful reviewer and fixer sessions, with explicit tools and structured local reporting tools.
- Markdown agent profiles: load named definitions and translate them into session options.
- Skill tags, allow/deny lists, and chained references: implement a scoped loader; integration with built-in discovery requires additional work.
- Decision agents: call a specialized inference service and validate its structured output.
- Autonomous permission classification: use `permission.prompt` to consult a model. Preserve explicit human escalation.
- Tool flows: `code_execution` already supports sandboxed Python tool orchestration. Exact approval and background-job semantics differ.
- Goals and dependency-aware todos: maintain plugin state and coordinate events. `agent.stop` permits only three consecutive continuations, so an indefinite controller needs a separate lifecycle.
- Language-server tools: use an external LSP bridge or MCP server. Automatic server discovery and lifecycle management are substantial additional work.

A review-loop extension can be built before any of the four core plans. The plans enable native branching, active steering, stronger capability selection, and main-agent profile transitions rather than basic orchestration.

## Implementation order

Plans 01 and 02 can be developed independently. Plan 03 should establish a shared capability policy before plan 04 uses it for main-agent transitions. Plan 04 must resolve its design questions before implementation.

Every change must preserve permission enforcement, explicit cancellation, provider history validity, and the append-only request contract. Do not use prompt instructions as a security boundary.

## Maki implementation references

- `maki-lua/src/api/agent.rs`: session construction, prompt execution, and tool delegation.
- `maki-ui/src/app/queue.rs`: existing subagent inbox routing.
- `maki-ui/src/app/session.rs`: current session fork and rewind behavior.
- `maki-agent/src/agent/frame.rs`: context updates and request frames.
- `maki-agent/src/agent/run.rs`: append-only contract tests.
- `site/docs/content/lua-api/_index.md`: public Lua API reference.
- `site/docs/content/hooks/_index.md`: agent, tool, compaction, and permission hooks.

Generated API documentation must be updated through its source and `maki-docgen`, not edited directly.

## Polytoken sources

- [Facets](https://docs.polytoken.dev/harness-engineering/facets/)
- [Subagent definitions](https://docs.polytoken.dev/harness-engineering/subagents/)
- [Subagent runtime](https://docs.polytoken.dev/using-polytoken/subagents/)
- [Sessions, compaction, rewind, and failover](https://docs.polytoken.dev/using-polytoken/sessions/)
- [Hooks](https://docs.polytoken.dev/harness-engineering/hooks/)
- [Skills](https://docs.polytoken.dev/harness-engineering/skills/)
- [Client protocol](https://docs.polytoken.dev/reference/client-protocol/)
- [Decision agents](https://docs.polytoken.dev/using-polytoken/decision-agents/)
- [Tool flows](https://docs.polytoken.dev/using-polytoken/tool-flows/)
- [Managing work](https://docs.polytoken.dev/using-polytoken/managing-work/)
- [Language servers](https://docs.polytoken.dev/reference/language-servers/)
