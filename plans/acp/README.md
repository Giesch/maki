# ACP support

Remaining ACP integration work for agent-shell, based on a comparison of the local Maki and agent-shell sources on 2026-10-24. These are optional feature gaps, not prerequisites for ordinary chat or session restoration.

## High priority

- **Session forking (`session/fork`).** Branch an existing conversation into an independent session. Maki does not implement or advertise this capability. Agent-shell starts a new session without the source history when a fork is requested from an unsupported agent.
- **Editor-mediated file access (`fs/read_text_file`, `fs/write_text_file`).** Use the client's advertised file capabilities so reads and writes can go through Emacs, including its handling of unsaved buffers. Maki currently uses its own filesystem tools. Explicitly attached file context already works.
- **Slash-command advertisement (`available_commands_update`).** Expose supported commands to agent-shell for discovery and completion. Maki currently sends no available-command updates. Define which commands ACP supports before advertising them.

## Lower priority

- **Active-turn steering (`_session/steering`).** Accept guidance while a turn is running. Agent-shell supports this experimental extension and checks `_meta.steering.supported`. Maki neither advertises nor implements it. Recheck the extension contract before implementation.
- **Structured plan updates (`sessionUpdate: "plan"`).** Send task-plan state for agent-shell's native plan display. Maki's existing Build/Plan mode selector does not provide these updates.
- **Resume without replay (`session/resume`).** Restore a session without streaming its history. Restoration already works through `session/load`. Agent-shell falls back to loading and reduced-history rendering for its minimal restore setting.
- **Live session titles (`session_info_update`).** Notify agent-shell when the current session's title changes. Session listing already supplies stored titles, but Maki sends no proactive title updates.
- **SSE MCP transport.** Accept client-injected SSE MCP servers. Maki supports stdio and HTTP, and drops unsupported injected transports with a warning. This only matters for configurations that still use SSE.

## Existing support

Session listing and full-history loading, model selection through `session/set_config_option`, Build/Plan mode selection, image and embedded-context prompts, permissions, native question forms, streaming tool activity, file locations and diffs, usage reporting, and stdio/HTTP MCP injection are already implemented. Legacy `session/set_model` is not required for agent-shell's model selector because it supports config options.

## Existing plans

- [ACP session discovery without pagination](acp_session_discovery.md): closed in favor of upstream PR #1305, now merged locally. Retained as historical design context, not an exact specification of the merged implementation.

## Source references

Paths below are relative to the repository root:

- `maki-acp/src/methods.rs`: advertised capabilities, modes, and model config options.
- `maki-acp/src/server.rs`: request dispatch, client requests, MCP injection, and event translation.
- `maki-acp/src/translate.rs`: tool, history, and usage updates.

The comparison used the sibling `agent-shell` checkout, particularly `agent-shell.el` and `agent-shell-experimental.el`. It was a source review, not an end-to-end interoperability test.
