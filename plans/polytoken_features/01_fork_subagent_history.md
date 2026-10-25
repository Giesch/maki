# 01: Fork subagent history

[Feature overview](../polytoken_features.md)

## Goal

Allow a Lua extension to create independent subagents from a completed subagent's conversation, then supply a new directive. Support branching an investigation or implementation into multiple continuations without flattening all context into prose.

## Current behavior

`maki.agent.session()` creates empty history. Repeated `Session:prompt()` calls continue that session, but there is no public history-seed or subagent-fork option. Main-chat forks exist in the UI and are not equivalent to a Lua subagent fork.

## Scope

- Fork a completed or idle subagent owned by the calling plugin and permitted parent scope.
- Preserve valid conversation structure and corresponding tool artifacts.
- Give each fork independent identity, future history, usage accounting, and lifecycle.
- Preserve the source unchanged.
- Reject unsupported compatibility combinations explicitly.

Do not include arbitrary transcript editing, cloning running calls, filesystem snapshots, or implicit worktree creation.

## Proposed API direction

Choose between `Session:fork(opts)` and a `source` option on `maki.agent.session()` after reviewing handle ownership and persisted-task access. Prefer a typed session handle for the first implementation rather than unrestricted session IDs.

The API must distinguish native-history cloning from portable-text transfer. If native continuation is incompatible, return a useful error or require an explicit portable transfer mode. Do not silently flatten provider reasoning or present that fallback as a native fork.

Decide whether closed handles can be forked. A completed prompt and a closed session are different states. Access to persisted completed tasks can be a later extension if it requires a separate ownership model.

## Implementation steps

1. Inspect subagent history ownership, tool-output storage, and main-session fork code for reusable snapshot primitives.
2. Define immutable snapshot capture at an idle boundary. Reject a source with an active prompt rather than racing its output.
3. Define compatibility checks for provider/model, system prompt, tool definitions, and provider-bound reasoning. Start with conservative same-configuration native forks.
4. Create the new agent with an independent history owner and valid initial frame. Do not copy active cancellation tokens, queued input, jobs, or source spending.
5. Preserve referenced tool outputs for the fork's lifetime without allowing source cleanup to invalidate them.
6. Expose the Lua operation with explicit ownership checks, errors, cancellation behavior, and cleanup.
7. Document native forks versus text transfer and update generated API documentation from source.

## Invariants

- Fork creation never modifies the source request prefix.
- Subsequent requests in each fork remain append-only within their frame.
- Tool calls and results remain paired.
- A fork cannot acquire permissions unavailable to the caller or its parent.
- Historical token usage is not billed again as new spending; actual continuation requests are accounted normally.
- Working-directory files remain shared unless explicitly isolated elsewhere.

## Acceptance criteria

- Two forks from one source can receive different prompts and evolve independently.
- The source transcript and usage do not change when a fork runs or closes.
- Forked tool artifacts survive source closure according to the documented lifetime contract.
- Incompatible native forks fail before sending a provider request.
- A running source cannot produce an inconsistent snapshot.
- Unauthorized source access is rejected.
- Tests cover cancellation, source/fork cleanup, tool-result pairing, usage accounting, and append-only requests using deterministic fake providers.

## Open decisions

- Handle-only access initially, or access to persisted completed subagents as well?
- Which configuration changes are compatible with native history?
- Should portable transfer use a transcript, a summary, or a caller-selected strategy?

## References

- [Polytoken subagent resume](https://docs.polytoken.dev/using-polytoken/subagents/)
- `maki-lua/src/api/agent.rs`
- `maki-storage/src/sessions.rs`
- `maki-ui/src/app/session.rs`
- `maki-agent/src/agent/run.rs`
