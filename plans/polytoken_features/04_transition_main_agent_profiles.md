# 04: Transition main-agent profiles

[Feature overview](../polytoken_features.md)

## Goal

Provide an explicit way to move a main session between named profiles with different prompts, tools, and optional model settings, while preserving Maki's append-only request contract and valid provider history.

This is a design proposal requiring an architecture decision before implementation. It is not authorization to reproduce Polytoken's prefix mutation.

## Current behavior and constraint

Polytoken facets replace the system prompt and toolset ahead of the same conversation and accept the resulting cache miss.

Maki keeps requests append-only. Rebuilding `system` or `tools`, or editing earlier messages within an active frame, can invalidate prompt caches and provider-bound thinking blocks. Dynamic identity/tone changes reach the main agent as context updates. Plan/build transitions do not establish an arbitrary named-profile API.

## Scope

- Resolve a profile to a prompt, effective tool policy, and optional model settings.
- Request a transition explicitly at a safe boundary.
- Create an announced new frame when prefix changes are required.
- Define context carryover, provider compatibility, persistence, and failure semantics.
- Expose the operation to Lua only after the core transition contract is established.

Do not include arbitrary history editing, unannounced prompt replacement, automatic model-group failover, or profile-based filesystem rollback.

## Design options

### Context-update-only profiles

Append role instructions and enforce narrower tools through runtime policy. This is the smallest change, but it does not replace the original system prompt or remove advertised tool definitions. Label it as a limited mode rather than full facet parity.

### New-frame profiles

Start a fresh request frame with the new system prompt and tool definitions. Carry context using a documented compatible-history or summary strategy. Announce the boundary in the transcript.

This is the preferred direction for full profile semantics, subject to provider compatibility investigation. A new frame alone does not make old signed reasoning valid under a different prefix.

### New-session profiles

Create a separate chat/session and transfer portable context. This has clearer separation, but differs from switching profiles within one conversation. It can serve as an initial explicit fallback.

## Implementation steps

1. Audit existing frame transitions, plan/build behavior, compaction, model switching, and provider thinking/reasoning constraints.
2. Specify profile resolution and ownership. Keep a Lua-defined registry separate from the minimal core transition primitive where possible.
3. Define effective permissions and tool policies, reusing plan 03 rather than introducing a second capability mechanism.
4. Define context-transfer modes. Reject unsupported native-history carryover and require explicit portable conversion rather than silently dropping reasoning or tool results.
5. Validate the target profile, model, and tools before changing session state. Establish atomic commit and clear error behavior for preparation failures.
6. Permit transitions only at safe boundaries. Define whether busy-session requests queue or fail, and how active subagents and background jobs are treated.
7. Record the transition and selected profile in session state. Define resume behavior when the profile changes or disappears after reload.
8. Add UI feedback, Lua access, and documentation that explains cache and context implications.

## Invariants

- Existing frame prefixes remain immutable.
- Prefix-changing transitions create an explicit, announced new frame or session.
- Provider-bound reasoning is never replayed under an incompatible prefix.
- Tool calls and results remain paired across any context transfer.
- A profile cannot exceed granted permissions.
- A tool-triggered transition cannot silently grant the model additional authority; define when user approval is required.
- Failure before commit leaves the original profile and history usable.

## Acceptance criteria

- An extension can move between reviewer and implementer profiles with distinct prompts and effective toolsets.
- Each frame passes append-only contract tests.
- Tests cover same-provider and cross-provider transitions, including reasoning-bearing histories.
- Rejected, cancelled, and invalid transitions do not leave partially applied state.
- Restored sessions identify their active profile and handle missing or changed definitions explicitly.
- Context-transfer mode and any loss of native continuation state are visible to the user.
- Cache-prefix changes occur only at the declared transition boundary.

## Decisions required before implementation

- Does a profile transition preserve the visible transcript while starting a summarized model context?
- Which providers permit compatible native-history transfer under which changes?
- Should profile definitions be pinned per session or re-resolved after reload?
- How should rewind interact with a profile boundary? Rich event-aware rewind is a separate project, so unsupported behavior must be explicit.
- Do running subagents retain their launch profile, or must a transition stop them? Avoid silently changing their active prefixes.
- Is a separate-session first version preferable to a new-frame first version?

## References

- [Polytoken facets](https://docs.polytoken.dev/harness-engineering/facets/)
- [Polytoken context and model transitions](https://docs.polytoken.dev/using-polytoken/sessions/)
- `maki-agent/src/agent/frame.rs`
- `maki-agent/src/agent/run.rs`
- `maki-lua/src/api/agent.rs`
- `site/docs/content/lua-api/_index.md`
