# 02: Steer running subagents

[Feature overview](../polytoken_features.md)

## Goal

Expose the existing subagent inbox capability to Lua so a coordinator can send updated requirements or findings while a subagent is running, without waiting for its current `:prompt()` call to finish.

## Current behavior

The TUI routes messages to a running subagent's inbox. The public Lua session handle offers `:prompt()` and `:close()`, but no dedicated steering operation. Concurrent `:prompt()` calls serialize behind the session mutex rather than inject into an active run.

This is primarily an API-exposure and lifecycle-contract task, not a new messaging runtime.

## Scope

- Queue a message on an owned, running subagent.
- Deliver it at a documented safe boundary, never in the middle of a provider response or tool-call/result pair.
- Return enqueue success or a structured failure without waiting for the agent to finish.
- Share routing and ordering behavior with the TUI inbox.

Do not include history rewriting, interrupting a tool, arbitrary cross-plugin messaging, or durable delivery across process restarts.

## Proposed API direction

Add a method such as `Session:send(message)` or `Session:steer(message)`. Select one name after reviewing existing API conventions.

Document that acceptance means queued, not consumed. Define behavior for idle, completed, closing, and closed sessions. Prefer rejecting delivery when no active run can consume it, leaving `:prompt()` as the explicit way to start another turn.

If delivery acknowledgement is needed, return a message ID and expose its state separately. Avoid adding acknowledgement machinery without a workflow that needs it.

## Implementation steps

1. Trace TUI inbox routing in `maki-ui/src/app/queue.rs` and identify the agent-side sender and consumption boundary.
2. Expose a sender on the Lua session handle without taking the mutex held by the active `:prompt()` call.
3. Validate ownership and lifecycle atomically with enqueueing, so a completion race cannot report misleading success.
4. Define ordering between user and plugin messages, queue limits, cancellation, and whether already accepted messages can be discarded at shutdown.
5. Route delivered text through the appropriate existing message hooks and transcript attribution. Mark it as plugin input rather than a human approval.
6. Add Lua documentation and a small coordinator example that sends new findings while a worker runs.

## Invariants

- Messages append at safe boundaries and never mutate earlier requests.
- A send operation cannot answer permission prompts or impersonate the user.
- Queue saturation returns an explicit error rather than silently losing input.
- Closing a session does not leave senders or pending callbacks alive indefinitely.
- Plugin and TUI inbox paths obey the same ordering and cancellation rules.

## Acceptance criteria

- A Lua coordinator can send while another task awaits `:prompt()` on the same session.
- The worker receives the message at the next supported boundary, in the documented order.
- Messages are not injected into a partial tool exchange.
- Completion/enqueue races have deterministic outcomes and documented delivery semantics.
- Closed, unauthorized, and full-queue cases return useful errors.
- Tests coordinate fake providers and explicit barriers rather than sleeps.

## References

- [Polytoken messaging running subagents](https://docs.polytoken.dev/using-polytoken/subagents/)
- `maki-ui/src/app/queue.rs`
- `maki-lua/src/api/agent.rs`
- `maki-lua/src/api/task.rs`
