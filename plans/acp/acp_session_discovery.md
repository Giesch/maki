# ACP session discovery without pagination

> **Closed — won't implement.** Existing upstream [PR #1305: feat(acp): answer session/list from stored sessions](https://github.com/tontinton/maki/pull/1305) covers this feature. This plan will not be implemented separately.

## Goal

Expose persisted Maki sessions through ACP `session/list` so clients such as agent-shell can offer a session picker and load the selected session through the existing `session/load` implementation.

The first implementation returns all matching sessions in one response. It does not implement pagination, change session restoration, or add multiple active sessions per ACP process.

## Protocol contract

- Advertise `sessionCapabilities.list` during initialization, alongside the existing `loadSession` capability.
- Accept `session/list` independently of whether a session is active.
- With no `cwd`, return all persisted sessions available in the configured Maki storage directory.
- With an absolute `cwd`, return sessions whose stored working directory exactly matches it. Preserve the storage API's existing matching semantics; do not introduce canonicalization or recursive project matching.
- Reject relative `cwd` values with an invalid-params error.
- Reject any supplied cursor with an invalid-params error explaining that pagination is unsupported.
- Return all matching entries, newest first, with a deterministic session-ID tie-breaker for equal update timestamps.
- Each entry includes the session ID, absolute working directory, title when available, and an ISO-8601 update timestamp when representable.
- Omit `nextCursor`, including for an empty result. An empty list is a successful response.
- Skip legacy entries whose working directory cannot satisfy the absolute-path requirement. Do not invent a directory or resolve a relative path against the ACP process directory. Log skipped entries without exposing conversation contents.
- Map storage failures to an ACP internal error with a useful explanation. Do not present a failed scan as an empty history.

Global discovery exposes stored session titles and paths to the connected ACP client. Document this behavior; it does not expose conversation contents until a session is loaded.

## Reuse existing support

The existing schema dependency already provides list request/response types, session metadata types, and the capability declaration. No dependency upgrade or storage migration is required.

Reuse the storage summary APIs rather than reading full conversation histories:

- `SessionSummary` in `maki-storage/src/sessions.rs`: ID, title, working directory, and update time.
- `Session::list` and `Session::list_all` in the same file: directory-filtered and global listing with cached header scanning.
- `src/cmd/session.rs`: existing CLI consumer of both listing paths.
- `maki-ui/src/event_loop.rs`: existing use of `smol::unblock` for session discovery.

The scanner may maintain its existing header cache. Discovery must not acquire session claims, modify conversation histories, replace the active session, resolve folder trust, load project configuration, or start MCP servers.

## Implementation steps

### 1. Advertise and dispatch the capability

In `maki-acp/src/methods.rs`, extend `initialize_response()` with the session-list capability using the existing schema builders.

In `maki-acp/src/server.rs`, add `session/list` to `handle_request()` and parse its parameters with the existing helper. Return the schema's `ListSessionsResponse` variant.

### 2. List stored sessions without blocking protocol work

Implement a listing handler in `maki-acp/src/server.rs`:

1. Validate the optional working directory and reject cursors.
2. Run the appropriate storage listing function through `smol::unblock` so filesystem scanning does not block the async executor.
3. Filter entries with unusable working directories.
4. Sort summaries by descending update time and a stable session-ID tie-breaker.
5. Convert summaries to ACP session metadata and return a response without a continuation cursor.

Keep conversion logic separate from active-session state. Use the existing storage location from `AcpParams`.

Offloading the scan keeps the executor responsive, but the current server dispatcher awaits request handlers. Do not describe this change as making all protocol request handling concurrent. Broader dispatcher concurrency is outside this plan.

Use the workspace's existing `jiff` dependency for timestamp formatting if needed, adding `jiff.workspace = true` to `maki-acp/Cargo.toml`. Safely omit an unrepresentable optional timestamp rather than panicking.

### 3. Add focused tests

Extend the existing ACP tests and reuse their server/storage fixtures. Follow repository conventions for parameterized tests and shared expected error strings.

Cover:

- Initialization advertises both listing and loading.
- Wire dispatch accepts `session/list` and serializes the expected response.
- Empty storage returns an empty list without `nextCursor`.
- Global listing includes sessions from multiple directories.
- Directory filtering uses exact matching and excludes other directories.
- Results are newest first, with deterministic ordering for tied timestamps.
- Entries contain usable IDs, titles, absolute paths, and correctly formatted timestamps.
- Relative request paths and supplied cursors produce invalid-params errors.
- Legacy entries with nonabsolute working directories are skipped.
- Storage errors are reported rather than converted to empty results.
- Listing does not replace an active session or require a claim on sessions held by another process.
- A session ID returned by listing can be passed to the existing load flow when it is not claimed elsewhere.

Do not duplicate storage scanner/cache tests that already exist. Test the ACP contract and conversion boundaries.

### 4. Document and validate client behavior

Read `site/docs/AGENTS.md` before updating the existing ACP documentation at `site/docs/content/acp/_index.md`.

Document global versus directory-filtered discovery, exact path matching, the absence of pagination, and the distinction between discovering a session and successfully claiming it for loading.

Run scoped checks first:

- `cargo check -p maki-acp --tests`
- `cargo clippy -p maki-acp --tests -- -D warnings`
- `cargo nextest run -p maki-acp`

Use repository-wide checks as appropriate after scoped validation.

Perform an agent-shell smoke test with the local fork:

1. Start Maki through ACP and verify the list capability is recognized.
2. Exercise the session picker with multiple saved sessions in the selected project.
3. Select a session and verify history replay through `session/load`.
4. Confirm the empty-history case is usable.
5. Confirm loading a session held by another process reports the existing busy error without treating discovery itself as a failure.

No Maki-specific agent-shell picker should be required: the fork already supports capability-driven session listing and loading.

## Non-goals

- Pagination, continuation cursors, or snapshots of changing history.
- Changes to storage layout or existing CLI/TUI listing semantics.
- Restoring the prior model or Build/Plan mode differently.
- Session deletion, forking, or additional resume methods.
- Multiple active sessions per ACP server process.
- Changes to authentication, folder trust, or tool permissions.

## Acceptance criteria

An ACP client can discover saved Maki sessions, display their metadata, and load a selected session without already knowing its ID. Discovery uses existing cached storage summaries, returns no pagination cursor, and does not alter the active session or bypass session ownership checks during loading.
