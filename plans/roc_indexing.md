# Roc grammar and source indexing

## Goal

Compile the grammar maintained at `~/Projects/tree-sitter-roc` into Maki and support `.roc` files in the `index` tool. Produce compact, accurate outlines of headers, imports, types, functions, constants, associated items, and tests, with correct source ranges.

This plan adds a built-in language, not runtime grammar loading. Syntax highlighting, compiler integration, execution of Roc projects, and general-purpose grammar installation are out of scope.

## Scope

- Grammar fixes in `~/Projects/tree-sitter-roc` are in scope for this work.
- When indexing exposes a grammar defect, fix it in the grammar repository with a corpus test. Then tag a new fork release and bump the Maki pin.
- Pushing commits and tags to the fork requires the user's authorization for each push.

## Source and existing integration

- The grammar source is the fork `https://github.com/Giesch/tree-sitter-roc`. Upstream is `https://github.com/faldor20/tree-sitter-roc`. Maki does not use upstream or crates.io releases.
- The pin policy is the latest tagged release on the fork. Fork tags use the format `YYYY-MM-DD.NN`.
- The current pin is tag `2026-10-23.03` at commit `b9cddc3b026ac678aedec71afa5de3d09583051e`.
- Its `Cargo.toml` declares `tree-sitter-roc` version `1.0.0`. `bindings/rust/lib.rs` exports `LANGUAGE: LanguageFn` and `NODE_TYPES`; `bindings/rust/build.rs` compiles checked-in parser/scanner C sources. Generation should not be required during a Maki build.
- The generated parser uses ABI 15. The grammar's development dependency is tree-sitter `0.25.10`, while Maki uses `0.27`; test compatibility against Maki's actual runtime rather than inferring it from version numbers.
- Maki's grammar dependencies live in root `Cargo.toml` and `maki-lua/Cargo.toml`. `maki-lua/src/language.rs` owns language names, extensions, and parser conversion.
- `plugins/index/indexer.lua` owns extension routing, shared extraction helpers, rendering, and lazy language loading. `plugins/index/lang/gleam.lua` is a useful module-factory example, but Roc needs its own AST handling.
- Lua language specs must be explicitly required from `plugins/index/tests/spec.lua`. They run through the real Rust `PluginHost`, not a standalone Lua interpreter.

## Implementation steps

### 1. Pin and register the grammar

- [ ] Before pinning, confirm that `git ls-remote --tags https://github.com/Giesch/tree-sitter-roc` lists the tag. If a newer tag exists when the work starts, use the newer tag and update the current pin in this plan.
- [ ] Pin the tag in root `Cargo.toml`: `tree-sitter-roc = { git = "https://github.com/Giesch/tree-sitter-roc", tag = "2026-10-23.03" }`. Use the HTTPS URL, not the SSH remote. Committed builds must not depend on the user's home directory or a moving branch.
- [ ] Inherit the dependency with `workspace = true` in `maki-lua/Cargo.toml` and update `Cargo.lock`.
- [ ] Add `Language::Roc`, `from_name("roc")`, `from_extension("roc")`, and `tree_sitter_roc::LANGUAGE.into()` in `maki-lua/src/language.rs`.
- [ ] Add routing and clean-parse Rust tests with representative modern Roc input. Check both grammar loading and absence of error/missing nodes.
- [ ] Add the `flake.nix` `gitDepHashes` entry with the key `git+https://github.com/Giesch/tree-sitter-roc?tag=2026-10-23.03#b9cddc3b026ac678aedec71afa5de3d09583051e`, using the existing refresh procedure. Verify a clean build without the local grammar checkout, Node, or the tree-sitter generator.
- [ ] To bump the pin, change the tag, update `Cargo.lock`, replace the `gitDepHashes` entry, and update the current pin in this plan.

### 2. Define and implement Roc outlines

- [ ] Add `roc = "roc"` to the indexer's extension map and implement `plugins/index/lang/roc.lua` as a factory receiving shared utilities `U`.
- [ ] Use a scope-aware extraction pass if necessary to pair sibling annotations and definitions. Reuse shared entries, sections, import rendering, truncation, and metadata rather than creating a separate output format.
- [ ] Keep extraction linear in source/AST size: collect names and annotations once per scope rather than repeatedly scanning siblings.

Extraction contract:

| Construct | Intended behavior |
| --- | --- |
| Module/app/package/platform headers | Summarize the header forms supported by the pinned grammar, including relevant exposed names; do not dump entire configuration bodies. |
| Module and file imports | Preserve package prefixes, relative paths, aliases, and exposed names. Handle `import_expr` and `import_file_expr` separately. |
| Signatures | `annotation_type_def` is a sibling of its definition. Match by name within the same declaration scope, allowing intervening comments. Emit one combined entry, preserve standalone signatures, and never pair across scopes. |
| Functions | A `value_declaration` whose body is `anon_fun_expr` is a function, not a special function-declaration node. Prefer its explicit signature; otherwise show parameters without the implementation body. Recognize function signatures on non-lambda bindings without pretending to infer arbitrary expression types. |
| Constants and patterns | Index named non-function bindings. For destructuring, collect actual bound identifiers or render a compact pattern; never mistake constructor names, wildcards, or record labels for declarations. Fix the chosen policy in tests. |
| Types | Handle `alias_type_def` (`:`), `opaque_type_def` (`::`), and `nominal_type_def` (`:=`), preserving parameters and distinctions. Use grammar fields/node kinds; check which kinds expose a `body` field in the pinned grammar. Bound large record/tag-union output. |
| Associated items | Descend into `nominal_methods` deliberately, keeping methods and nested types attached to their owner. An `inferred_associated_annotation` such as `is_eq : _` is not automatically a derived method: check for a same-named definition in that scope. |
| Local declarations | Do not recursively promote declarations inside function bodies, blocks, lambdas, or branches into top-level entries. |
| Documentation and tests | Attach appropriate preceding documentation without leaking across unrelated declarations. Summarize `expect` declarations through the existing tests convention, not as functions or full expressions. |
| Ranges | Store ranges covering the declaration represented, including paired signatures where applicable. Keep UI metadata and displayed one-based line ranges consistent. |

Inspect the pinned AST before finalizing each rule. `queries/tags.scm` in the grammar is only a reference: it covers direct-lambda definitions and types, not a complete index.

### 3. Add focused regression coverage

Create `plugins/index/tests/lang/roc.lua` and require it from `plugins/index/tests/spec.lua`. Use the existing helpers for output, exclusions, metadata, and ranges. Assert substantive symbols and omission of bodies/locals; a nonempty output assertion alone is insufficient.

Test matrix:

- Headers and both import forms, including package-qualified names, relative filesystem paths, aliases, exposing lists, multiple imports, and long lists requiring truncation.
- Annotated/unannotated functions, effectful names ending in `!`, multiline signatures, function types, `where` constraints, standalone signatures, and comments between signature and definition. Include repeated names in different scopes and adjacent unrelated annotations.
- Alias, opaque, and nominal types; generic parameters; open records/tag unions; nested function types; long records and unions; nominal methods and nested associated types. Include `is_eq : _` with and without a same-named explicit implementation.
- Constants, mutable declarations where supported, wildcard bindings, nested tag/tuple/record destructuring, and record shorthand. Examples from the grammar include `Ok(parsed_value)`, `Ok(Some(parsed_value))`, `Pair(left, right,)`, `Ok(_)`, and `Ok({ value })` patterns.
- Locals and local annotations inside blocks/functions, including same-line blocks. Names used in calls, match branches, strings, and type references must not become declarations.
- Unicode identifiers, leading underscores/`$`, effect suffixes, Unicode before a declaration, CRLF, final newline/no final newline, documentation, ordinary comments, blank files, comment-only files, and header-only files.
- Body syntax that must not confuse declaration boundaries: `?` and spaced try handlers, pipelines, record builders, negative literals, field/tuple access, interpolation, adjacent string captures, typed multiline strings, and nominal destructuring.
- Malformed/incomplete input: unfinished header/signature/import/lambda/type, unmatched delimiters, and valid declarations before/after an error. Verify deterministic, bounded behavior and existing error/fallback semantics without fabricated entries or a crash.
- Exact ranges and metadata for multiline declarations, attached signatures, nested associated items, truncated sections, and a large generated declaration set. Test deterministic output across repeated runs.

Use the grammar corpus as the source of valid/invalid syntax, especially `test/corpus/modern_syntax.txt`, `annotation_statements.txt`, `derived_methods.txt`, `tag_destructuring.txt`, and `known_issues.txt`. Check expected trees: a file named `known_issues` is not a list of universally failing cases.

Track these explicit grammar boundaries separately:

- Empty/header-only files may fail because the root requires a module element.
- Uppercase type definitions inside block bodies are documented as unsupported.
- `Ok(value) as whole = result` has a recorded lexical regression.
- Whitespace-sensitive forms such as `Ok(value)` versus `Ok (value)`, and invalid spaced access such as `rec. field`, need distinct expectations.
- Error-free parsing is not compiler validation; permissive acceptance of fragments such as `x = 10 -3` must not establish correctness.

Do not repair grammar limitations with regex extraction or silently bless recovery trees. Minimize failures into grammar regressions, fix them in the grammar repository, tag a new fork release, update the pin, and add an indexing regression. Document a narrowly scoped limitation only when a grammar fix is not practical.

### 4. Validate against pinned real projects

Run an explicit, opt-in corpus sweep against local checkouts at recorded commits. Normal tests must remain offline and must not clone repositories. The sweep must call the actual Maki parser and indexer, without running project code, building dependencies, connecting to PostgreSQL, or invoking an LLM.

Corpus storage:

- Clone each external project into `/tmp/roc-corpus/<name>` and check out the commit under test. Cloning is a separate explicit step from the sweep.
- Existing compiler checkouts under `~/Projects` (`roc`, `roc-main`, `roc-old`) stay in place.
- Corpus sources, sweep reports, exception manifests, and expected-symbol inventories stay out of the Maki repository.
- The Maki repository stores only the tested commit of each project, in the "Tested project commits" table below.

Required projects:

1. **`agu-z/roc-pg` — `https://github.com/agu-z/roc-pg/`.** Clone into `/tmp/roc-corpus/roc-pg` and record its commit. Index every tracked `.roc` source and example. Inspect the pinned tree rather than assuming paths from another revision. Prioritize PostgreSQL client/command/result modules, protocol codecs, byte readers, and batch/query/prepared-statement examples; these exercise large signatures, nested types, effects, record builders, and large implementation bodies. Inventory file sizes and manually review the ten largest files plus representative public API files. Review their expected symbols out of repo.
2. **The Roc compiler repository at `~/Projects/roc`.** Record its remote and commit. Sweep its tracked `.roc` files, with separate cohorts for valid library/example sources and intentionally invalid compiler tests. Include `src/build/roc/Builtin.roc` and the largest valid modules found by inventory. Test fixtures intentionally rejected by the compiler are robustness cases, not a zero-parse-error gate.
3. **`roc-lang/basic-cli` — `https://github.com/roc-lang/basic-cli`.** Clone into `/tmp/roc-corpus/basic-cli` and record its commit. Sweep every tracked `.roc` file, including platform modules and examples. Review representative public APIs and application entry points for effectful functions, imports, types, and source ranges; include the largest modules in the manual inventory.
4. **`roc-lang/basic-webserver` — `https://github.com/roc-lang/basic-webserver`.** Clone into `/tmp/roc-corpus/basic-webserver` and record its commit. Sweep every tracked `.roc` file, including platform modules and examples. Review representative request/response APIs and server applications for headers, imports, types, effectful handlers, and source ranges; include the largest modules in the manual inventory.
5. **Additional syntax-generation coverage from `~/Projects/roc-old` or `~/Projects/roc-main`, if these contain a materially different corpus.** Record repository identity and commit first; select substantive library/example files rather than counting duplicated fixtures as additional coverage.

Roc syntax evolves. Classify each project's pinned sources by syntax generation before defining the support claim. Do not assume these four projects use identical syntax. All four sweeps are mandatory even if they expose unsupported syntax: classify and report those failures, and either fix support or explicitly narrow the feature claim. Do not claim complete support for a project while excluding its failing production files.

Sweep/report requirements:

- Enumerate sorted tracked `.roc` files; report totals, bytes, line counts, and any explicit exclusions. Handle tracked symlinks without following paths outside the selected checkout.
- Record Maki commit/worktree state, grammar commit, project commits, invocation, and test configuration so the result can be reproduced.
- Inspect every tree for `ERROR` and missing nodes independently of outline output. The existing indexer can return a plausible partial skeleton when parsing failed; nonempty output is not evidence of full support.
- Classify failures as grammar coverage, extraction omission/misclassification, range/rendering defect, or intentional invalid input. A recoverable parser error must not be hidden by counting the file as successfully indexed.
- For hand-reviewed API files and largest modules, maintain expected names, declaration categories, imports, and ranges out of repo, independently of the extractor. Compare required symbols and forbidden local names. Do not generate the expected inventory from the same extraction logic under test.
- Check every result for valid in-file ranges, deterministic output, bounded truncation, no duplicated signature/definition pairs, and no local-body leakage. Distinguish an intentionally empty outline from a missed declaration.
- Record parse/extraction time, output bytes versus source bytes, and slowest/largest files. Use repeated warm runs for median/p95 diagnostics; keep wall-clock thresholds out of normal CI. Add a scaled synthetic case to detect accidental quadratic signature pairing and enforce output bounds deterministically.
- Keep any exception manifest narrow and out of repo, next to the sweep report: project commit, path, reason, expected failure, and follow-up. Fail on new exceptions and unexpected successes so obsolete allowances are removed.
- Promote minimized failures and a small set of representative real-world cases into offline tests as small snippets written for Maki tests, respecting source licenses and attribution. Do not copy project files into the repository.

Extend the existing Rust/Lua spec harness with an opt-in corpus input rather than adding a new testing framework. An environment variable gives the corpus directory path. Normal test runs skip the sweep when the variable is not set.

### Tested project commits

| Project | Repository | Commit |
| --- | --- | --- |
| roc-pg | `https://github.com/agu-z/roc-pg` | |
| roc | `https://github.com/roc-lang/roc` | |
| basic-cli | `https://github.com/roc-lang/basic-cli` | |
| basic-webserver | `https://github.com/roc-lang/basic-webserver` | |

Fill each commit cell when its sweep passes.

### 5. Validate and document the supported boundary

Run cheap scoped checks first, followed by broader checks:

```sh
cargo check -p maki-lua --tests
cargo nextest run -p maki-lua --test spec index_plugin_spec
cargo nextest run -p maki-lua
just fmt-check
just check-lua
just lint
just test
```

For the Git dependency, also run `nix flake check` and `nix build`. Run the pinned-project sweep and retain its report out of repo before declaring indexing complete. For grammar changes, run that repository's guarded `npm run ci` / `just ci` workflow; do not blindly regenerate corpus expectations.

Check user-facing language lists and generated tool documentation for required updates. Read `site/docs/AGENTS.md` before changing site documentation and use `just gen-docs` / `just gen-docs-check` for generated pages. Do not advertise tree-sitter-based syntax highlighting: Maki's highlighting is a separate syntect/two-face integration.

## Acceptance criteria

- A clean checkout builds the Roc grammar from the latest fork tag at merge time, without access to `~/Projects/tree-sitter-roc`. This plan records that tag and commit. `.roc` routing and the Lua parser API work with Maki's tree-sitter runtime.
- The index tool produces compact, useful Roc outlines with correct signatures, categories, ownership, and ranges. It does not include local declarations or full implementation bodies.
- Focused offline tests cover the matrix above, including malformed input, grammar boundaries, and output truncation. Existing language specs still pass.
- A reproducible sweep covers roc-pg, the current compiler corpus, basic-cli, and basic-webserver, including manual checks of the largest and API-heavy files. This plan records the commit of each tested project. Reports stay out of repo. Production files in each claimed-supported cohort have no unexplained parse or indexing failures.
- Syntax-generation gaps and known parser recovery cases are explicit; no unsupported cohort is presented as fully supported because it yielded partial output.
- Packaging, generated-document checks where applicable, and scoped/full validation pass. No runtime downloads, absolute home-directory dependencies, new indexing framework, or unrelated highlighting changes are introduced.
