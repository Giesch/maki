use std::collections::{HashMap, HashSet};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use maki_config::{
    DefaultEffect, Effect, FILE_WRITE_TOOLS, PermissionRule, PermissionTarget, PermissionsConfig,
    ProjectConfig, ToolKey, append_permission_rule,
};
use maki_providers::{Message, Role};
use maki_storage::id::SessionRef;
use serde_json::{Value, json};
use thiserror::Error;
use tracing::{info, warn};

use crate::tools::PermissionScopes;
use crate::tools::registry::BoxFuture;
use crate::{AgentEvent, CancelToken, EventSender};

pub const DEFAULT_DENY_GUIDANCE: &str =
    "Do not retry. Try a different approach or ask the user for guidance.";

/// Tests assert on this exact prefix; a wording tweak here updates them in one place.
pub const PERMISSION_DENIED_PREFIX: &str = "Permission denied for";

/// Values for the `source` attribute on `maki.tool_decision` events.
pub const DECISION_SOURCE_RULE: &str = "rule";
pub const DECISION_SOURCE_YOLO: &str = "yolo";
pub const DECISION_SOURCE_USER_ONCE: &str = "user_once";
pub const DECISION_SOURCE_USER_SESSION: &str = "user_session";
pub const DECISION_SOURCE_USER_ALWAYS: &str = "user_always";
pub const DECISION_SOURCE_USER_ABORT: &str = "user_abort";
pub const DECISION_SOURCE_PLUGIN: &str = "plugin";

/// Selects complete, visible human authorization text without accepting summaries.
pub fn trusted_user_prompts(messages: &[Message], budget: usize) -> (bool, Vec<&str>) {
    let mut complete = messages
        .first()
        .is_some_and(|message| message.prompt_history_start);
    let mut prompts = Vec::new();
    let mut bytes = 0usize;
    for message in messages {
        let excluded = !matches!(message.role, Role::User)
            || message.is_from_host()
            || message.display_text.as_deref() == Some("");
        if excluded {
            continue;
        }
        if let Some(text) = message.human_prompt.as_deref() {
            bytes = bytes.saturating_add(text.len());
            if bytes > budget {
                return (false, Vec::new());
            }
            prompts.push(text);
        } else if message.user_text().is_some() {
            complete = false;
        }
    }

    (complete, prompts)
}

const PROMPT_POLICY_MAX_BYTES: usize = 64 * 1024;
const GUARDED_FILE_REASON: &str =
    "This file may contain credentials or private keys. Human approval is required.";
const UNKNOWN_FILE_REASON: &str =
    "The file target cannot be determined safely. Human approval is required.";
const OPAQUE_SHELL_REASON: &str =
    "Shell effects and destinations are not resolved by fixed guards. Human approval is required.";
const GUARDED_FILE_TOOLS: &[&str] = &["read", "write", "edit", "multiedit"];
const GUARDED_COMPONENTS: &[&str] = &[".ssh", ".aws", ".gnupg", ".azure", ".kube"];
const GUARDED_FILENAMES: &[&str] = &[
    ".netrc",
    ".npmrc",
    ".pypirc",
    "credentials",
    "credentials.json",
    "id_rsa",
    "id_ed25519",
];

/// Fixed guards cover dedicated file targets and conservatively escalate opaque
/// shell calls. Search, network, MCP, and other plugin tools are not covered.
pub(crate) fn fixed_guard_reason(tool: &ToolKey, input: &Value) -> Option<&'static str> {
    let ToolKey::Native(name) = tool else {
        return None;
    };
    if name.as_ref() == BASH_TOOL {
        let literal_printf = input
            .get("command")
            .and_then(Value::as_str)
            .and_then(|command| command.strip_prefix("printf '%s\\n' '"))
            .and_then(|argument| argument.strip_suffix('\''))
            .is_some_and(|argument| {
                !argument.contains('\'') && !argument.chars().any(char::is_control)
            });

        return (!(literal_printf || bounded_project_command(input)))
            .then_some(OPAQUE_SHELL_REASON);
    }

    if !GUARDED_FILE_TOOLS.contains(&name.as_ref()) {
        return None;
    }

    let path = match input
        .get("path")
        .or_else(|| input.get("file_path"))
        .and_then(Value::as_str)
    {
        Some(path) if !path.is_empty() && !path.contains('\0') => path,
        _ => return Some(UNKNOWN_FILE_REASON),
    };
    let target = Path::new(path);
    let expanded = maki_storage::paths::expand_tilde(target);
    let absolute = match std::path::absolute(expanded) {
        Ok(absolute) => absolute,
        Err(_) => return Some(UNKNOWN_FILE_REASON),
    };
    let resolved = match maki_storage::paths::incremental_canonicalize(&absolute) {
        Some(resolved) => resolved,
        None => return Some(UNKNOWN_FILE_REASON),
    };
    let guarded = [target, resolved.as_path()].iter().any(|path| {
        path.components().any(|component| {
            let Component::Normal(component) = component else {
                return false;
            };
            let component = component.to_string_lossy().to_ascii_lowercase();

            GUARDED_COMPONENTS.contains(&component.as_str())
                || GUARDED_FILENAMES.contains(&component.as_str())
                || component == ".env"
                || component.starts_with(".env.")
                || component.ends_with(".pem")
                || component.ends_with(".key")
        })
    });

    guarded.then_some(GUARDED_FILE_REASON)
}

/// Recognizes literal project commands, not their transitive effects. Build scripts,
/// dependencies, inherited environment and test code remain contextual review inputs.
fn bounded_project_command(input: &Value) -> bool {
    let Some(command) = input.get("command").and_then(Value::as_str) else {
        return false;
    };
    // This grammar has no quoting, escapes, expansions, assignments or shell operators.
    let literal = !command.is_empty()
        && command
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b" -_.,:".contains(&byte));
    if !literal {
        return false;
    }

    let mut words = command.split(' ').filter(|word| !word.is_empty());
    if words.next() != Some("cargo") {
        return false;
    }
    let Some(action @ ("build" | "check" | "test" | "clippy")) = words.next() else {
        return false;
    };
    let identifier = |word: &str| {
        !word.is_empty()
            && !word.starts_with('-')
            && word
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
    };
    let mut test_filter = false;
    while let Some(word) = words.next() {
        match word {
            "--offline"
            | "--locked"
            | "--frozen"
            | "--release"
            | "--workspace"
            | "--all-targets"
            | "--all-features"
            | "--no-default-features"
            | "--lib"
            | "--bins"
            | "--tests"
            | "--benches"
            | "--examples"
            | "--quiet"
            | "-q"
            | "--verbose"
            | "-v" => {}
            "-p" | "--package" | "--bin" | "--test" | "--bench" | "--example" => {
                if !words.next().is_some_and(identifier) {
                    return false;
                }
            }
            "--features" => {
                if !words
                    .next()
                    .is_some_and(|value| value.split(',').all(identifier))
                {
                    return false;
                }
            }
            "-j" | "--jobs" => {
                if !words
                    .next()
                    .is_some_and(|value| value.parse::<u16>().is_ok_and(|jobs| jobs > 0))
                {
                    return false;
                }
            }
            value if action == "test" && !test_filter && value.split("::").all(identifier) => {
                test_filter = true;
            }
            _ => return false,
        }
    }

    let cwd = match input.get("workdir") {
        None | Some(Value::Null) => std::env::current_dir().ok(),
        Some(Value::String(path)) if Path::new(path).is_absolute() => Some(PathBuf::from(path)),
        _ => None,
    };
    let Some(raw_cwd) = cwd.as_ref().and_then(|cwd| cwd.to_str()) else {
        return false;
    };
    let guarded_raw_cwd =
        fixed_guard_reason(&ToolKey::native("read"), &json!({"path": raw_cwd})).is_some();
    if guarded_raw_cwd {
        return false;
    }

    let Some(cwd) = cwd
        .filter(|cwd| cwd.is_dir())
        .and_then(|cwd| cwd.canonicalize().ok())
    else {
        return false;
    };
    let Some(canonical_cwd) = cwd.to_str() else {
        return false;
    };
    let target = json!({"path": canonical_cwd});
    let guarded_cwd = fixed_guard_reason(&ToolKey::native("read"), &target).is_some();

    !guarded_cwd && cwd.join("Cargo.toml").is_file()
}

const TASK_TOOL: &str = "task";
const BASH_TOOL: &str = "bash";

/// Splits the ask id from the encoded answer on the answer channel. A control
/// character cannot appear in a tool-use id, and the answer is the tail, so
/// deny guidance holding one still round-trips.
const ANSWER_ID_SEPARATOR: char = '\u{1f}';

/// Words that open a block the bash plugin keeps as one scope. Their first
/// token names no program, so wildcarding it would cover every command the
/// block can hold. See [`generalize_bash_segment`].
const SHELL_KEYWORDS: [&str; 15] = [
    "if", "then", "elif", "else", "fi", "for", "while", "until", "do", "done", "case", "esac",
    "select", "function", "time",
];

fn builtin_rules(cwd: &Path) -> Vec<PermissionRule> {
    let cwd_glob = format!(
        "{}/**",
        maki_storage::paths::canonicalize_clean(cwd).display()
    );
    let allow = |tool: &str, scope: &str| PermissionRule {
        tool: ToolKey::native(tool),
        scope: Some(scope.into()),
        effect: Effect::Allow,
    };
    let mut rules: Vec<PermissionRule> = FILE_WRITE_TOOLS
        .iter()
        .map(|tool| allow(tool, &cwd_glob))
        .collect();
    rules.push(allow(TASK_TOOL, "*"));
    rules
}

pub const BOUNDARY_UNVERIFIABLE_PREFIX: &str = "Cannot verify project boundary for";

/// Whether the builtin defaults treat `tool` specially. File write tools get
/// the cwd allow and the plan mode allow, `task` gets a blanket allow, and an
/// "allow always" for `bash` is stored under the first word of the command.
/// Rules are keyed by name alone, so a plugin taking one of these names
/// inherits all of it.
pub fn carries_builtin_defaults(tool: &str) -> bool {
    FILE_WRITE_TOOLS.contains(&tool) || matches!(tool, TASK_TOOL | BASH_TOOL)
}

#[derive(Debug)]
pub enum PermissionCheck {
    Allowed,
    /// Denied, with the reason shown to the model: which deny rule matched
    /// and where it came from, or which default answered.
    Denied(String),
    NeedsPrompt {
        tool: ToolKey,
        scopes: Vec<String>,
        force_prompt: bool,
    },
}

#[derive(Debug, Error)]
pub struct PermissionError {
    tool: String,
    scope: String,
    reason: String,
    guidance: Option<String>,
    /// Set when a plugin denied the call. Its guidance can echo the very input
    /// it judged, so the agent must not take it for the user's words.
    plugin: Option<Arc<str>>,
}

impl std::fmt::Display for PermissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} `{}` ({}): {}.",
            PERMISSION_DENIED_PREFIX, self.tool, self.scope, self.reason
        )?;
        match (&self.plugin, &self.guidance) {
            (Some(p), Some(g)) => write!(f, " Plugin `{p}` denied it: {g}"),
            (Some(p), None) => write!(f, " Plugin `{p}` denied it. {DEFAULT_DENY_GUIDANCE}"),
            (None, Some(g)) => write!(f, " User guidance: {g}"),
            (None, None) => write!(f, " {DEFAULT_DENY_GUIDANCE}"),
        }
    }
}

impl PermissionError {
    fn denied(
        tool: &str,
        scope: &str,
        reason: String,
        guidance: Option<String>,
        plugin: Option<Arc<str>>,
    ) -> Self {
        Self {
            tool: tool.to_string(),
            scope: scope.to_string(),
            reason,
            guidance,
            plugin,
        }
    }
}

/// Where a matched rule came from, named in the denial reason so the model
/// can tell a session grant's counterpart from a persisted config rule.
const ORIGIN_SESSION: &str = "session rules";
const ORIGIN_CONFIG: &str = "the permissions config";
const ORIGIN_BUILTIN: &str = "the built-in defaults";
const ORIGIN_PLUGIN: &str = "a Lua plugin";

const USER_REJECTED_REASON: &str = "rejected by the user";
const PROMPT_UNANSWERED_REASON: &str = "permission prompt cancelled, unanswered";
const UNATTENDED_REASON: &str =
    "no one can answer a permission prompt in this session, so this call needs an allow rule";
const PLUGIN_DENIED_REASON: &str = "denied by a plugin answering the prompt";

fn deny_rule_reason(origin: &str, rule: &PermissionRule) -> String {
    match &rule.scope {
        Some(scope) => format!("deny rule `{scope}` for `{}` in {origin}", rule.tool),
        None => format!("blanket deny rule for `{}` in {origin}", rule.tool),
    }
}

/// How squarely an approval names the tool being checked. Every source of
/// approval has to say which one it is, so the question cannot be skipped by a
/// source added later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Approval {
    /// A rule naming this tool. The user answered about this tool.
    ForThisTool,
    /// Yolo, a default, a `*` rule, a whole-server rule. It covers this tool
    /// along with others and says nothing about this one in particular.
    Standing,
}

/// Whether an approval counts for the tool at hand. An MCP tool is opaque, so
/// nothing here tells a repo search from a commit, and plan mode only stays
/// read-only while a standing yes never speaks for one. Native tools are known
/// quantities and keep every approval they had.
#[derive(Clone, Copy)]
struct ApprovalGate {
    opaque_under_plan_mode: bool,
}

impl ApprovalGate {
    fn new(tool: &ToolKey, plan_path: Option<&Path>) -> Self {
        Self {
            opaque_under_plan_mode: plan_path.is_some() && tool.is_mcp(),
        }
    }

    fn accepts(self, approval: Approval) -> bool {
        !self.opaque_under_plan_mode || approval == Approval::ForThisTool
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermissionAnswer {
    AllowOnce,
    AllowSession,
    AllowAlwaysProject,
    AllowAlwaysGlobal,
    Deny,
    DenyWithGuidance(String),
    DenyAlwaysProject,
    DenyAlwaysGlobal,
}

impl PermissionAnswer {
    pub fn decision_source(&self) -> &'static str {
        match self {
            Self::AllowOnce | Self::Deny | Self::DenyWithGuidance(_) => DECISION_SOURCE_USER_ONCE,
            Self::AllowSession => DECISION_SOURCE_USER_SESSION,
            Self::AllowAlwaysProject
            | Self::AllowAlwaysGlobal
            | Self::DenyAlwaysProject
            | Self::DenyAlwaysGlobal => DECISION_SOURCE_USER_ALWAYS,
        }
    }

    pub fn is_allow(&self) -> bool {
        matches!(
            self,
            Self::AllowOnce
                | Self::AllowSession
                | Self::AllowAlwaysProject
                | Self::AllowAlwaysGlobal
        )
    }

    pub fn encode(&self) -> String {
        match self {
            Self::AllowOnce => "allow".to_string(),
            Self::AllowSession => "allow_session".to_string(),
            Self::AllowAlwaysProject => "allow_always_project".to_string(),
            Self::AllowAlwaysGlobal => "allow_always_global".to_string(),
            Self::Deny => "deny".to_string(),
            Self::DenyWithGuidance(g) => format!("deny:{g}"),
            Self::DenyAlwaysProject => "deny_always_project".to_string(),
            Self::DenyAlwaysGlobal => "deny_always_global".to_string(),
        }
    }

    pub fn decode(s: &str) -> Option<Self> {
        match s {
            "allow" => Some(Self::AllowOnce),
            "allow_session" => Some(Self::AllowSession),
            "allow_always_project" => Some(Self::AllowAlwaysProject),
            "allow_always_global" => Some(Self::AllowAlwaysGlobal),
            "deny" => Some(Self::Deny),
            "deny_always_project" => Some(Self::DenyAlwaysProject),
            "deny_always_global" => Some(Self::DenyAlwaysGlobal),
            _ if s.starts_with("deny:") => {
                let guidance = s.strip_prefix("deny:").unwrap();
                if guidance.is_empty() {
                    Some(Self::Deny)
                } else {
                    Some(Self::DenyWithGuidance(guidance.to_string()))
                }
            }
            _ => None,
        }
    }

    pub fn guidance(&self) -> Option<&str> {
        match self {
            Self::DenyWithGuidance(g) => Some(g),
            _ => None,
        }
    }
}

/// An answer together with the id of the ask it answers.
///
/// The name is what makes a late answer harmless. The answer channel is a
/// queue with no receiver parked between turns, so an answer to a cancelled
/// turn's ask can sit there until the next turn's first permission wait pops
/// it. Untagged, that stale answer is applied to a different tool and scope,
/// and an `allow_always_*` then installs a rule for something the user never
/// saw. Tagged, the waiter can tell it apart and drop it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaggedAnswer {
    pub request_id: String,
    pub answer: PermissionAnswer,
}

impl TaggedAnswer {
    pub fn new(request_id: impl Into<String>, answer: PermissionAnswer) -> Self {
        Self {
            request_id: request_id.into(),
            answer,
        }
    }

    pub fn encode(&self) -> String {
        format!(
            "{}{ANSWER_ID_SEPARATOR}{}",
            self.request_id,
            self.answer.encode()
        )
    }

    pub fn decode(raw: &str) -> Option<Self> {
        let (request_id, answer) = raw.split_once(ANSWER_ID_SEPARATOR)?;
        Some(Self::new(request_id, PermissionAnswer::decode(answer)?))
    }
}

/// A plugin answering the prompt can only allow or deny this one call. The
/// prompt's own answers save rules, and allowing `git status` for the session
/// leaves a `git *` rule behind. A plugin giving that answer would let through
/// a later `git push --force` it never got to see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LayerVerdict {
    ClassifierAllow {
        policy_version: String,
        grant: bool,
        reuse: bool,
        denial_limit: usize,
    },
    ClassifierDeny {
        guidance: Option<String>,
        denial_limit: usize,
    },
    Allow,
    Deny {
        guidance: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayerAnswer {
    pub plugin: Arc<str>,
    pub verdict: LayerVerdict,
}

/// The plugins sitting in front of the permission prompt. `None` leaves the
/// call to the prompt.
pub trait PromptLayers: Sync {
    fn answer<'a>(&'a self, scopes: &'a [String]) -> BoxFuture<'a, Option<LayerAnswer>>;

    fn exact_binding(&self) -> Option<Value> {
        None
    }

    fn requires_human(&self) -> bool {
        false
    }

    fn answer_with_metadata<'a>(
        &'a self,
        scopes: &'a [String],
        _metadata: &'a Value,
    ) -> BoxFuture<'a, Option<LayerAnswer>> {
        self.answer(scopes)
    }
}

/// Permission rules declared by Lua plugins via
/// `maki.api.register_permission_rule`, keyed by plugin name. Shared between
/// the Lua runtime (writer, on plugin load/unload) and every
/// [`PermissionManager`] (reader).
#[derive(Default)]
pub struct PluginRuleStore(Mutex<HashMap<Arc<str>, Vec<PermissionRule>>>, AtomicU64);

impl PluginRuleStore {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<Arc<str>, Vec<PermissionRule>>> {
        self.0.lock().unwrap_or_else(|e| {
            warn!("plugin rule mutex was poisoned, recovering");
            e.into_inner()
        })
    }

    /// An empty `rules` removes the entry, so a reload that registers
    /// nothing clears the stale rules.
    pub fn replace(&self, plugin: &str, rules: Vec<PermissionRule>) {
        self.1.fetch_add(1, Ordering::SeqCst);
        let mut map = self.lock();
        if rules.is_empty() {
            map.remove(plugin);
        } else {
            map.insert(Arc::from(plugin), rules);
        }
    }

    pub fn remove(&self, plugin: &str) {
        self.1.fetch_add(1, Ordering::SeqCst);
        self.lock().remove(plugin);
    }

    pub fn snapshot(&self) -> Vec<PermissionRule> {
        self.lock().values().flatten().cloned().collect()
    }
}

const CLASSIFIER_GRANT_CAP: usize = 64;
const CLASSIFIER_GRANT_TTL: Duration = Duration::from_secs(300);
const DEFAULT_CLASSIFIER_DENIAL_LIMIT: usize = 3;

#[derive(Default)]
struct ClassifierState {
    denials: usize,
    grants: Vec<(Value, Instant)>,
}

pub struct PermissionManager {
    policy_generation: AtomicU64,
    classifier: Mutex<ClassifierState>,
    classifier_denial_limit: Mutex<usize>,
    session_rules: Mutex<Vec<PermissionRule>>,
    config_rules: Vec<PermissionRule>,
    builtin_rules: Vec<PermissionRule>,
    yolo: AtomicBool,
    /// Whether the user set yolo for this session themselves, which is what
    /// makes it worth persisting.
    yolo_explicit: AtomicBool,
    /// What `--yolo` / `always_yolo` seeded `yolo` with, so a session with no
    /// stored intent falls back to the flag instead of to off.
    seed_yolo: bool,
    default: DefaultEffect,
    tool_defaults: HashMap<ToolKey, DefaultEffect>,
    cwd: PathBuf,
    project_config: ProjectConfig,
    plugin_rules: Arc<PluginRuleStore>,
}

impl PermissionManager {
    pub fn set_classifier_denial_limit(&self, limit: usize) {
        *self
            .classifier_denial_limit
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = limit.clamp(1, 100);
    }

    /// Outcomes are linearized by this mutex in host-observed completion order.
    pub fn successful_tool_completion(&self) {
        self.reset_classifier_denials();
    }

    fn reset_classifier_denials(&self) {
        self.classifier
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .denials = 0;
    }

    #[cfg(test)]
    pub(crate) fn classifier_denials_for_test(&self, count: Option<usize>) -> usize {
        let mut state = self.classifier.lock().unwrap();
        if let Some(count) = count {
            state.denials = count;
        }

        state.denials
    }

    fn classifier_key(
        &self,
        tool: &ToolKey,
        scopes: &PermissionScopes,
        plan_path: Option<&Path>,
        layers: &dyn PromptLayers,
    ) -> Option<Value> {
        let binding = layers.exact_binding()?;
        let metadata = self.prompt_metadata(tool, scopes);
        if metadata["policy"]["complete"] != true {
            return None;
        }

        let key = json!({"binding": binding, "metadata": metadata, "plan_path": plan_path, "plugin_generation": self.plugin_rules.1.load(Ordering::SeqCst), "policy_generation": self.policy_generation.load(Ordering::SeqCst)});
        let bounded = key.to_string().len() <= PROMPT_POLICY_MAX_BYTES;

        bounded.then_some(key)
    }

    pub fn new(
        config: PermissionsConfig,
        cwd: PathBuf,
        project_config: ProjectConfig,
        plugin_rules: Arc<PluginRuleStore>,
    ) -> Self {
        let config_rules = config.rules;
        let builtin_rules = builtin_rules(&cwd);

        // Warn if wildcard deny is present — it blocks ALL tools including builtins.
        let has_wildcard_deny = config_rules
            .iter()
            .any(|r| matches!(r.tool, ToolKey::Wildcard) && r.effect == Effect::Deny);
        if has_wildcard_deny {
            warn!(
                "wildcard deny detected — this blocks ALL tools including \
                 builtins (write/edit/multiedit/task). Use per-tool rules \
                 instead if you want selective access."
            );
        }
        // Warn if wildcard allow is present — it permits ALL tools including write/edit/task.
        let has_wildcard_allow = config_rules
            .iter()
            .any(|r| matches!(r.tool, ToolKey::Wildcard) && r.effect == Effect::Allow);
        if has_wildcard_allow {
            warn!(
                "wildcard allow detected — this permits ALL tools including \
                 write/edit/multiedit/task. Use per-tool rules \
                 instead if you want selective access."
            );
        }

        Self {
            policy_generation: AtomicU64::new(0),
            classifier: Mutex::default(),
            classifier_denial_limit: Mutex::new(DEFAULT_CLASSIFIER_DENIAL_LIMIT),
            builtin_rules,
            session_rules: Mutex::new(Vec::new()),
            config_rules,
            yolo: AtomicBool::new(config.yolo),
            yolo_explicit: AtomicBool::new(false),
            seed_yolo: config.yolo,
            default: config.default,
            tool_defaults: config.tool_defaults,
            cwd,
            project_config,
            plugin_rules,
        }
    }

    /// Fresh manager for a new session runtime: shares config and builtin
    /// rules plus the current yolo state, but owns empty session rules so
    /// restoring one session never clobbers another's grants.
    pub fn fork(&self) -> Self {
        Self {
            policy_generation: AtomicU64::new(0),
            classifier: Mutex::default(),
            classifier_denial_limit: Mutex::new(
                *self
                    .classifier_denial_limit
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()),
            ),
            session_rules: Mutex::new(Vec::new()),
            config_rules: self.config_rules.clone(),
            builtin_rules: self.builtin_rules.clone(),
            yolo: AtomicBool::new(self.is_yolo()),
            yolo_explicit: AtomicBool::new(self.yolo_explicit.load(Ordering::Relaxed)),
            seed_yolo: self.seed_yolo,
            default: self.default,
            tool_defaults: self.tool_defaults.clone(),
            cwd: self.cwd.clone(),
            project_config: self.project_config.clone(),
            plugin_rules: Arc::clone(&self.plugin_rules),
        }
    }

    fn session_rules(&self) -> std::sync::MutexGuard<'_, Vec<PermissionRule>> {
        self.session_rules.lock().unwrap_or_else(|e| {
            warn!("permission mutex was poisoned, recovering");
            e.into_inner()
        })
    }

    /// The order of the checks below is the policy itself, not an accident of
    /// how it was written: denies first, then yolo, then explicit allows, the
    /// plan file write, and last the defaults. Moving one moves the rules.
    /// Every approval among them goes through [`ApprovalGate`], which is what
    /// keeps plan mode's hold from depending on which one happens to run first.
    fn check_inner(
        &self,
        tool: &ToolKey,
        scopes: &[&str],
        force_prompt: bool,
        plan_path: Option<&Path>,
    ) -> PermissionCheck {
        let session = self.session_rules();
        let plugin = self.plugin_rules.snapshot();

        let gate = ApprovalGate::new(tool, plan_path);

        // Any matching deny wins, however broadly it was aimed. Only approvals
        // are ranked by how squarely they name the tool, and only plan mode
        // reads that rank.
        let mut unclaimed_scopes: Vec<&str> = if force_prompt {
            Vec::new()
        } else {
            Vec::with_capacity(scopes.len())
        };

        for scope in scopes {
            let mut has_allow = false;
            for (origin, r) in session
                .iter()
                .map(|r| (ORIGIN_SESSION, r))
                .chain(self.config_rules.iter().map(|r| (ORIGIN_CONFIG, r)))
                .chain(self.builtin_rules.iter().map(|r| (ORIGIN_BUILTIN, r)))
                .chain(plugin.iter().map(|r| (ORIGIN_PLUGIN, r)))
            {
                let Some(approval) = rule_reach(&r.tool, tool) else {
                    continue;
                };
                if !rule_matches_scope(r, scope) {
                    continue;
                }
                match r.effect {
                    Effect::Deny => {
                        info!(tool = %tool, scope = %scope, rule = ?r, "permission denied");
                        return PermissionCheck::Denied(deny_rule_reason(origin, r));
                    }
                    Effect::Allow => has_allow |= gate.accepts(approval),
                }
            }

            if has_allow {
                // allow wins for this scope (no deny matched)
            } else if !force_prompt {
                unclaimed_scopes.push(scope);
            }
            // force_prompt: all scopes will be prompted anyway
        }

        if self.yolo.load(Ordering::Relaxed) && gate.accepts(Approval::Standing) {
            return PermissionCheck::Allowed;
        }

        let pending: Vec<&str> = if force_prompt {
            scopes.to_vec()
        } else {
            unclaimed_scopes
        };

        if pending.is_empty() {
            return PermissionCheck::Allowed;
        }

        // Plan file auto-allow: fires AFTER deny rules have been evaluated.
        // Only triggers if ALL pending scopes match the plan file path.
        // A single non-plan scope means we must prompt for the rest.
        // Compared the way the write lands: `link/../plan.md` is the plan
        // file lexically but somewhere else once `link` is followed.
        if !force_prompt && !pending.is_empty() {
            let is_plan_write = plan_path.is_some_and(|pp| {
                matches!(tool, ToolKey::Native(name) if FILE_WRITE_TOOLS.contains(&name.as_ref()))
                    && {
                        let plan = normalize_scope_prefix(pp);
                        pending.iter().all(|s| normalize_scope_prefix(s) == plan)
                    }
            });
            if is_plan_write {
                return PermissionCheck::Allowed;
            }
        }

        let tool_default = self
            .tool_defaults
            .get(tool)
            .or_else(|| {
                // McpTool falls back to McpServer-level default (Arc clone, ~2ns)
                let server = match tool {
                    ToolKey::McpTool { server, .. } => server,
                    _ => return None,
                };
                self.tool_defaults.get(&ToolKey::McpServer {
                    server: server.clone(),
                })
            })
            .copied();
        let eff = tool_default.unwrap_or(self.default);
        match eff {
            DefaultEffect::Deny => {
                info!(tool = %tool, "denied by default");
                PermissionCheck::Denied(match tool_default {
                    Some(_) => format!("deny default for `{tool}`"),
                    None => "deny default from permissions config".to_string(),
                })
            }
            DefaultEffect::Allow if gate.accepts(Approval::Standing) => PermissionCheck::Allowed,
            DefaultEffect::Allow | DefaultEffect::Prompt => PermissionCheck::NeedsPrompt {
                tool: tool.clone(),
                scopes: pending.into_iter().map(|s| s.to_string()).collect(),
                force_prompt,
            },
        }
    }

    pub fn check(&self, tool: &ToolKey, scope: &str, plan_path: Option<&Path>) -> PermissionCheck {
        self.check_inner(tool, &[scope], false, plan_path)
    }

    pub fn check_multi(
        &self,
        tool: &ToolKey,
        scopes: &[&str],
        force_prompt: bool,
        plan_path: Option<&Path>,
    ) -> PermissionCheck {
        self.check_inner(tool, scopes, force_prompt, plan_path)
    }

    fn invalidate_classifier_grants(&self) {
        self.policy_generation.fetch_add(1, Ordering::SeqCst);
        self.classifier
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .grants
            .clear();
    }

    pub fn add_session_rule(&self, rule: PermissionRule) {
        self.invalidate_classifier_grants();
        let mut rules = self.session_rules();
        let exists = rules
            .iter()
            .any(|r| r.tool == rule.tool && r.scope == rule.scope && r.effect == rule.effect);
        if !exists {
            rules.push(rule);
        }
    }

    /// The explicit toggle, so it also claims the session's intent: `/yolo` off
    /// under `--yolo` genuinely turns the session off and is remembered.
    pub fn toggle_yolo(&self) -> bool {
        self.invalidate_classifier_grants();
        let enabled = !self.yolo.fetch_xor(true, Ordering::Relaxed);
        self.yolo_explicit.store(true, Ordering::Relaxed);
        enabled
    }

    /// Replaces whatever this session was running with: `Some` is the user's
    /// stored intent, `None` means they never expressed one and the seed
    /// applies again.
    pub fn set_session_yolo(&self, stored: Option<bool>) {
        self.invalidate_classifier_grants();
        self.yolo
            .store(stored.unwrap_or(self.seed_yolo), Ordering::Relaxed);
        self.yolo_explicit
            .store(stored.is_some(), Ordering::Relaxed);
    }

    pub fn is_yolo(&self) -> bool {
        self.yolo.load(Ordering::Relaxed)
    }

    /// What the session may persist. A one-shot `--yolo` is a property of the
    /// invocation, so on its own it stores nothing.
    pub fn persisted_yolo(&self) -> Option<bool> {
        self.yolo_explicit
            .load(Ordering::Relaxed)
            .then(|| self.is_yolo())
    }

    /// Outside-cwd paths are not blocked here. They flow through the normal
    /// permission prompt (which uses the same canonicalization via
    /// [`scope_matches`]). Only unresolvable boundaries are hard-blocked.
    pub fn boundary_block_reason(&self, path: &Path) -> Option<String> {
        match physical_boundary_check(&self.cwd, path) {
            Some(_) => None,
            None => Some(format!(
                "{BOUNDARY_UNVERIFIABLE_PREFIX} {} \
                 (project root could not be resolved)",
                path.display()
            )),
        }
    }

    pub fn session_rules_snapshot(&self) -> Vec<PermissionRule> {
        self.session_rules().clone()
    }

    pub fn load_session_rules(&self, rules: Vec<PermissionRule>) {
        self.invalidate_classifier_grants();
        *self.classifier.lock().unwrap_or_else(|e| e.into_inner()) = ClassifierState::default();
        *self.session_rules() = rules;
    }

    pub fn project_is_trusted(&self) -> bool {
        self.project_config.is_trusted()
    }

    /// Where an always-answer gets written, or `None` when it only holds for
    /// this session. An untrusted folder gets nothing, for a different reason
    /// on each side. An allow saved there is stripped on the next start, so it
    /// would only look forgotten. A deny would survive, because an untrusted
    /// project still contributes its deny scopes, but saving it means Maki
    /// writing `.maki/permissions.toml` into a checkout the user declined to
    /// trust, and the next start would then ask them about a gated file Maki
    /// created itself. The durable deny is the global one, which lands in the
    /// user's own config and no repository can touch.
    fn persist_target(&self, answer: &PermissionAnswer) -> Option<PermissionTarget> {
        match answer {
            PermissionAnswer::AllowAlwaysProject | PermissionAnswer::DenyAlwaysProject => self
                .project_config
                .is_trusted()
                .then(|| PermissionTarget::Project(self.project_config.clone())),
            _ => Some(PermissionTarget::Global),
        }
    }

    pub fn apply_decision(&self, tool: &ToolKey, scopes: &[String], answer: &PermissionAnswer) {
        let resolved = if answer.is_allow() || tool.is_mcp() {
            // MCP scopes are always wildcarded — both allow and deny generalize to "*".
            // This makes session and persisted rules consistent: a deny on an MCP tool
            // blocks the tool entirely, not just the specific input that triggered it.
            generalized_scopes(tool, scopes)
        } else {
            scopes.to_vec()
        };

        match answer {
            PermissionAnswer::AllowOnce
            | PermissionAnswer::Deny
            | PermissionAnswer::DenyWithGuidance(_) => {}
            PermissionAnswer::AllowSession => {
                for s in &resolved {
                    self.add_session_rule(PermissionRule {
                        tool: tool.clone(),
                        scope: Some(s.clone()),
                        effect: Effect::Allow,
                    });
                }
            }
            PermissionAnswer::AllowAlwaysProject
            | PermissionAnswer::AllowAlwaysGlobal
            | PermissionAnswer::DenyAlwaysProject
            | PermissionAnswer::DenyAlwaysGlobal => {
                let effect = if answer.is_allow() {
                    Effect::Allow
                } else {
                    Effect::Deny
                };
                let target = self.persist_target(answer);
                if target.is_none() {
                    info!(
                        tool = %tool,
                        "project answer stays in this session because the folder is not trusted, the global answer is the one that lasts"
                    );
                }
                for s in &resolved {
                    self.add_session_rule(PermissionRule {
                        tool: tool.clone(),
                        scope: Some(s.clone()),
                        effect,
                    });
                    if let Some(target) = &target
                        && let Err(e) = append_permission_rule(tool, Some(s), effect, target)
                    {
                        tracing::warn!(error = %e, "failed to persist permission rule");
                    }
                }
            }
        }
    }

    /// For a call a plugin escalated. Allow rules, defaults and yolo all turn
    /// into a question for the user. Only a deny still answers on its own, so
    /// escalating can make a call harder to run but never easier.
    fn check_escalated(
        &self,
        tool: &ToolKey,
        scopes: &[&str],
        plan_path: Option<&Path>,
    ) -> PermissionCheck {
        match self.check_inner(tool, scopes, true, plan_path) {
            PermissionCheck::Denied(reason) => PermissionCheck::Denied(reason),
            PermissionCheck::Allowed | PermissionCheck::NeedsPrompt { .. } => {
                PermissionCheck::NeedsPrompt {
                    tool: tool.clone(),
                    scopes: scopes.iter().map(|s| s.to_string()).collect(),
                    force_prompt: true,
                }
            }
        }
    }

    fn prompt_metadata(&self, tool: &ToolKey, scopes: &PermissionScopes) -> Value {
        let rule_value = |origin: &str, rule: &PermissionRule| {
            json!({
                "origin": origin,
                "tool": rule.tool.to_string(),
                "scope": rule.scope,
                "effect": match rule.effect { Effect::Allow => "allow", Effect::Deny => "deny" },
            })
        };
        let session = self.session_rules();
        let plugin = self.plugin_rules.snapshot();
        let rules: Vec<Value> = session
            .iter()
            .map(|r| rule_value(ORIGIN_SESSION, r))
            .chain(
                self.config_rules
                    .iter()
                    .map(|r| rule_value(ORIGIN_CONFIG, r)),
            )
            .chain(
                self.builtin_rules
                    .iter()
                    .map(|r| rule_value(ORIGIN_BUILTIN, r)),
            )
            .chain(plugin.iter().map(|r| rule_value(ORIGIN_PLUGIN, r)))
            .collect();
        let default_name = |effect| match effect {
            DefaultEffect::Allow => "allow",
            DefaultEffect::Deny => "deny",
            DefaultEffect::Prompt => "prompt",
        };
        let mut tool_defaults: Vec<Value> = self
            .tool_defaults
            .iter()
            .map(
                |(tool, effect)| json!({"tool": tool.to_string(), "effect": default_name(*effect)}),
            )
            .collect();
        tool_defaults.sort_by_key(|value| value["tool"].as_str().unwrap_or_default().to_owned());
        let mut policy = json!({
            "complete": true,
            "rules": rules,
            "default": default_name(self.default),
            "tool_defaults": tool_defaults,
            "yolo": self.is_yolo(),
        });
        let policy_too_large = policy.to_string().len() > PROMPT_POLICY_MAX_BYTES;
        if policy_too_large {
            policy = json!({"complete": false, "reason": "policy_size_limit"});
        }
        let shell = matches!(tool, ToolKey::Native(name) if name.as_ref() == BASH_TOOL);
        let candidates: Vec<Value> = scopes
            .scopes
            .iter()
            .map(|scope| {
                json!({
                    "tool": tool.to_string(), "scope": scope, "effect": "allow",
                })
            })
            .collect();

        json!({
            "version": 1,
            "fixed_guards": {
                "file_tools": GUARDED_FILE_TOOLS,
                "file_checks": "known_secret_path_patterns_and_resolved_target",
                "shell": "bounded_literal_cargo_project_commands_or_literal_printf_otherwise_human",
                "shell_execution": "contextual_not_sandboxed_no_post_review_rtk_rewrite",
                "bypassed_classes": ["search", "network", "mcp", "other_plugins"],
                "classifier_grants": "absolute_read_with_complete_live_history_only",
            },
            "all_scopes": scopes.scopes,
            "force_prompt": scopes.force_prompt,
            "policy": policy,
            "subjects": scopes.scopes,
            "subject_kind": if shell { "shell_scope" } else { "permission_scope" },
            "subjects_resolved": false,
            "candidate_rules": candidates,
            "candidate_kind": "exact_scope",
            "limitations": if shell {
                vec!["Shell scopes are opaque permission strings, not resolved file or network targets. Exact-scope candidates use host prefix matching and are not exact-call grants."]
            } else {
                vec!["Permission scopes are tool-supplied strings, not independently resolved effects. Exact-scope candidates use host prefix matching and are not exact-call grants."]
            },
        })
    }

    /// `ask` is a plugin's reason to show this call to the user whatever the
    /// rules say. See [`Self::check_escalated`]. `layers` may answer in the
    /// user's place before the prompt opens, and the plugin that allowed the
    /// call comes back so the caller can mark it.
    ///
    /// No `user_response_rx` means nobody is there to answer, like in `maki -p`
    /// or a background session, so a prompt is denied instead of waiting forever.
    #[allow(clippy::too_many_arguments)]
    pub async fn enforce(
        &self,
        tool: &ToolKey,
        scopes: &PermissionScopes,
        session: Option<&SessionRef>,
        event_tx: &EventSender,
        user_response_rx: Option<&smol::lock::Mutex<flume::Receiver<String>>>,
        request_id: &str,
        cancel: &CancelToken,
        plan_path: Option<&Path>,
        ask: Option<&str>,
        layers: Option<&dyn PromptLayers>,
    ) -> Result<Option<Arc<str>>, PermissionError> {
        let check = |tool: &ToolKey, scopes: &[&str], force_prompt: bool| match ask {
            Some(_) => self.check_escalated(tool, scopes, plan_path),
            None => self.check_inner(tool, scopes, force_prompt, plan_path),
        };
        let scope_refs: Vec<&str> = scopes.scopes.iter().map(|s| s.as_str()).collect();
        let tool_string = tool.to_string();
        let scope_display = || scopes.scopes.join("; ");
        // Every deny is built here and every approval passes through
        // `allowed`, so reporting cannot drift from what the caller gets.
        let deny = |source: &'static str,
                    reason: String,
                    guidance: Option<String>,
                    plugin: Option<Arc<str>>| {
            maki_otel::emit::tool_decision(&tool_string, maki_otel::emit::DECISION_REJECT, source);
            PermissionError::denied(&tool_string, &scope_display(), reason, guidance, plugin)
        };
        let allowed = |source: &'static str| {
            maki_otel::emit::tool_decision(&tool_string, maki_otel::emit::DECISION_ACCEPT, source);
            Ok(None)
        };
        let by_rule = || {
            if self.yolo.load(Ordering::Relaxed) {
                DECISION_SOURCE_YOLO
            } else {
                DECISION_SOURCE_RULE
            }
        };

        let (pt, ps, force_prompt) = match check(tool, &scope_refs, scopes.force_prompt) {
            PermissionCheck::Allowed => return allowed(by_rule()),
            PermissionCheck::Denied(reason) => {
                return Err(deny(DECISION_SOURCE_RULE, reason, None, None));
            }
            PermissionCheck::NeedsPrompt {
                tool,
                scopes,
                force_prompt,
            } => (tool, scopes, force_prompt),
        };

        // Asked before the prompt lock, so a slow layer never holds up a prompt
        // the user could already answer, and before the missing channel check,
        // since a run nobody watches is where a layer helps the most.
        //
        // An escalated call skips the layers. Another plugin's `tool.*.input`
        // sent it to a human on purpose, and under yolo these are the only
        // calls that get this far. Nothing is recorded, see `LayerVerdict`.
        let mut metadata = self.prompt_metadata(tool, scopes);
        let key = layers.and_then(|layers| self.classifier_key(tool, scopes, plan_path, layers));
        let limit = *self
            .classifier_denial_limit
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let threshold_reached = {
            let mut state = self.classifier.lock().unwrap_or_else(|e| e.into_inner());
            state.grants.retain(|(stored, created)| {
                created.elapsed() < CLASSIFIER_GRANT_TTL
                    && key.as_ref().is_some_and(|key| {
                        stored["binding"]["session"] == key["binding"]["session"]
                            && stored["binding"]["authorization_revision"]
                                == key["binding"]["authorization_revision"]
                            && stored["metadata"] == key["metadata"]
                            && stored["plugin_generation"] == key["plugin_generation"]
                    })
            });
            let available = key.as_ref().and_then(|key| {
                state.grants.iter().find(|(stored, _)| {
                    let mut host = stored.clone();
                    host.as_object_mut()
                        .map(|object| object.remove("classifier_policy"));
                    &host == key
                })
            });
            metadata["classifier"] = json!({"version": 1, "denial_limit": limit, "consecutive_denials": state.denials, "exact_grant_available": available.is_some(), "grant_policy_version": available.map(|(stored, _)| &stored["classifier_policy"]), "exact_grant_supported": key.is_some()});
            state.denials >= limit
        };
        if ask.is_none()
            && !threshold_reached
            && let Some(layers) = layers
            && let Ok(Some(LayerAnswer { plugin, verdict })) = cancel
                .race(layers.answer_with_metadata(&ps, &metadata))
                .await
        {
            match verdict {
                LayerVerdict::ClassifierAllow {
                    policy_version,
                    grant,
                    reuse,
                    denial_limit,
                } => {
                    if layers.requires_human() {
                        return Err(deny(
                            DECISION_SOURCE_RULE,
                            "Fixed guard changed during review; retry for human approval."
                                .to_owned(),
                            None,
                            None,
                        ));
                    }
                    self.set_classifier_denial_limit(denial_limit);
                    if let PermissionCheck::Denied(reason) =
                        check(tool, &scope_refs, scopes.force_prompt)
                    {
                        return Err(deny(DECISION_SOURCE_RULE, reason, None, None));
                    }
                    let fresh = self.classifier_key(tool, scopes, plan_path, layers);
                    let valid = key.is_some()
                        && key == fresh
                        && !policy_version.is_empty()
                        && policy_version.len() <= 128
                        && !policy_version.chars().any(char::is_control);
                    let key = key.map(|mut key| {
                        key["classifier_policy"] = json!(policy_version);
                        key
                    });
                    let mut state = self.classifier.lock().unwrap_or_else(|e| e.into_inner());
                    let hit = valid
                        && state.grants.iter().any(|(stored, created)| {
                            created.elapsed() < CLASSIFIER_GRANT_TTL && Some(stored) == key.as_ref()
                        });
                    if !reuse || hit {
                        if grant && valid {
                            if state.grants.len() >= CLASSIFIER_GRANT_CAP {
                                state.grants.remove(0);
                            }
                            if let Some(key) = key {
                                state.grants.push((key, Instant::now()));
                            }
                        }
                        return allowed(DECISION_SOURCE_PLUGIN).map(|_| Some(plugin));
                    }
                }
                LayerVerdict::ClassifierDeny {
                    guidance,
                    denial_limit,
                } => {
                    self.set_classifier_denial_limit(denial_limit);
                    let mut state = self.classifier.lock().unwrap_or_else(|e| e.into_inner());
                    state.denials = state.denials.saturating_add(1);
                    return Err(deny(
                        DECISION_SOURCE_PLUGIN,
                        PLUGIN_DENIED_REASON.to_owned(),
                        guidance,
                        Some(plugin),
                    ));
                }
                LayerVerdict::Allow => {
                    if layers.requires_human() {
                        return Err(deny(
                            DECISION_SOURCE_RULE,
                            "Fixed guard changed during review; retry for human approval."
                                .to_owned(),
                            None,
                            None,
                        ));
                    }
                    if let PermissionCheck::Denied(reason) =
                        check(tool, &scope_refs, scopes.force_prompt)
                    {
                        return Err(deny(DECISION_SOURCE_RULE, reason, None, None));
                    }

                    return allowed(DECISION_SOURCE_PLUGIN).map(|_| Some(plugin));
                }
                LayerVerdict::Deny { guidance } => {
                    return Err(deny(
                        DECISION_SOURCE_PLUGIN,
                        PLUGIN_DENIED_REASON.to_owned(),
                        guidance,
                        Some(plugin),
                    ));
                }
            };
        }

        let Some(rx) = user_response_rx else {
            warn!(
                tool = %tool,
                scope = %scope_display(),
                session = ?session,
                request_id,
                "denied a permission prompt nobody can answer"
            );
            return Err(deny(
                DECISION_SOURCE_USER_ABORT,
                UNATTENDED_REASON.to_owned(),
                None,
                None,
            ));
        };

        let guard = rx.lock().await;
        let refs: Vec<&str> = ps.iter().map(|s| s.as_str()).collect();
        let (t2, s2) = match check(&pt, &refs, force_prompt) {
            PermissionCheck::Allowed => return allowed(by_rule()),
            PermissionCheck::Denied(reason) => {
                return Err(deny(DECISION_SOURCE_RULE, reason, None, None));
            }
            PermissionCheck::NeedsPrompt { tool, scopes, .. } => (tool, scopes),
        };

        let _ = event_tx.send(AgentEvent::PermissionRequest {
            id: request_id.to_owned(),
            tool: t2.clone(),
            scopes: s2.clone(),
            reason: ask.map(str::to_owned),
        });
        // Only the answer naming this ask may be applied. Anything else is a
        // leftover from a cancelled or reassigned ask, so it is dropped and the
        // wait continues: consuming it would approve or deny this tool on a
        // decision the user made about another one.
        let answer = loop {
            let response = cancel.race(guard.recv_async()).await;
            match response {
                Ok(Ok(raw)) => match TaggedAnswer::decode(&raw) {
                    Some(tagged) if tagged.request_id == request_id => break tagged.answer,
                    tagged => warn!(
                        tool = %tool,
                        scope = %scope_display(),
                        request_id,
                        answered = tagged.map(|t| t.request_id).unwrap_or_default(),
                        "discarding a permission answer that does not name this request"
                    ),
                },
                Ok(Err(_)) => {
                    drop(guard);
                    warn!(tool = %tool, scope = %scope_display(), "permission channel closed");
                    return Err(deny(
                        DECISION_SOURCE_USER_ABORT,
                        PROMPT_UNANSWERED_REASON.to_owned(),
                        None,
                        None,
                    ));
                }
                Err(_) => {
                    drop(guard);
                    return Err(deny(
                        DECISION_SOURCE_USER_ABORT,
                        PROMPT_UNANSWERED_REASON.to_owned(),
                        None,
                        None,
                    ));
                }
            }
        };
        drop(guard);

        self.reset_classifier_denials();
        self.apply_decision(&t2, &s2, &answer);
        let source = answer.decision_source();
        if answer.is_allow() {
            allowed(source)
        } else {
            Err(deny(
                source,
                USER_REJECTED_REASON.to_owned(),
                answer.guidance().map(String::from),
                None,
            ))
        }
    }
}

/// Whether a rule reaches this tool, and how narrowly it was aimed if it does.
/// Both questions get answered by the one match, because a rule that reaches a
/// tool without saying how squarely is what let a `*` allow walk past plan mode.
fn rule_reach(rule_key: &ToolKey, actual: &ToolKey) -> Option<Approval> {
    match (rule_key, actual) {
        (ToolKey::Wildcard, _) => Some(Approval::Standing),
        (ToolKey::McpServer { server: rs }, ToolKey::McpTool { server: as_, .. }) => {
            (rs == as_).then_some(Approval::Standing)
        }
        (ToolKey::Native(a), ToolKey::Native(b)) => (a == b).then_some(Approval::ForThisTool),
        (ToolKey::McpServer { server: rs }, ToolKey::McpServer { server: as_ }) => {
            (rs == as_).then_some(Approval::ForThisTool)
        }
        (
            ToolKey::McpTool {
                server: rs,
                tool: rt,
            },
            ToolKey::McpTool {
                server: as_,
                tool: at,
            },
        ) => (rs == as_ && rt == at).then_some(Approval::ForThisTool),
        _ => None,
    }
}

/// A deny fails closed: a pattern refused as a blanket allow also denies
/// every scope, even where [`scope_matches`] reads it as a narrower subtree.
fn rule_matches_scope(rule: &PermissionRule, scope: &str) -> bool {
    match &rule.scope {
        None => true,
        Some(pattern) => {
            (rule.effect == Effect::Deny && is_universal_scope(pattern))
                || scope_matches(pattern, scope)
        }
    }
}

/// A rule and the path it is matched against have to agree on what file they
/// name, including for a relative rule like `dist/**` written before the dir
/// exists — both are `canonical_key`'s job.
fn normalize_scope_prefix(path: impl AsRef<Path>) -> PathBuf {
    maki_storage::paths::canonical_key(path.as_ref())
}

/// Whether a pattern might cover every scope, the question behind refusing a
/// plugin allow. `*`, `**`, `/*` and `/**` do by their text. A `/**` prefix
/// counts when either reading of it is the root: the canonical one
/// (`canonical_key`: expands `~`, follows symlinks), which is how
/// [`scope_matches`] grants, or the lexical one (`normalize_path`: collapses
/// `.` and `..` textually), which catches `//**`, `/./**` and `/tmp/../**`
/// even where `/tmp` is a symlink and the canonical reading lands elsewhere.
///
/// Refusing is the safe direction, so this reads broadly on purpose. The
/// invariant is one way: a pattern [`scope_matches`] treats as matching
/// everything is always universal here, a pattern universal here need not
/// match everything there.
pub fn is_universal_scope(pattern: &str) -> bool {
    match pattern.strip_suffix("/**") {
        Some(prefix) => {
            is_root(&normalize_scope_prefix(prefix))
                || is_root(&maki_storage::paths::normalize_path(Path::new(prefix)))
        }
        None => {
            let stem = pattern.trim_end_matches('*');
            stem.len() < pattern.len() && matches!(stem, "" | "/")
        }
    }
}

fn is_root(path: &Path) -> bool {
    path.parent().is_none()
}

/// Glob matcher for permission scopes. The boundary suffixes (`/**`, `" *"`)
/// must be tried before the bare `*`, otherwise a plain prefix would swallow
/// them. `" *"` is the bash form `<command> *`: it has to match the bare
/// command too (`pwd *` covers `pwd` and `pwd -L`, but not `pwdx`).
///
/// For the `/**` path pattern, `Path::starts_with` is used to compare
/// components rather than characters, which handles both `/` and `\`
/// transparently on all platforms.
///
/// A `/**` prefix is read one way only, canonically, the way the write tools
/// follow symlinks. A lexical root like `link/../../**` is the subtree the
/// filesystem resolves it to here, never everything; [`is_universal_scope`]
/// still refuses it.
pub fn scope_matches(pattern: &str, value: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix("/**") {
        let norm_prefix = normalize_scope_prefix(prefix);
        // A root prefix covers every scope, bash commands included. Those are
        // not paths, so a plain prefix test would miss them.
        return is_root(&norm_prefix) || normalize_scope_prefix(value).starts_with(&norm_prefix);
    }
    if is_universal_scope(pattern) {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix(" *") {
        return value == prefix || value.starts_with(&format!("{prefix} "));
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return value.starts_with(prefix);
    }
    pattern == value
}

/// Check whether `child` is physically inside `parent`, following symlinks.
///
/// Uses incremental left-to-right canonicalization: each component is
/// resolved through the filesystem (including symlinks) *before* any
/// subsequent `..` component can act on it. This prevents symlink-based
/// boundary escapes where a symlink followed by `..` resolves to a
/// location outside the parent.
///
/// Returns `true` only when the resolved filesystem location of `child`
/// is under `parent`. Returns `None` if the parent itself cannot be resolved.
pub fn physical_boundary_check(parent: &Path, child: &Path) -> Option<bool> {
    let parent_canon = maki_storage::paths::incremental_canonicalize(parent)?;
    let child_canon =
        maki_storage::paths::incremental_canonicalize(child).unwrap_or_else(|| child.to_path_buf());
    Some(child_canon.starts_with(&parent_canon))
}

/// A `<cmd> *` rule is only safe when `<cmd>` names one program. The bash
/// plugin keeps block forms whole on purpose, so `for f in *.rs; do wc -l $f;
/// done` arrives as one scope and its first token is `for`; wildcarding that
/// hands out every loop the model can write. Same for a bodiless `> log`,
/// whose first token is the redirect. Those scopes stay literal: remembering
/// one exact command is worth little, but it is never a blank cheque.
fn generalize_bash_segment(segment: &str) -> String {
    let first_token = segment.split_whitespace().next().unwrap_or(segment);
    let is_command_word = !first_token.is_empty()
        && first_token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_.:/@+-".contains(c))
        && !SHELL_KEYWORDS.contains(&first_token);
    if is_command_word {
        format!("{first_token} *")
    } else {
        segment.to_string()
    }
}

pub fn generalized_scopes(tool: &ToolKey, scopes: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    scopes
        .iter()
        .map(|s| generalize_scope(tool, s))
        .filter(|g| seen.insert(g.clone()))
        .collect()
}

fn generalize_scope(tool: &ToolKey, scope: &str) -> String {
    match tool {
        ToolKey::Native(name) if name.as_ref() == BASH_TOOL => generalize_bash_segment(scope),
        ToolKey::Native(name) if FILE_WRITE_TOOLS.contains(&name.as_ref()) => {
            format!("{}/**", write_rule_dir(scope).display())
        }
        // MCP tool calls have a scope equal to the JSON-stringified input.
        // "Allow always" should whitelist the tool regardless of its arguments,
        // so generalize the scope to `*`. The rule's `tool` field still gates
        // which MCP tool it applies to, keeping distinct tools distinct.
        ToolKey::McpTool { .. } | ToolKey::McpServer { .. } => "*".to_string(),
        _ => scope.to_string(),
    }
}

/// The directory a write rule names: where the write lands, resolved the way
/// [`scope_matches`] resolves it, so the rule never holds `..` for the lexical
/// reading to collapse into something wider. The path as the model spelled it
/// is kept when its parent already names that directory, so ordinary rules
/// stay readable (`node_modules/react/**`, relative or through a symlink).
fn write_rule_dir(scope: &str) -> PathBuf {
    let landing = normalize_scope_prefix(scope);
    let landing_dir = landing.parent().unwrap_or(&landing);
    match Path::new(scope).parent() {
        Some(spelled)
            if !spelled.as_os_str().is_empty()
                && !spelled.components().any(|c| c == Component::ParentDir)
                && normalize_scope_prefix(spelled) == landing_dir =>
        {
            spelled.to_path_buf()
        }
        _ => landing_dir.to_path_buf(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    #[test_case("cargo build" => true; "build")]
    #[test_case("cargo check --offline --locked --frozen --release --workspace --all-targets --all-features --no-default-features --lib --bins --tests --benches --examples --quiet -q --verbose -v" => true; "standalone_flags")]
    #[test_case("cargo clippy -p crate_1 --package crate-2 --bin app --test integration --bench perf --example demo" => true; "selectors")]
    #[test_case("cargo test --features first,second_2,third-3" => true; "features")]
    #[test_case("cargo test -j 1 --jobs 65535" => true; "jobs_bounds")]
    #[test_case("cargo test module::case" => true; "qualified_filter")]
    #[test_case("cargo test case --lib" => true; "filter_before_flag")]
    #[test_case("cargo test -j 0" => false; "jobs_zero")]
    #[test_case("cargo test --jobs 65536" => false; "jobs_overflow")]
    #[test_case("cargo test --jobs 99999999999999999999" => false; "jobs_parse_overflow")]
    #[test_case("cargo test -j -1" => false; "jobs_negative")]
    #[test_case("cargo test -j 1.5" => false; "jobs_fraction")]
    #[test_case("cargo test -j0" => false; "attached_jobs_zero")]
    #[test_case("cargo test --jobs=1" => false; "equals_jobs")]
    #[test_case("cargo test -p" => false; "missing_package")]
    #[test_case("cargo test --package --lib" => false; "flag_as_package")]
    #[test_case("cargo test --bin" => false; "missing_bin")]
    #[test_case("cargo test --test" => false; "missing_test")]
    #[test_case("cargo test --bench" => false; "missing_bench")]
    #[test_case("cargo test --example" => false; "missing_example")]
    #[test_case("cargo test --features" => false; "missing_features")]
    #[test_case("cargo test --jobs" => false; "missing_jobs")]
    #[test_case("cargo test --features first,,second" => false; "empty_feature")]
    #[test_case("cargo test --features first," => false; "trailing_feature")]
    #[test_case("cargo test --features ,first" => false; "leading_feature")]
    #[test_case("cargo test --features first/second" => false; "dependency_feature")]
    #[test_case("cargo test --features --lib" => false; "flag_as_feature")]
    #[test_case("cargo test --features first.second" => false; "punctuated_feature")]
    #[test_case("cargo test first second" => false; "second_filter")]
    #[test_case("cargo test module::::case" => false; "empty_filter_component")]
    #[test_case("cargo test module::" => false; "trailing_filter_component")]
    #[test_case("cargo test ::case" => false; "leading_filter_component")]
    #[test_case("cargo build case" => false; "build_filter")]
    #[test_case("cargo test --bin ../app" => false; "selector_path")]
    #[test_case("cargo test --unknown" => false; "unknown_flag")]
    fn cargo_grammar_boundaries(command: &str) -> bool {
        let project = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("Cargo.toml"), "[workspace]").unwrap();

        bounded_project_command(&json!({"command": command, "workdir": project.path()}))
    }

    #[test_case("missing" => false; "missing_directory")]
    #[test_case("plain" => false; "no_manifest")]
    #[test_case(".ssh" => false; "secret_directory")]
    #[test_case("project" => true; "project_directory")]
    fn cargo_cwd_boundaries(directory: &str) -> bool {
        let root = tempfile::tempdir().unwrap();
        for name in ["plain", ".ssh", "project"] {
            let path = root.path().join(name);
            std::fs::create_dir(&path).unwrap();
            if name != "plain" {
                std::fs::write(path.join("Cargo.toml"), "[workspace]").unwrap();
            }
        }

        bounded_project_command(
            &json!({"command": "cargo test", "workdir": root.path().join(directory)}),
        )
    }

    #[test]
    fn cargo_default_cwd_matches_explicit_process_cwd() {
        let cwd = std::env::current_dir().unwrap();
        let expected = bounded_project_command(&json!({"command":"cargo test", "workdir":cwd}));
        assert!(expected, "test process starts in this Cargo project");
        assert_eq!(
            bounded_project_command(&json!({"command":"cargo test"})),
            expected
        );
        assert_eq!(
            bounded_project_command(&json!({"command":"cargo test", "workdir":null})),
            expected
        );
    }

    #[cfg(unix)]
    #[test]
    fn cargo_non_utf8_process_cwd_rejects_without_panicking() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        use std::process::Command;

        const CHILD: &str = "MAKI_TEST_NON_UTF8_CWD";
        const SENTINEL: &str = "non-UTF8 cwd rejection verified";
        if std::env::var_os(CHILD).is_some() {
            assert!(!bounded_project_command(&json!({"command":"cargo test"})));
            println!("{SENTINEL}");
            return;
        }

        let root = tempfile::tempdir().unwrap();
        let cwd = root.path().join(OsString::from_vec(vec![b'p', 0xff]));
        std::fs::create_dir(&cwd).unwrap();
        std::fs::write(cwd.join("Cargo.toml"), "[workspace]").unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "permissions::tests::cargo_non_utf8_process_cwd_rejects_without_panicking",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .current_dir(cwd)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("running 1 test"), "{stdout}");
        assert!(stdout.contains(SENTINEL), "{stdout}");
    }

    #[cfg(unix)]
    #[test]
    fn cargo_cwd_symlinks_and_non_utf8_are_guarded_without_panicking() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        for name in [
            OsString::from("project"),
            OsString::from(".ssh"),
            OsString::from_vec(vec![b'p', 0xff]),
        ] {
            let path = root.path().join(&name);
            std::fs::create_dir(&path).unwrap();
            std::fs::write(path.join("Cargo.toml"), "[workspace]").unwrap();
        }
        for (link, target, expected) in [
            ("ordinary", OsString::from("project"), true),
            ("secret", OsString::from(".ssh"), false),
            ("nonutf8", OsString::from_vec(vec![b'p', 0xff]), false),
        ] {
            let path = root.path().join(link);
            symlink(root.path().join(target), &path).unwrap();
            assert_eq!(
                bounded_project_command(&json!({"command":"cargo test", "workdir":path})),
                expected,
                "{link}"
            );
        }
    }

    const PLAN_FILE: &str = "/home/user/.local/state/maki/plans/test.md";
    const TEST_CWD: &str = "/tmp";
    const MCP_SERVER: &str = "deepwiki";
    const MCP_TOOL: &str = "deepwiki.search";
    const MCP_ARGS: &str = "{\"q\":\"maki\"}";
    const READ_TOOL: &str = "read";
    const READ_SCOPE: &str = "/home/user/project/src/main.rs";
    const TAGGED_REQUEST_ID: &str = "toolu_1";
    /// Guidance is free text and may hold the separator itself.
    const TAGGED_GUIDANCE: &str = "no\u{1f}way";

    const ALLOWED: &str = "allowed";
    const DENIED: &str = "denied";
    const PROMPTS: &str = "prompts";
    const PROJECT_DIR: &str = ".maki";
    const PROJECT_PERMISSIONS: &str = ".maki/permissions.toml";
    #[cfg(unix)]
    const OUTSIDE_WRITES: [&str; 2] = ["/etc/passwd", "~/.bashrc"];
    const OUTSIDE_SCOPES: [&str; 3] = ["/etc/passwd", "~/.bashrc", "cargo test"];

    fn outcome(check: PermissionCheck) -> &'static str {
        match check {
            PermissionCheck::Allowed => ALLOWED,
            PermissionCheck::Denied(_) => DENIED,
            PermissionCheck::NeedsPrompt { .. } => PROMPTS,
        }
    }

    fn mcp_tool_key() -> ToolKey {
        ToolKey::parse(MCP_TOOL).expect("test tool key parses")
    }

    fn native_key() -> ToolKey {
        ToolKey::Native(READ_TOOL.into())
    }

    fn mcp_server_key() -> ToolKey {
        ToolKey::McpServer {
            server: MCP_SERVER.into(),
        }
    }

    fn make_config(rules: Vec<PermissionRule>) -> PermissionsConfig {
        PermissionsConfig {
            rules,
            ..Default::default()
        }
    }

    fn allow_rule(scope: &str) -> PermissionRule {
        PermissionRule {
            tool: ToolKey::native("bash"),
            scope: Some(scope.into()),
            effect: Effect::Allow,
        }
    }

    fn deny_rule(scope: &str) -> PermissionRule {
        PermissionRule {
            tool: ToolKey::native("bash"),
            scope: Some(scope.into()),
            effect: Effect::Deny,
        }
    }

    fn mgr_with(config: PermissionsConfig, cwd: PathBuf) -> PermissionManager {
        let project_config = ProjectConfig::for_project(&cwd);
        PermissionManager::new(config, cwd, project_config, Arc::default())
    }

    fn default_mgr() -> PermissionManager {
        mgr_with(PermissionsConfig::default(), PathBuf::from("/tmp"))
    }

    #[test]
    fn unattended_denies_prompt_without_parking() {
        let (event_tx, events) = flume::unbounded();
        let err = smol::block_on(default_mgr().enforce(
            &ToolKey::native(BASH_TOOL),
            &PermissionScopes::single("cargo test".to_owned()),
            None,
            &EventSender::new(event_tx, 0),
            None,
            TAGGED_REQUEST_ID,
            &CancelToken::none(),
            None,
            None,
            None,
        ))
        .unwrap_err();

        assert_eq!(err.reason, UNATTENDED_REASON);
        assert!(events.is_empty(), "no prompt may go out");
    }

    fn plugin_edit_rule(scope: &str, effect: Effect) -> PermissionRule {
        PermissionRule {
            tool: ToolKey::native("edit"),
            scope: Some(scope.into()),
            effect,
        }
    }

    #[test_case("*", "anything" => true ; "star")]
    #[test_case("cargo *", "cargo test" => true ; "prefix")]
    #[test_case("cargo *", "git push" => false ; "prefix_no_match")]
    #[test_case("pwd *", "pwd" => true ; "space_star_matches_bare_command")]
    #[test_case("pwd *", "pwd -L" => true ; "space_star_matches_with_args")]
    #[test_case("pwd *", "pwdx" => false ; "space_star_no_partial_token")]
    #[test_case("src/**", "src/main.rs" => true ; "glob")]
    #[test_case("src/**", "src/deep/nested/file.rs" => true ; "glob_deep_nested")]
    #[test_case("src/**", "src" => true ; "glob_exact_prefix")]
    #[test_case("src/**", "srcfoo" => false ; "glob_no_bare_prefix")]
    #[test_case("src/**", "other/src/main.rs" => false ; "glob_no_inner_match")]
    fn scope_match(pattern: &str, value: &str) -> bool {
        scope_matches(pattern, value)
    }

    /// A pattern is universal only when the trailing glob is all it says.
    #[test_case("*" => true ; "star")]
    #[test_case("**" => true ; "double_star")]
    #[test_case("/*" => true ; "root_star")]
    #[test_case("/**" => true ; "root_double_star")]
    #[test_case("//**" => true ; "doubled_root_slash")]
    #[test_case("/./**" => true ; "root_dot")]
    #[test_case("/tmp/../**" => true ; "root_by_parent")]
    #[test_case("/tmp/**" => false ; "directory_subtree")]
    #[test_case("cargo *" => false ; "bash_command")]
    #[test_case("/" => false ; "root_without_glob")]
    #[test_case("" => false ; "empty")]
    fn universal_scope(pattern: &str) -> bool {
        is_universal_scope(pattern)
    }

    /// The canonical half of `prefix_is_universal`. Lexically the prefix is just
    /// a tempdir; only resolving the symlink reaches the root. A `~/../..`
    /// spelling would prove the same branch but assumes `$HOME` is set and
    /// exactly two levels deep.
    #[test]
    #[cfg(unix)]
    fn universal_scope_through_symlink_to_root() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("root");
        std::os::unix::fs::symlink("/", &link).unwrap();
        assert!(is_universal_scope(&format!("{}/**", link.display())));
        assert_universal_invariant(&format!("{}/**", link.display()));
    }

    fn matches_everything(pattern: &str) -> bool {
        OUTSIDE_SCOPES.iter().all(|s| scope_matches(pattern, s))
    }

    fn assert_universal_invariant(pattern: &str) {
        assert!(
            !matches_everything(pattern) || is_universal_scope(pattern),
            "{pattern:?} matches everything but a plugin allow for it would not be refused"
        );
    }

    #[cfg(unix)]
    fn normal_depth(path: &Path) -> usize {
        path.components()
            .filter(|c| matches!(c, Component::Normal(_)))
            .count()
    }

    /// Enough `..` after `path` to reach the root lexically, whatever the
    /// filesystem makes of them.
    #[cfg(unix)]
    fn climb_to_lexical_root(path: &Path) -> String {
        format!("{}{}", path.display(), "/..".repeat(normal_depth(path)))
    }

    #[test_case("*" ; "star")]
    #[test_case("**" ; "double_star")]
    #[test_case("/*" ; "root_star")]
    #[test_case("/**" ; "root_double_star")]
    #[test_case("//**" ; "doubled_root_slash")]
    #[test_case("/./**" ; "root_dot")]
    #[test_case("/tmp/../**" ; "root_by_parent")]
    #[test_case("/etc/../../**" ; "parent_past_root")]
    #[test_case("~/**" ; "home")]
    #[test_case("~/../../../../../../../../**" ; "home_climbed_past_root")]
    #[test_case("../../../../../../../../../../../../**" ; "relative_climbed_past_root")]
    #[test_case("/tmp/**" ; "directory_subtree")]
    #[test_case("cargo *" ; "bash_command")]
    fn universal_scope_invariant(pattern: &str) {
        assert_universal_invariant(pattern);
    }

    /// `link` points four levels deeper, so the `..` that reach the root
    /// lexically stop inside the tempdir once the symlink is followed. Allowing
    /// it grants only that subtree, denying it still denies everything.
    #[test]
    #[cfg(unix)]
    fn lexical_root_through_symlink_is_refused_but_grants_only_its_subtree() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("a/b/c/d");
        std::fs::create_dir_all(&real).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let pattern = format!("{}/**", climb_to_lexical_root(&link));

        assert!(is_universal_scope(&pattern), "{pattern}");
        for scope in OUTSIDE_SCOPES {
            assert!(!scope_matches(&pattern, scope), "{pattern} matched {scope}");
        }
        for (rule, expected) in [
            (allow_rule(&pattern), PROMPTS),
            (deny_rule(&pattern), DENIED),
        ] {
            let mgr = mgr_with(make_config(vec![rule]), dir.path().to_path_buf());
            assert_eq!(
                outcome(mgr.check(&ToolKey::native(BASH_TOOL), "cargo test", None)),
                expected
            );
        }
    }

    /// The pnpm layout from the bug: `node_modules/react` links deeper into the
    /// store, so a write path climbing to the root lexically lands inside the
    /// project. The session rule has to name that directory, not the root.
    #[test]
    #[cfg(unix)]
    fn write_rule_through_pnpm_symlink_stays_in_landing_dir() {
        let project = tempfile::tempdir().unwrap();
        let link = project.path().join("node_modules/react");
        let store = project
            .path()
            .join(".pnpm/react@18/node_modules/react")
            .join("pad/".repeat(normal_depth(&link).saturating_sub(4)));
        std::fs::create_dir_all(&store).unwrap();
        std::fs::create_dir(link.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&store, &link).unwrap();
        let scope = format!("{}/x", climb_to_lexical_root(&link));
        let write = ToolKey::native("write");

        let rule = generalized_scopes(&write, std::slice::from_ref(&scope)).remove(0);
        let rule_dir = rule.strip_suffix("/**").unwrap();
        assert!(
            !Path::new(rule_dir)
                .components()
                .any(|c| c == Component::ParentDir),
            "{rule}"
        );
        assert!(
            normalize_scope_prefix(rule_dir).starts_with(normalize_scope_prefix(project.path())),
            "{rule}"
        );
        assert!(scope_matches(&rule, &scope), "{rule} misses {scope}");

        let mgr = mgr_with(PermissionsConfig::default(), project.path().to_path_buf());
        mgr.apply_decision(&write, &[scope], &PermissionAnswer::AllowSession);
        for outside in OUTSIDE_WRITES {
            assert_eq!(
                outcome(mgr.check(&write, outside, None)),
                PROMPTS,
                "{outside}"
            );
        }
    }

    #[test_case(vec!["cd /tmp", "cargo test"], vec!["cd *", "cargo *"], true ; "all_allowed")]
    #[test_case(vec!["cd /tmp", "cargo test"], vec!["cargo *"], false ; "missing_rule")]
    fn compound_check(scopes: Vec<&str>, rules: Vec<&str>, expect_allowed: bool) {
        let mgr = mgr_with(
            make_config(rules.into_iter().map(allow_rule).collect()),
            PathBuf::from("/tmp"),
        );
        let check = mgr.check_multi(&ToolKey::native("bash"), &scopes, false, None);
        assert_eq!(matches!(check, PermissionCheck::Allowed), expect_allowed);
    }

    #[test]
    fn compound_denied_if_any_segment_denied() {
        let mgr = mgr_with(
            make_config(vec![
                allow_rule("cd *"),
                allow_rule("cargo *"),
                deny_rule("rm *"),
            ]),
            PathBuf::from("/tmp"),
        );
        assert!(matches!(
            mgr.check_multi(
                &ToolKey::native("bash"),
                &["cd /tmp", "cargo test", "rm -rf /"],
                false,
                None
            ),
            PermissionCheck::Denied(_)
        ));
    }

    #[test]
    fn complex_constructs_force_prompt_even_with_allow_star() {
        let mgr = mgr_with(make_config(vec![allow_rule("*")]), PathBuf::from("/tmp"));
        assert!(matches!(
            mgr.check_multi(&ToolKey::native("bash"), &["echo $(whoami)"], true, None),
            PermissionCheck::NeedsPrompt { .. }
        ));
    }

    #[test_case("write", "/tmp/file.txt" => true ; "write_in_cwd")]
    #[test_case("write", "/etc/passwd" => false ; "write_outside_cwd")]
    #[test_case("task", "task:research" => true ; "task_allowed")]
    #[test_case("bash", "cargo test" => false ; "bash_prompts")]
    fn builtin_check(tool: &str, scope: &str) -> bool {
        matches!(
            default_mgr().check(&ToolKey::native(tool), scope, None),
            PermissionCheck::Allowed
        )
    }

    #[test]
    #[cfg(unix)]
    fn scope_matches_resolves_symlinked_parent() {
        let tmp = std::env::temp_dir();
        let real = tmp.join("__maki_test_scope_symlink_real");
        let link = tmp.join("__maki_test_scope_symlink_link");
        let _ = std::fs::remove_dir_all(&real);
        let _ = std::fs::remove_file(&link);
        std::fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let pattern = format!("{}/**", real.display());
        let value = format!("{}/new_file.txt", link.display());
        assert!(
            scope_matches(&pattern, &value),
            "symlinked parent should resolve: pattern={pattern}, value={value}"
        );

        let _ = std::fs::remove_dir_all(&real);
        let _ = std::fs::remove_file(&link);
    }

    #[test]
    fn scope_matches_relative_pattern_before_dir_exists() {
        // A relative rule like `dist/**` must match an absolute value even
        // before the directory exists.
        let cwd = std::env::current_dir().unwrap();
        let value = cwd.join("__maki_nonexistent_dist/file.txt");
        assert!(!value.exists(), "test dir must not exist");
        assert!(
            scope_matches("__maki_nonexistent_dist/**", &value.to_string_lossy()),
            "relative pattern should match absolute value: value={}",
            value.display()
        );
    }

    #[test]
    #[cfg(unix)]
    fn scope_matches_symlinked_parent_with_nonexistent_tail() {
        // Regression: symlinked leading component plus a non-existent tail
        // (`proj`). Both sides must resolve the symlink before appending the
        // lexical tail, else the prefix stays lexical and this returns false.
        let tmp = std::env::temp_dir();
        let real = tmp.join("__maki_test_scope_symlink_tail_real");
        let link = tmp.join("__maki_test_scope_symlink_tail_link");
        let _ = std::fs::remove_dir_all(&real);
        let _ = std::fs::remove_file(&link);
        std::fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();

        // `proj` under the symlink does not exist.
        let pattern = format!("{}/proj/**", link.display());
        let value = format!("{}/proj/file.txt", link.display());
        assert!(
            scope_matches(&pattern, &value),
            "symlinked parent with non-existent tail should match: pattern={pattern}, value={value}"
        );

        let _ = std::fs::remove_dir_all(&real);
        let _ = std::fs::remove_file(&link);
    }

    #[test]
    fn path_traversal_prompts() {
        assert!(matches!(
            default_mgr().check(&ToolKey::native("write"), "/tmp/../etc/passwd", None),
            PermissionCheck::NeedsPrompt { .. }
        ));
    }

    #[test]
    fn session_rule_overrides_config() {
        let mgr = mgr_with(
            make_config(vec![allow_rule("cargo *")]),
            PathBuf::from("/tmp"),
        );
        mgr.add_session_rule(deny_rule("cargo *"));
        assert!(matches!(
            mgr.check(&ToolKey::native("bash"), "cargo test", None),
            PermissionCheck::Denied(_)
        ));
    }

    #[test]
    fn deny_overrides_default_allow() {
        let mgr = mgr_with(
            PermissionsConfig {
                default: DefaultEffect::Allow,
                rules: vec![deny_rule("rm *")],
                ..Default::default()
            },
            PathBuf::from("/tmp"),
        );
        assert!(matches!(
            mgr.check(&ToolKey::native("bash"), "rm -rf /", None),
            PermissionCheck::Denied(_)
        ));
    }

    // When you allow "cargo test", we generalize to "cargo *" for convenience.
    // But denies stay exact, you probably have a good reason to block that specific thing.
    #[test]
    fn allow_decision_generalizes() {
        let mgr = default_mgr();
        mgr.apply_decision(
            &ToolKey::native("bash"),
            &["cargo test --all".into()],
            &PermissionAnswer::AllowSession,
        );
        assert!(matches!(
            mgr.check(&ToolKey::native("bash"), "cargo build", None),
            PermissionCheck::Allowed
        ));
    }

    #[test]
    fn deny_decision_uses_exact() {
        let project = tempfile::tempdir().unwrap();
        let mgr = mgr_with(PermissionsConfig::default(), project.path().to_path_buf());
        mgr.apply_decision(
            &ToolKey::native("bash"),
            &["cargo test".into()],
            &PermissionAnswer::DenyAlwaysProject,
        );
        assert!(matches!(
            mgr.check(&ToolKey::native("bash"), "cargo test", None),
            PermissionCheck::Denied(_)
        ));
        assert!(matches!(
            mgr.check(&ToolKey::native("bash"), "cargo build", None),
            PermissionCheck::NeedsPrompt { .. }
        ));
    }

    /// A trusted folder collects the answer in `.maki/permissions.toml`. An
    /// untrusted one keeps it for the session and gets no `.maki` directory,
    /// for deny as much as for allow, because declining to trust a checkout
    /// has to leave nothing behind in it. The deny that lasts is the global
    /// one.
    #[test_case(PermissionAnswer::AllowAlwaysProject, true, true ; "allow_is_written_when_trusted")]
    #[test_case(PermissionAnswer::DenyAlwaysProject, false, true ; "deny_is_written_when_trusted")]
    #[test_case(PermissionAnswer::AllowAlwaysProject, true, false ; "allow_stays_in_the_session_when_untrusted")]
    #[test_case(PermissionAnswer::DenyAlwaysProject, false, false ; "deny_stays_in_the_session_when_untrusted")]
    fn project_answer_is_written_only_in_a_trusted_folder(
        answer: PermissionAnswer,
        allowed: bool,
        trusted: bool,
    ) {
        let project = tempfile::tempdir().unwrap();
        let mgr = PermissionManager::new(
            PermissionsConfig::default(),
            project.path().to_path_buf(),
            if trusted {
                ProjectConfig::for_project(project.path())
            } else {
                ProjectConfig::discover(project.path())
            },
            Arc::default(),
        );

        mgr.apply_decision(&ToolKey::native("bash"), &["cargo test".into()], &answer);

        assert_eq!(mgr.session_rules_snapshot().len(), 1);
        assert_eq!(project.path().join(PROJECT_DIR).exists(), trusted);
        assert_eq!(project.path().join(PROJECT_PERMISSIONS).is_file(), trusted);
        let check = mgr.check(&ToolKey::native("bash"), "cargo test", None);
        assert_eq!(matches!(check, PermissionCheck::Allowed), allowed);
        assert_eq!(matches!(check, PermissionCheck::Denied(_)), !allowed);
    }
    #[test]
    fn boundary_inside_proceeds() {
        let tmp = std::env::temp_dir();
        let mgr = mgr_with(PermissionsConfig::default(), tmp.clone());
        assert!(
            mgr.boundary_block_reason(&tmp.join("some_file.txt"))
                .is_none()
        );
    }

    #[test]
    fn boundary_outside_proceeds_via_prompt() {
        let tmp = std::env::temp_dir();
        let mgr = mgr_with(PermissionsConfig::default(), tmp);
        #[cfg(unix)]
        let outside = Path::new("/etc/hosts");
        #[cfg(windows)]
        let outside = Path::new(r"C:\Windows\System32\drivers\etc\hosts");
        assert!(mgr.boundary_block_reason(outside).is_none());
    }

    #[test]
    fn boundary_dotdot_smuggling_proceeds_via_prompt() {
        let tmp = std::env::temp_dir();
        let sub = tmp.join("__maki_test_boundary");
        std::fs::create_dir_all(&sub).unwrap();
        #[cfg(unix)]
        let attack = sub
            .join("x")
            .join("..")
            .join("..")
            .join("..")
            .join("etc")
            .join("passwd");
        #[cfg(windows)]
        let attack = sub
            .join("x")
            .join("..")
            .join("..")
            .join("..")
            .join("Windows")
            .join("System32");
        let mgr = mgr_with(PermissionsConfig::default(), sub.clone());
        assert!(
            mgr.boundary_block_reason(&attack).is_none(),
            "outside-cwd dotdot path should prompt, not hard-block: {}",
            attack.display()
        );
        let _ = std::fs::remove_dir_all(&sub);
    }

    #[test]
    #[cfg(unix)]
    fn boundary_symlink_escape_proceeds_via_prompt() {
        // Lexical normalization resolves this inside (/project/escape), but
        // incremental canonicalization follows the symlink first, so `..`
        // escapes outside. The permission prompt catches it, not this function.
        let tmp = std::env::temp_dir();
        let project = tmp.join("__maki_test_symlink_escape");
        let _ = std::fs::remove_dir_all(&project);
        std::fs::create_dir_all(&project).unwrap();
        let link = project.join("link");
        let _ = std::os::unix::fs::symlink(&tmp, &link);

        let attack = link.join("..").join("escape_target");
        let mgr = mgr_with(PermissionsConfig::default(), project.clone());
        assert!(
            mgr.boundary_block_reason(&attack).is_none(),
            "outside-boundary edits are gated by the prompt, not hard-blocked: {}",
            attack.display()
        );
        let _ = std::fs::remove_dir_all(&project);
    }

    #[test]
    fn boundary_nonexistent_cwd_proceeds_via_lexical_tail() {
        let missing = std::env::temp_dir().join("__maki_test_absent_cwd_xyz");
        let _ = std::fs::remove_dir_all(&missing);
        let mgr = mgr_with(PermissionsConfig::default(), missing.clone());
        assert!(
            mgr.boundary_block_reason(&missing.join("file.txt"))
                .is_none()
        );
    }

    #[test]
    fn permission_answer_roundtrip() {
        for a in [
            PermissionAnswer::AllowOnce,
            PermissionAnswer::AllowSession,
            PermissionAnswer::AllowAlwaysProject,
            PermissionAnswer::Deny,
            PermissionAnswer::DenyWithGuidance("hint".into()),
        ] {
            assert_eq!(PermissionAnswer::decode(&a.encode()), Some(a));
        }
    }

    #[test_case(PermissionAnswer::AllowAlwaysProject ; "allow")]
    #[test_case(PermissionAnswer::Deny ; "deny")]
    #[test_case(PermissionAnswer::DenyWithGuidance(TAGGED_GUIDANCE.into()) ; "guidance_with_separator")]
    fn tagged_answer_roundtrip(answer: PermissionAnswer) {
        let tagged = TaggedAnswer::new(TAGGED_REQUEST_ID, answer);
        assert_eq!(TaggedAnswer::decode(&tagged.encode()), Some(tagged));
    }

    #[test_case("" ; "empty")]
    #[test_case("allow" ; "untagged_answer")]
    #[test_case(TAGGED_REQUEST_ID ; "id_only")]
    #[test_case("{\"json\": true}" ; "elicitation_result")]
    fn untagged_payloads_never_decode_to_an_answer(raw: &str) {
        assert_eq!(TaggedAnswer::decode(raw), None);
    }

    #[test]
    fn check_multi_force_prompt_skips_allow_rules() {
        let mgr = mgr_with(
            make_config(vec![allow_rule("cargo *"), allow_rule("git *")]),
            PathBuf::from("/tmp"),
        );
        assert!(matches!(
            mgr.check_multi(
                &ToolKey::native("bash"),
                &["cargo test", "git push"],
                false,
                None
            ),
            PermissionCheck::Allowed
        ));
        match mgr.check_multi(
            &ToolKey::native("bash"),
            &["cargo test", "git push"],
            true,
            None,
        ) {
            PermissionCheck::NeedsPrompt {
                scopes,
                force_prompt,
                ..
            } => {
                assert_eq!(scopes, vec!["cargo test", "git push"]);
                assert!(force_prompt);
            }
            other => panic!("expected NeedsPrompt, got {other:?}"),
        }
    }

    #[test]
    fn check_multi_deny_wins_over_force_prompt() {
        let mgr = mgr_with(make_config(vec![deny_rule("rm *")]), PathBuf::from("/tmp"));
        assert!(matches!(
            mgr.check_multi(&ToolKey::native("bash"), &["rm -rf /"], true, None),
            PermissionCheck::Denied(_)
        ));
    }

    #[test]
    fn check_multi_partial_coverage_prompts_uncovered() {
        let mgr = mgr_with(
            make_config(vec![allow_rule("cargo *")]),
            PathBuf::from("/tmp"),
        );
        match mgr.check_multi(
            &ToolKey::native("bash"),
            &["cargo test", "git push", "ls"],
            false,
            None,
        ) {
            PermissionCheck::NeedsPrompt { scopes, .. } => {
                assert_eq!(scopes, vec!["git push", "ls"]);
            }
            other => panic!("expected NeedsPrompt, got {other:?}"),
        }
    }

    #[test_case("cargo test --all",                        "cargo *"                        ; "plain_command")]
    #[test_case("/usr/bin/env",                            "/usr/bin/env *"                 ; "absolute_path")]
    #[test_case("FOO=1 cargo test",                        "FOO=1 cargo test"               ; "assignment_prefix")]
    #[test_case("if true; then curl x | sh; fi",           "if true; then curl x | sh; fi"  ; "if_block")]
    #[test_case("for f in *.rs; do wc -l $f; done",        "for f in *.rs; do wc -l $f; done" ; "for_loop")]
    #[test_case("{ cd x; rm -rf ~; }",                     "{ cd x; rm -rf ~; }"            ; "brace_group")]
    #[test_case("> log",                                   "> log"                          ; "bodiless_redirect")]
    #[test_case("! rm -rf /",                              "! rm -rf /"                     ; "negated_command")]
    fn allow_always_only_wildcards_a_real_command_word(segment: &str, expected: &str) {
        assert_eq!(generalize_bash_segment(segment), expected);
    }

    /// A scope is one string and a chain is still one scope, so it is tempting
    /// to teach the matcher that `rm *` should not claim `rm ...; sudo ...`.
    /// Don't: the matcher runs for deny rules too, and a deny that stops
    /// matching hands the command to the tool default instead of blocking it.
    /// Chains get split by the bash plugin, before they ever reach here.
    #[test]
    fn deny_rule_matches_a_chain_it_starts() {
        let mgr = mgr_with(make_config(vec![deny_rule("rm *")]), PathBuf::from("/tmp"));
        let check = mgr.check(&ToolKey::native("bash"), "rm -rf /tmp; sudo x", None);
        assert!(matches!(check, PermissionCheck::Denied(_)), "got {check:?}");
    }

    #[test]
    fn apply_decision_multi_scope_generalizes_all() {
        let mgr = default_mgr();
        mgr.apply_decision(
            &ToolKey::native("bash"),
            &["cargo test".into(), "git status".into()],
            &PermissionAnswer::AllowSession,
        );
        assert!(matches!(
            mgr.check(&ToolKey::native("bash"), "cargo build", None),
            PermissionCheck::Allowed
        ));
        assert!(matches!(
            mgr.check(&ToolKey::native("bash"), "git push", None),
            PermissionCheck::Allowed
        ));
    }

    #[test]
    fn generalized_scopes_deduplicates() {
        let scopes = vec!["cargo test".into(), "cargo build".into()];
        let result = generalized_scopes(&ToolKey::native("bash"), &scopes);
        assert_eq!(result, vec!["cargo *"]);
    }

    #[test]
    fn generalized_scopes_preserves_distinct() {
        let scopes = vec!["cargo test".into(), "git status".into()];
        let result = generalized_scopes(&ToolKey::native("bash"), &scopes);
        assert_eq!(result, vec!["cargo *", "git *"]);
    }

    #[test_case("webfetch", "some:scope" => "some:scope" ; "unknown_tool_preserves_exact")]
    #[test_case("myserver.fetch", "{\"url\":\"https://a\"}" => "*" ; "mcp_tool_generalizes_to_wildcard")]
    fn generalize_single_scope(tool: &str, scope: &str) -> String {
        generalized_scopes(&ToolKey::parse(tool).unwrap(), &[scope.into()])
            .into_iter()
            .next()
            .unwrap()
    }

    #[test]
    fn generalize_edit_uses_parent_dir() {
        let result = generalize_scope(&ToolKey::native("edit"), "/home/user/project/src/main.rs");
        let expected = format!(
            "{}/**",
            Path::new("/home/user/project/src/main.rs")
                .parent()
                .unwrap()
                .display()
        );
        assert_eq!(result, expected);
    }

    #[test]
    fn generalize_edit_root_file() {
        let result = generalize_scope(&ToolKey::native("edit"), "/Cargo.toml");
        let expected = format!(
            "{}/**",
            Path::new("/Cargo.toml").parent().unwrap().display()
        );
        assert_eq!(result, expected);
    }

    /// "Allow always" stores a command's generalized scope as a rule, so the
    /// command must match the very rule it would create. When this broke, the
    /// bare `pwd` never matched its own `pwd *` rule and we reprompted forever.
    #[test_case("bash", "pwd" ; "bash_bare_command")]
    #[test_case("bash", "cargo test" ; "bash_command_with_args")]
    #[test_case("bash", "git status --short" ; "bash_command_with_flags")]
    #[test_case("edit", "/home/user/project/src/main.rs" ; "edit_path")]
    #[test_case("webfetch", "https://example.com" ; "unknown_tool_exact")]
    #[test_case("myfetch.search", "{\"url\":\"https://a\"}" ; "mcp_tool_call")]
    fn command_matches_its_own_generalized_rule(tool: &str, scope: &str) {
        let tool_key = ToolKey::parse(tool).unwrap();
        let rule = &generalized_scopes(&tool_key, &[scope.into()])[0];
        assert!(
            scope_matches(rule, scope),
            "{scope:?} does not match its generalized rule {rule:?}"
        );
    }

    /// "Allow always" on an MCP tool generalizes the stored scope to `*`, so a
    /// later call with different arguments matches the persisted rule instead of
    /// reprompting, while a different MCP tool is still gated by its `tool` name.
    #[test]
    fn mcp_allow_always_matches_any_args_but_stays_per_tool() {
        let mgr = default_mgr();
        mgr.apply_decision(
            &ToolKey::parse("myfetch.search").unwrap(),
            &["{\"url\":\"https://a\"}".into()],
            &PermissionAnswer::AllowSession,
        );
        // Same tool, different arguments -> allowed without reprompting.
        assert!(matches!(
            mgr.check(
                &ToolKey::parse("myfetch.search").unwrap(),
                "{\"url\":\"https://b\"}",
                None
            ),
            PermissionCheck::Allowed
        ));
        // A distinct MCP tool is not covered by the fetch rule.
        assert!(!matches!(
            mgr.check(
                &ToolKey::parse("myfetch.exec").unwrap(),
                "{\"cmd\":\"ls\"}",
                None
            ),
            PermissionCheck::Allowed
        ));
    }

    #[test]
    fn deny_rule_with_none_scope_blocks_everything() {
        let mgr = mgr_with(
            make_config(vec![PermissionRule {
                tool: ToolKey::native("bash"),
                scope: None,
                effect: Effect::Deny,
            }]),
            PathBuf::from("/tmp"),
        );
        assert!(matches!(
            mgr.check(&ToolKey::native("bash"), "anything", None),
            PermissionCheck::Denied(_)
        ));
    }

    #[test]
    fn wildcard_deny_blocks_all_tools() {
        let mgr = mgr_with(
            make_config(vec![PermissionRule {
                tool: ToolKey::Wildcard,
                scope: None,
                effect: Effect::Deny,
            }]),
            PathBuf::from("/tmp"),
        );
        // Any deny wins: Wildcard deny blocks everything including builtins
        assert!(matches!(
            mgr.check(&ToolKey::native("bash"), "ls", None),
            PermissionCheck::Denied(_)
        ));
        assert!(matches!(
            mgr.check(&ToolKey::native("write"), "/tmp/x", None),
            PermissionCheck::Denied(_)
        ));
    }

    #[test]
    fn mcp_deny_always_blocks_all_arguments() {
        let project = tempfile::tempdir().unwrap();
        let mgr = mgr_with(make_config(vec![]), project.path().to_path_buf());
        let tool = ToolKey::McpTool {
            server: "deepwiki".into(),
            tool: "search".into(),
        };
        // User denies with specific arguments — should generalize to block all.
        mgr.apply_decision(
            &tool,
            &["{\"q\":\"dangerous\"}".into()],
            &PermissionAnswer::DenyAlwaysProject,
        );
        // Different arguments: still denied.
        assert!(matches!(
            mgr.check(&tool, "{\"q\":\"safe\"}", None),
            PermissionCheck::Denied(_)
        ));
        // Even wildcard scope: denied.
        assert!(matches!(
            mgr.check(&tool, "*", None),
            PermissionCheck::Denied(_)
        ));
    }

    #[test]
    fn yolo_mode_allows_but_deny_still_blocks() {
        let mgr = mgr_with(make_config(vec![deny_rule("rm *")]), PathBuf::from("/tmp"));
        mgr.toggle_yolo();
        assert!(mgr.is_yolo());
        assert!(matches!(
            mgr.check(&ToolKey::native("bash"), "cargo test", None),
            PermissionCheck::Allowed
        ));
        assert!(matches!(
            mgr.check(&ToolKey::native("bash"), "rm -rf /", None),
            PermissionCheck::Denied(_)
        ));
    }

    fn seeded_mgr(yolo: bool) -> PermissionManager {
        mgr_with(
            PermissionsConfig {
                yolo,
                ..Default::default()
            },
            PathBuf::from("/tmp"),
        )
    }

    /// A fork runs the same session, so it has to answer both questions the
    /// same way or a respawned agent drifts from the tab that owns it.
    fn yolo_state(mgr: &PermissionManager) -> (bool, Option<bool>) {
        let forked = mgr.fork();
        assert_eq!(
            (forked.is_yolo(), forked.persisted_yolo()),
            (mgr.is_yolo(), mgr.persisted_yolo()),
        );
        (mgr.is_yolo(), mgr.persisted_yolo())
    }

    /// A stored intent replaces the seed outright, and no stored intent falls
    /// back to it: `--yolo` must neither be erased by an untouched session nor
    /// survive one the user explicitly turned off.
    #[test_case(false, None        => (false, None)        ; "no_flag_and_no_intent_stays_off")]
    #[test_case(true,  None        => (true,  None)        ; "the_flag_applies_but_is_never_stored")]
    #[test_case(false, Some(true)  => (true,  Some(true))  ; "stored_on_comes_back_without_the_flag")]
    #[test_case(true,  Some(true)  => (true,  Some(true))  ; "the_flag_does_not_wipe_stored_on")]
    #[test_case(true,  Some(false) => (false, Some(false)) ; "stored_off_overrides_the_flag")]
    #[test_case(false, Some(false) => (false, Some(false)) ; "stored_off_stays_off")]
    fn a_stored_yolo_intent_replaces_the_seed(
        seed: bool,
        stored: Option<bool>,
    ) -> (bool, Option<bool>) {
        let mgr = seeded_mgr(seed);
        mgr.set_session_yolo(stored);
        yolo_state(&mgr)
    }

    /// `/yolo` always drives the effective state, so under `--yolo` it can turn
    /// the session off, and either way the session now owns the answer.
    #[test_case(false => (true,  Some(true))  ; "toggling_on_claims_the_session")]
    #[test_case(true  => (false, Some(false)) ; "toggling_off_under_the_flag_claims_the_session")]
    fn toggling_yolo_records_the_intent(seed: bool) -> (bool, Option<bool>) {
        let mgr = seeded_mgr(seed);
        assert_eq!(mgr.toggle_yolo(), !seed);
        yolo_state(&mgr)
    }

    #[test]
    fn add_session_rule_is_idempotent() {
        let mgr = default_mgr();
        let rule = allow_rule("cargo *");
        mgr.add_session_rule(rule.clone());
        mgr.add_session_rule(rule.clone());
        mgr.add_session_rule(rule);
        assert_eq!(mgr.session_rules_snapshot().len(), 1);
    }

    #[test_case(PermissionAnswer::AllowOnce ; "allow_once")]
    #[test_case(PermissionAnswer::Deny ; "deny_once")]
    fn once_decisions_add_no_session_rules(answer: PermissionAnswer) {
        let mgr = default_mgr();
        mgr.apply_decision(&ToolKey::native("bash"), &["cargo test".into()], &answer);
        assert!(mgr.session_rules_snapshot().is_empty());
    }

    #[test]
    fn default_deny_blocks_unmatched() {
        let mgr = mgr_with(
            PermissionsConfig {
                default: DefaultEffect::Deny,
                ..Default::default()
            },
            PathBuf::from("/tmp"),
        );
        assert!(matches!(
            mgr.check(&ToolKey::native("bash"), "cargo test", None),
            PermissionCheck::Denied(_)
        ));
    }

    #[test]
    fn default_deny_with_allow_rules() {
        let mgr = mgr_with(
            PermissionsConfig {
                default: DefaultEffect::Deny,
                rules: vec![allow_rule("cargo *")],
                ..Default::default()
            },
            PathBuf::from("/tmp"),
        );
        assert!(matches!(
            mgr.check(&ToolKey::native("bash"), "cargo test", None),
            PermissionCheck::Allowed
        ));
        assert!(matches!(
            mgr.check(&ToolKey::native("bash"), "rm -rf /", None),
            PermissionCheck::Denied(_)
        ));
    }

    #[test]
    fn default_allow_allows_unmatched() {
        let mgr = mgr_with(
            PermissionsConfig {
                default: DefaultEffect::Allow,
                ..Default::default()
            },
            PathBuf::from("/tmp"),
        );
        assert!(matches!(
            mgr.check(&ToolKey::native("bash"), "cargo test", None),
            PermissionCheck::Allowed
        ));
    }

    #[test]
    fn default_prompt_is_default_behavior() {
        let mgr = mgr_with(PermissionsConfig::default(), PathBuf::from("/tmp"));
        assert!(matches!(
            mgr.check(&ToolKey::native("bash"), "cargo test", None),
            PermissionCheck::NeedsPrompt { .. }
        ));
    }

    #[test]
    fn mcp_server_wildcard_matches_all_server_tools() {
        let mgr = mgr_with(
            make_config(vec![PermissionRule {
                tool: ToolKey::McpServer {
                    server: "deepwiki".into(),
                },
                scope: None,
                effect: Effect::Allow,
            }]),
            PathBuf::from("/tmp"),
        );
        assert!(matches!(
            mgr.check(
                &ToolKey::McpTool {
                    server: "deepwiki".into(),
                    tool: "search".into()
                },
                "{}",
                None
            ),
            PermissionCheck::Allowed
        ));
        assert!(matches!(
            mgr.check(
                &ToolKey::McpTool {
                    server: "deepwiki".into(),
                    tool: "web_search".into()
                },
                "{}",
                None
            ),
            PermissionCheck::Allowed
        ));
    }

    #[test]
    fn mcp_server_wildcard_does_not_match_other_server() {
        let mgr = mgr_with(
            make_config(vec![PermissionRule {
                tool: ToolKey::McpServer {
                    server: "deepwiki".into(),
                },
                scope: None,
                effect: Effect::Allow,
            }]),
            PathBuf::from("/tmp"),
        );
        assert!(!matches!(
            mgr.check(
                &ToolKey::McpTool {
                    server: "github".into(),
                    tool: "search".into()
                },
                "{}",
                None
            ),
            PermissionCheck::Allowed
        ));
    }

    #[test]
    fn per_tool_default_overrides_global() {
        let mgr = mgr_with(
            PermissionsConfig {
                default: DefaultEffect::Deny,
                tool_defaults: HashMap::from([(ToolKey::native("bash"), DefaultEffect::Allow)]),
                rules: vec![],
                ..Default::default()
            },
            PathBuf::from("/tmp"),
        );
        assert!(matches!(
            mgr.check(&ToolKey::native("bash"), "cargo test", None),
            PermissionCheck::Allowed
        ));
        assert!(matches!(
            mgr.check(&ToolKey::native("write"), "/etc/passwd", None),
            PermissionCheck::Denied(_)
        ));
    }

    #[test_case("write", true ; "write_tool_allowed")]
    #[test_case("edit", true ; "edit_tool_allowed")]
    #[test_case("bash", false ; "non_write_tool_prompts")]
    fn plan_path_auto_allows_file_write_tools_only(tool: &str, expect_allowed: bool) {
        let plan_path = Path::new(PLAN_FILE);
        let mgr = default_mgr();
        assert_eq!(
            matches!(
                mgr.check(&ToolKey::native(tool), PLAN_FILE, Some(plan_path)),
                PermissionCheck::Allowed
            ),
            expect_allowed,
        );
    }

    /// Plan mode is read-only and an MCP server can write without saying so,
    /// so approving one for the user would break that. Native tools are known,
    /// and the ones plan mode does not block stay automatic.
    #[test_case(MCP_TOOL,  MCP_ARGS,  DefaultEffect::Prompt, true  => PROMPTS ; "yolo_plan_mode_prompts_for_mcp")]
    #[test_case(MCP_TOOL,  MCP_ARGS,  DefaultEffect::Allow,  true  => PROMPTS ; "default_allow_plan_mode_prompts_for_mcp")]
    #[test_case(MCP_TOOL,  MCP_ARGS,  DefaultEffect::Prompt, false => ALLOWED ; "yolo_build_mode_allows_mcp")]
    #[test_case(READ_TOOL, READ_SCOPE, DefaultEffect::Prompt, true => ALLOWED ; "yolo_plan_mode_allows_native_read")]
    fn plan_mode_outranks_blanket_approval_for_mcp_tools(
        tool: &str,
        scope: &str,
        default: DefaultEffect,
        plan_mode: bool,
    ) -> &'static str {
        let mgr = mgr_with(
            PermissionsConfig {
                yolo: true,
                default,
                ..Default::default()
            },
            PathBuf::from("/tmp"),
        );
        let plan_path = Path::new(PLAN_FILE);
        outcome(mgr.check(
            &ToolKey::parse(tool).expect("test tool key parses"),
            scope,
            plan_mode.then_some(plan_path),
        ))
    }

    /// A rule is the user's own decision about this exact tool, so plan mode
    /// leaves it alone. Only automatic approval is held back.
    #[test]
    fn plan_mode_keeps_an_explicit_allow_rule_for_an_mcp_tool() {
        let mgr = mgr_with(
            make_config(vec![PermissionRule {
                tool: ToolKey::parse(MCP_TOOL).expect("test tool key parses"),
                scope: Some("*".into()),
                effect: Effect::Allow,
            }]),
            PathBuf::from("/tmp"),
        );
        assert_eq!(
            outcome(mgr.check(
                &ToolKey::parse(MCP_TOOL).expect("test tool key parses"),
                MCP_ARGS,
                Some(Path::new(PLAN_FILE)),
            )),
            ALLOWED
        );
    }

    /// The gate itself, apart from any one source of approval. A tool plan mode
    /// cannot read is the only case where how squarely a yes was aimed changes
    /// the answer.
    #[test_case(&mcp_tool_key(), true,  Approval::Standing    => false ; "opaque_tool_refuses_a_standing_yes")]
    #[test_case(&mcp_tool_key(), true,  Approval::ForThisTool => true  ; "opaque_tool_takes_an_answer_about_itself")]
    #[test_case(&mcp_tool_key(), false, Approval::Standing    => true  ; "no_plan_mode_takes_anything")]
    #[test_case(&native_key(),   true,  Approval::Standing    => true  ; "native_tool_is_never_opaque")]
    fn the_gate_only_ranks_approvals_for_a_tool_plan_mode_cannot_read(
        tool: &ToolKey,
        plan_mode: bool,
        approval: Approval,
    ) -> bool {
        ApprovalGate::new(tool, plan_mode.then_some(Path::new(PLAN_FILE))).accepts(approval)
    }

    /// A rule that was not written for this exact tool is a standing approval
    /// the user never gave it, so plan mode holds it back the way it holds back
    /// yolo. Denies are not approvals and keep winning.
    #[test_case(ToolKey::Wildcard,  Effect::Allow, true  => PROMPTS ; "wildcard_allow_prompts_in_plan_mode")]
    #[test_case(mcp_server_key(),   Effect::Allow, true  => PROMPTS ; "server_allow_prompts_in_plan_mode")]
    #[test_case(mcp_tool_key(),     Effect::Allow, true  => ALLOWED ; "exact_tool_allow_decides_in_plan_mode")]
    #[test_case(ToolKey::Wildcard,  Effect::Deny,  true  => DENIED  ; "wildcard_deny_denies_in_plan_mode")]
    #[test_case(ToolKey::Wildcard,  Effect::Allow, false => ALLOWED ; "wildcard_allow_outside_plan_mode")]
    #[test_case(mcp_server_key(),   Effect::Allow, false => ALLOWED ; "server_allow_outside_plan_mode")]
    #[test_case(ToolKey::Wildcard,  Effect::Deny,  false => DENIED  ; "wildcard_deny_outside_plan_mode")]
    fn plan_mode_holds_back_rules_not_written_for_the_mcp_tool(
        rule_key: ToolKey,
        effect: Effect,
        plan_mode: bool,
    ) -> &'static str {
        let mgr = mgr_with(
            make_config(vec![PermissionRule {
                tool: rule_key,
                scope: None,
                effect,
            }]),
            PathBuf::from(TEST_CWD),
        );
        outcome(mgr.check(
            &mcp_tool_key(),
            MCP_ARGS,
            plan_mode.then_some(Path::new(PLAN_FILE)),
        ))
    }

    #[test]
    fn plugin_rules_apply_to_manager_and_forks() {
        let store = Arc::new(PluginRuleStore::default());
        let mgr = PermissionManager::new(
            PermissionsConfig::default(),
            PathBuf::from("/tmp"),
            ProjectConfig::for_project(Path::new("/tmp")),
            Arc::clone(&store),
        );
        let fork = mgr.fork();
        store.replace("memory", vec![plugin_edit_rule("/x/**", Effect::Allow)]);
        for m in [&mgr, &fork] {
            assert!(matches!(
                m.check(&ToolKey::native("edit"), "/x/f", None),
                PermissionCheck::Allowed
            ));
        }
    }

    #[test]
    fn config_deny_beats_plugin_allow() {
        let store = Arc::new(PluginRuleStore::default());
        store.replace("memory", vec![plugin_edit_rule("/x/**", Effect::Allow)]);
        let mgr = PermissionManager::new(
            make_config(vec![plugin_edit_rule("/x/**", Effect::Deny)]),
            PathBuf::from("/tmp"),
            ProjectConfig::for_project(Path::new("/tmp")),
            store,
        );
        assert!(matches!(
            mgr.check(&ToolKey::native("edit"), "/x/f", None),
            PermissionCheck::Denied(_)
        ));
    }

    #[test]
    fn plan_path_multi_scope_all_must_match() {
        let plan_path = Path::new(PLAN_FILE);
        let mgr = default_mgr();

        // All scopes match plan → allowed
        assert!(matches!(
            mgr.check_multi(
                &ToolKey::native("write"),
                &[PLAN_FILE, PLAN_FILE],
                false,
                Some(plan_path),
            ),
            PermissionCheck::Allowed
        ));

        // One scope is non-plan → needs prompt
        assert!(matches!(
            mgr.check_multi(
                &ToolKey::native("write"),
                &[PLAN_FILE, "/etc/passwd"],
                false,
                Some(plan_path),
            ),
            PermissionCheck::NeedsPrompt { .. }
        ));
    }

    /// `away/..` spells the plan file, but `away` is a symlink, so the write
    /// lands beside its target instead. A symlinked spelling of the plan file
    /// itself still is the plan file.
    #[test]
    #[cfg(unix)]
    fn plan_auto_allow_follows_symlinks_like_the_write() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = tempfile::tempdir().unwrap();
        let plans = dir.path().join("plans");
        let elsewhere = dir.path().join("elsewhere/deep");
        std::fs::create_dir_all(&plans).unwrap();
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, plans.join("away")).unwrap();
        std::os::unix::fs::symlink(&plans, dir.path().join("alias")).unwrap();
        let plan = plans.join("plan.md");
        let mgr = mgr_with(PermissionsConfig::default(), cwd.path().to_path_buf());
        let write = ToolKey::native("write");

        for (scope, expected) in [
            (plans.join("away/../plan.md"), PROMPTS),
            (dir.path().join("alias/plan.md"), ALLOWED),
        ] {
            let scope = scope.to_string_lossy();
            assert_eq!(
                outcome(mgr.check(&write, &scope, Some(&plan))),
                expected,
                "{scope}"
            );
        }
    }

    fn denied_reason(mgr: &PermissionManager, tool: &ToolKey, scope: &str) -> String {
        match mgr.check(tool, scope, None) {
            PermissionCheck::Denied(reason) => reason,
            other => panic!("expected denied, got {other:?}"),
        }
    }

    /// The model must learn which rule closed the door, not just that one did.
    #[test]
    fn deny_rule_reason_names_the_rule_and_its_source() {
        let mgr = mgr_with(
            make_config(vec![deny_rule("head *")]),
            PathBuf::from("/tmp"),
        );
        let reason = denied_reason(&mgr, &ToolKey::native("bash"), "head -3");
        assert!(reason.contains("head *"), "got: {reason}");
        assert!(reason.contains(ORIGIN_CONFIG), "got: {reason}");
    }

    #[test]
    fn session_deny_rule_reason_says_session() {
        let mgr = mgr_with(make_config(vec![]), PathBuf::from("/tmp"));
        mgr.add_session_rule(deny_rule("rm *"));
        let reason = denied_reason(&mgr, &ToolKey::native("bash"), "rm -rf /");
        assert!(reason.contains(ORIGIN_SESSION), "got: {reason}");
    }

    #[test]
    fn blanket_deny_rule_reason_says_blanket() {
        let mgr = mgr_with(
            make_config(vec![PermissionRule {
                tool: ToolKey::native("bash"),
                scope: None,
                effect: Effect::Deny,
            }]),
            PathBuf::from("/tmp"),
        );
        let reason = denied_reason(&mgr, &ToolKey::native("bash"), "anything");
        assert!(reason.contains("blanket"), "got: {reason}");
    }

    #[test]
    fn plugin_deny_rule_reason_names_the_plugin_store() {
        let store = Arc::new(PluginRuleStore::default());
        store.replace("guard", vec![plugin_edit_rule("/x/**", Effect::Deny)]);
        let mgr = PermissionManager::new(
            PermissionsConfig::default(),
            PathBuf::from("/tmp"),
            ProjectConfig::for_project(Path::new("/tmp")),
            store,
        );
        let reason = denied_reason(&mgr, &ToolKey::native("edit"), "/x/f");
        assert!(reason.contains(ORIGIN_PLUGIN), "got: {reason}");
        assert!(reason.contains("/x/**"), "got: {reason}");
    }

    #[test]
    fn default_deny_reason_names_the_default() {
        let mgr = mgr_with(
            PermissionsConfig {
                default: DefaultEffect::Deny,
                ..Default::default()
            },
            PathBuf::from("/tmp"),
        );
        let reason = denied_reason(&mgr, &ToolKey::native("bash"), "cargo test");
        assert!(reason.contains("default"), "got: {reason}");

        let mgr = mgr_with(
            PermissionsConfig {
                tool_defaults: HashMap::from([(ToolKey::native("bash"), DefaultEffect::Deny)]),
                ..Default::default()
            },
            PathBuf::from("/tmp"),
        );
        let reason = denied_reason(&mgr, &ToolKey::native("bash"), "cargo test");
        assert!(reason.contains("deny default for `bash`"), "got: {reason}");
    }

    #[test_case(None, DEFAULT_DENY_GUIDANCE; "plain")]
    #[test_case(Some("use rg instead"), "User guidance: use rg instead"; "with_guidance")]
    fn error_message_leads_with_tool_scope_and_reason(guidance: Option<&str>, tail: &str) {
        let err = PermissionError::denied(
            "bash",
            "head -3",
            deny_rule_reason(ORIGIN_CONFIG, &deny_rule("head *")),
            guidance.map(str::to_owned),
            None,
        );
        let msg = err.to_string();
        assert!(msg.starts_with(PERMISSION_DENIED_PREFIX), "got: {msg}");
        assert!(msg.contains("`bash` (head -3):"), "got: {msg}");
        assert!(msg.contains("deny rule `head *` for `bash`"), "got: {msg}");
        assert!(msg.contains(tail), "got: {msg}");
    }

    const LAYER_PLUGIN: &str = "guard";
    const LAYER_SCOPE: &str = "rm -rf build";
    const LAYER_GUIDANCE: &str = "use trash instead";
    const ESCALATION: &str = "look at this";

    #[test_case("read", "/tmp/project/.env", true ; "environment_file")]
    #[test_case("write", "/tmp/project/.env.local", true ; "environment_variant")]
    #[test_case("edit", "/tmp/project/.ssh/config", true ; "ssh_directory")]
    #[test_case("multiedit", "/tmp/project/private.pem", true ; "private_key")]
    #[test_case("read", "/tmp/project/main.rs", false ; "ordinary_file")]
    #[test_case("grep", "/tmp/project/.env", false ; "search_is_not_covered")]
    fn fixed_guard_file_classes(tool: &str, path: &str, guarded: bool) {
        assert_eq!(
            fixed_guard_reason(&ToolKey::native(tool), &json!({"path": path})).is_some(),
            guarded
        );
    }

    #[test_case("printf '%s\\n' 'observation'", false ; "literal_observation")]
    #[test_case("printf '%s\\n' '$(cat .env)'", false ; "substitution_is_literal_inside_single_quotes")]
    #[test_case("printf '%s\\n' 'ok' > output", true ; "redirection")]
    #[test_case("printf '%s\\n' 'ok'; cat .env", true ; "command_chain")]
    #[test_case("printf '%s\\n' \"$(cat .env)\"", true ; "dynamic_argument")]
    #[test_case("printf '%s\\n' 'a' 'b'", true ; "multiple_arguments")]
    #[test_case("printf '%s\\n' 'line\nbreak'", true ; "control_character")]
    fn fixed_guard_shell_boundary(command: &str, guarded: bool) {
        assert_eq!(
            fixed_guard_reason(&ToolKey::native(BASH_TOOL), &json!({"command": command})).is_some(),
            guarded
        );
    }

    #[test]
    fn fixed_guard_unknown_file_target_requires_human() {
        assert_eq!(
            fixed_guard_reason(&ToolKey::native("read"), &json!({})),
            Some(UNKNOWN_FILE_REASON)
        );
    }

    #[cfg(unix)]
    #[test]
    fn fixed_guard_follows_symlink_targets() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let secret = dir.path().join(".env");
        std::fs::write(&secret, "test fixture").expect("fixture");
        let alias = dir.path().join("ordinary.txt");
        std::os::unix::fs::symlink(secret, &alias).expect("symlink");
        assert_eq!(
            fixed_guard_reason(&ToolKey::native("read"), &json!({"path": alias})),
            Some(GUARDED_FILE_REASON)
        );
    }

    struct ClassifierLayer {
        binding: Value,
        verdict: LayerVerdict,
    }

    impl PromptLayers for ClassifierLayer {
        fn exact_binding(&self) -> Option<Value> {
            Some(self.binding.clone())
        }
        fn answer<'a>(&'a self, _scopes: &'a [String]) -> BoxFuture<'a, Option<LayerAnswer>> {
            Box::pin(std::future::ready(Some(LayerAnswer {
                plugin: Arc::from(LAYER_PLUGIN),
                verdict: self.verdict.clone(),
            })))
        }
    }

    fn classifier_call(manager: &PermissionManager, layer: &ClassifierLayer) -> bool {
        let (events, _rx) = crate::event_stream();
        smol::block_on(manager.enforce(
            &ToolKey::native("read"),
            &PermissionScopes::single("/tmp/input".into()),
            None,
            &events.sender(0),
            None,
            TAGGED_REQUEST_ID,
            &CancelToken::none(),
            None,
            None,
            Some(layer),
        ))
        .is_ok()
    }

    fn classifier_layer(reuse: bool) -> ClassifierLayer {
        ClassifierLayer {
            binding: json!({"session":"one", "authorization_revision":"1:2", "cwd":"/tmp", "input":{"path":"/tmp/input"}}),
            verdict: LayerVerdict::ClassifierAllow {
                policy_version: "test-v1".into(),
                grant: !reuse,
                reuse,
                denial_limit: 3,
            },
        }
    }

    #[test]
    fn classifier_exact_grants_are_volatile_and_bound() {
        let manager = default_mgr();
        assert!(classifier_call(&manager, &classifier_layer(false)));
        assert!(classifier_call(&manager, &classifier_layer(true)));
        for (field, value) in [
            ("cwd", json!("/other")),
            ("session", json!("two")),
            ("authorization_revision", json!("2:2")),
            ("input", json!({"path":"/other"})),
        ] {
            let mut changed = classifier_layer(true);
            changed.binding[field] = value;
            assert!(!classifier_call(&manager, &changed), "{field}");
        }
        assert!(manager.session_rules_snapshot().is_empty());
        assert!(!classifier_call(&manager.fork(), &classifier_layer(true)));
    }

    #[test]
    fn classifier_grant_expiration_policy_and_deny() {
        let manager = default_mgr();
        assert!(classifier_call(&manager, &classifier_layer(false)));
        manager.classifier.lock().unwrap().grants[0].1 = Instant::now() - CLASSIFIER_GRANT_TTL;
        assert!(!classifier_call(&manager, &classifier_layer(true)));
        assert!(classifier_call(&manager, &classifier_layer(false)));
        manager.plugin_rules.replace(LAYER_PLUGIN, Vec::new());
        assert!(!classifier_call(&manager, &classifier_layer(true)));
        assert!(classifier_call(&manager, &classifier_layer(false)));
        manager.add_session_rule(PermissionRule {
            tool: ToolKey::native("read"),
            scope: None,
            effect: Effect::Deny,
        });
        assert!(!classifier_call(&manager, &classifier_layer(true)));
    }

    #[test]
    fn classifier_denials_and_resets_follow_observed_order() {
        let manager = default_mgr();
        manager.set_classifier_denial_limit(2);
        let mut deny = classifier_layer(false);
        deny.verdict = LayerVerdict::ClassifierDeny {
            guidance: None,
            denial_limit: 2,
        };
        assert!(!classifier_call(&manager, &deny));
        manager.successful_tool_completion();
        assert!(!classifier_call(&manager, &deny));
        assert_eq!(manager.classifier.lock().unwrap().denials, 1);
        assert!(!classifier_call(&manager, &deny));
        assert!(!classifier_call(&manager, &classifier_layer(false)));
        manager.successful_tool_completion();
        assert!(classifier_call(&manager, &classifier_layer(false)));
        assert!(!classifier_call(&manager, &deny));
        manager.successful_tool_completion();
        assert_eq!(manager.classifier.lock().unwrap().denials, 0);
    }

    #[test]
    fn classifier_human_answer_resets_but_unattended_does_not() {
        let manager = default_mgr();
        manager.set_classifier_denial_limit(1);
        manager.classifier.lock().unwrap().denials = 1;
        assert!(!classifier_call(&manager, &classifier_layer(false)));
        assert_eq!(manager.classifier.lock().unwrap().denials, 1);
        let (events, _rx) = crate::event_stream();
        let (tx, rx) = flume::unbounded();
        tx.send(TaggedAnswer::new(TAGGED_REQUEST_ID, PermissionAnswer::AllowOnce).encode())
            .unwrap();
        let rx = smol::lock::Mutex::new(rx);
        let layer = classifier_layer(false);
        let result = smol::block_on(manager.enforce(
            &ToolKey::native("read"),
            &PermissionScopes::single("/tmp/input".into()),
            None,
            &events.sender(0),
            Some(&rx),
            TAGGED_REQUEST_ID,
            &CancelToken::none(),
            None,
            None,
            Some(&layer),
        ));
        assert!(result.is_ok());
        assert_eq!(manager.classifier.lock().unwrap().denials, 0);
    }

    #[test_case(true ; "success_after_deny_resets")]
    #[test_case(false ; "deny_after_success_counts")]
    fn classifier_concurrent_outcomes_have_completion_order(success_last: bool) {
        let manager = default_mgr();
        let (tx, rx) = flume::bounded::<()>(1);
        std::thread::scope(|scope| {
            let first = scope.spawn(|| {
                if success_last {
                    let mut layer = classifier_layer(false);
                    layer.verdict = LayerVerdict::ClassifierDeny {
                        guidance: None,
                        denial_limit: 3,
                    };
                    assert!(!classifier_call(&manager, &layer));
                } else {
                    manager.successful_tool_completion();
                }
                tx.send(()).unwrap();
            });
            let second = scope.spawn(|| {
                rx.recv().unwrap();
                if success_last {
                    manager.successful_tool_completion();
                } else {
                    let mut layer = classifier_layer(false);
                    layer.verdict = LayerVerdict::ClassifierDeny {
                        guidance: None,
                        denial_limit: 3,
                    };
                    assert!(!classifier_call(&manager, &layer));
                }
            });
            first.join().unwrap();
            second.join().unwrap();
        });
        assert_eq!(
            manager.classifier_denials_for_test(None),
            usize::from(!success_last)
        );
    }

    struct GuardedClassifier;

    impl PromptLayers for GuardedClassifier {
        fn requires_human(&self) -> bool {
            true
        }
        fn answer<'a>(&'a self, _scopes: &'a [String]) -> BoxFuture<'a, Option<LayerAnswer>> {
            Box::pin(std::future::ready(Some(LayerAnswer {
                plugin: Arc::from(LAYER_PLUGIN),
                verdict: LayerVerdict::ClassifierAllow {
                    policy_version: "test-v1".into(),
                    grant: true,
                    reuse: false,
                    denial_limit: 3,
                },
            })))
        }
    }

    #[test]
    fn classifier_cannot_override_changed_guard() {
        let manager = default_mgr();
        let (events, _rx) = crate::event_stream();
        let result = smol::block_on(manager.enforce(
            &ToolKey::native("read"),
            &PermissionScopes::single("/tmp/input".into()),
            None,
            &events.sender(0),
            None,
            TAGGED_REQUEST_ID,
            &CancelToken::none(),
            None,
            None,
            Some(&GuardedClassifier),
        ));
        assert!(result.is_err());
        assert!(manager.classifier.lock().unwrap().grants.is_empty());
    }

    #[test]
    fn classifier_resume_discards_runtime_state() {
        let manager = default_mgr();
        assert!(classifier_call(&manager, &classifier_layer(false)));
        manager.load_session_rules(Vec::new());
        assert!(!classifier_call(&manager, &classifier_layer(true)));
    }

    const COVERED_SCOPE: &str = "git status";

    struct MetadataLayer<'a> {
        manager: &'a PermissionManager,
        late_deny: Option<bool>,
    }

    impl PromptLayers for MetadataLayer<'_> {
        fn answer<'a>(&'a self, _scopes: &'a [String]) -> BoxFuture<'a, Option<LayerAnswer>> {
            panic!("metadata method must be used")
        }

        fn answer_with_metadata<'a>(
            &'a self,
            scopes: &'a [String],
            metadata: &'a Value,
        ) -> BoxFuture<'a, Option<LayerAnswer>> {
            Box::pin(async move {
                assert_eq!(scopes, &[LAYER_SCOPE]);
                assert_eq!(metadata["all_scopes"], json!([COVERED_SCOPE, LAYER_SCOPE]));
                assert_eq!(metadata["policy"]["complete"], true);
                assert_eq!(metadata["subject_kind"], "shell_scope");
                assert_eq!(metadata["subjects_resolved"], false);
                if let Some(plugin) = self.late_deny {
                    let rule = deny_rule(COVERED_SCOPE);
                    if plugin {
                        self.manager.plugin_rules.replace(LAYER_PLUGIN, vec![rule]);
                    } else {
                        self.manager.add_session_rule(rule);
                    }
                }
                Some(LayerAnswer {
                    plugin: Arc::from(LAYER_PLUGIN),
                    verdict: LayerVerdict::Allow,
                })
            })
        }
    }

    #[test_case(None, true ; "full_scopes_and_unresolved_scopes_are_separate")]
    #[test_case(Some(false), false ; "late_session_deny_on_previously_allowed_scope_wins")]
    #[test_case(Some(true), false ; "late_plugin_deny_on_previously_allowed_scope_wins")]
    fn metadata_and_late_deny(late_deny: Option<bool>, allowed: bool) {
        let mgr = mgr_with(
            make_config(vec![allow_rule(COVERED_SCOPE)]),
            PathBuf::from(TEST_CWD),
        );
        let layer = MetadataLayer {
            manager: &mgr,
            late_deny,
        };
        let scopes = PermissionScopes {
            scopes: vec![COVERED_SCOPE.to_owned(), LAYER_SCOPE.to_owned()],
            force_prompt: false,
        };
        let (guard, _events) = crate::event_stream();
        let result = smol::block_on(mgr.enforce(
            &ToolKey::native(BASH_TOOL),
            &scopes,
            None,
            &guard.sender(0),
            None,
            TAGGED_REQUEST_ID,
            &CancelToken::none(),
            None,
            None,
            Some(&layer),
        ));
        assert_eq!(result.is_ok(), allowed, "{result:?}");
        if !allowed {
            assert!(result.unwrap_err().to_string().contains(COVERED_SCOPE));
        }
    }

    #[test]
    fn oversized_policy_is_explicitly_incomplete() {
        let scope = "x".repeat(PROMPT_POLICY_MAX_BYTES);
        let mgr = mgr_with(
            make_config(vec![allow_rule(&scope)]),
            PathBuf::from(TEST_CWD),
        );
        let metadata = mgr.prompt_metadata(
            &ToolKey::native(BASH_TOOL),
            &PermissionScopes::single(LAYER_SCOPE.to_owned()),
        );
        assert_eq!(
            metadata["policy"],
            json!({"complete": false, "reason": "policy_size_limit"})
        );
        assert_eq!(metadata["all_scopes"], json!([LAYER_SCOPE]));
    }

    #[test]
    fn metadata_includes_live_rule_origins_and_defaults() {
        let mgr = mgr_with(
            make_config(vec![allow_rule(COVERED_SCOPE)]),
            PathBuf::from(TEST_CWD),
        );
        mgr.add_session_rule(deny_rule(LAYER_SCOPE));
        mgr.plugin_rules
            .replace(LAYER_PLUGIN, vec![allow_rule("pwd")]);
        let metadata = mgr.prompt_metadata(
            &ToolKey::native(BASH_TOOL),
            &PermissionScopes::single(LAYER_SCOPE.to_owned()),
        );
        let rules = metadata["policy"]["rules"].as_array().expect("rules");
        for origin in [ORIGIN_CONFIG, ORIGIN_BUILTIN, ORIGIN_SESSION, ORIGIN_PLUGIN] {
            assert!(
                rules.iter().any(|rule| rule["origin"] == origin),
                "{origin}"
            );
        }
        assert_eq!(metadata["policy"]["default"], "prompt");
        assert_eq!(metadata["candidate_rules"][0]["scope"], LAYER_SCOPE);
    }

    struct Layer(Option<LayerVerdict>);

    impl PromptLayers for Layer {
        fn answer<'a>(&'a self, _scopes: &'a [String]) -> BoxFuture<'a, Option<LayerAnswer>> {
            let answer = self.0.clone().map(|verdict| LayerAnswer {
                plugin: Arc::from(LAYER_PLUGIN),
                verdict,
            });
            Box::pin(std::future::ready(answer))
        }
    }

    /// No answer channel, like `maki -p`, so whatever the layer leaves to the
    /// prompt gets denied.
    fn enforce_behind(
        mgr: &PermissionManager,
        layer: Layer,
        ask: Option<&str>,
    ) -> Result<Option<Arc<str>>, PermissionError> {
        let (guard, _events) = crate::event_stream();
        smol::block_on(mgr.enforce(
            &ToolKey::native(BASH_TOOL),
            &crate::tools::PermissionScopes::single(LAYER_SCOPE.to_owned()),
            None,
            &guard.sender(0),
            None,
            TAGGED_REQUEST_ID,
            &crate::CancelToken::none(),
            None,
            ask,
            Some(&layer),
        ))
    }

    /// The next call on the same scope still prompts, so an allow saved no
    /// rule that could cover calls the layer never saw.
    #[test_case(Some(LayerVerdict::Allow), true ; "allow")]
    #[test_case(Some(LayerVerdict::Deny { guidance: None }), false ; "deny")]
    #[test_case(None, false ; "no_answer_falls_to_the_prompt")]
    fn a_layer_answers_in_place_of_the_prompt(verdict: Option<LayerVerdict>, allowed: bool) {
        let mgr = default_mgr();
        let result = enforce_behind(&mgr, Layer(verdict), None);
        assert_eq!(result.is_ok(), allowed, "{result:?}");
        assert_eq!(
            result.unwrap_or_default().is_some(),
            allowed,
            "an allow has to name the plugin, so the call can be marked"
        );
        assert_eq!(
            outcome(mgr.check(&ToolKey::native(BASH_TOOL), LAYER_SCOPE, None)),
            PROMPTS
        );
    }

    /// Another plugin sent this call to a human on purpose, so no layer may
    /// answer it, whichever way it would go.
    #[test_case(LayerVerdict::Allow ; "allow")]
    #[test_case(LayerVerdict::Deny { guidance: None } ; "deny")]
    fn an_escalated_call_never_reaches_a_layer(verdict: LayerVerdict) {
        let result = enforce_behind(&default_mgr(), Layer(Some(verdict)), Some(ESCALATION));
        let err = result
            .expect_err("no channel, so the prompt cannot answer")
            .to_string();
        assert!(!err.contains(LAYER_PLUGIN), "a layer answered: {err}");
    }

    /// The guidance can echo the input the plugin judged, so the agent has to
    /// know it came from the plugin rather than the user.
    #[test_case(None, DEFAULT_DENY_GUIDANCE ; "bare")]
    #[test_case(Some(LAYER_GUIDANCE.to_owned()), LAYER_GUIDANCE ; "with_guidance")]
    fn a_layer_deny_is_labelled_by_plugin(guidance: Option<String>, expected: &str) {
        let result = enforce_behind(
            &default_mgr(),
            Layer(Some(LayerVerdict::Deny { guidance })),
            None,
        );
        let err = result.expect_err("a deny").to_string();
        assert!(
            err.contains(&format!("Plugin `{LAYER_PLUGIN}` denied it")),
            "{err}"
        );
        assert!(err.contains(expected), "{err}");
    }
}
