use std::sync::Arc;

use arc_swap::ArcSwap;
use maki_agent::agent::{History, HistorySnapshot, SharedMessages, publish_live_history};
use maki_agent::tools::registry::ToolRegistry;
use maki_lua::{Interaction, PluginHost};
use maki_providers::{Message, Role};
use maki_storage::id::MakiId;
use test_case::test_case;

const FIRST_PROMPT: &str = "Print the synthetic fixture marker with literal printf.";
const SECOND_PROMPT: &str = "Read the second synthetic fixture only.";
const BYTE_BUDGET: usize = 16384;

fn live_history(text: &str) -> (MakiId, History, SharedMessages) {
    let id = MakiId::generate();
    let mirror = Arc::new(ArcSwap::from_pointee(HistorySnapshot::new(Vec::new())));
    let mut history = History::new(Vec::new()).with_mirror(Arc::clone(&mirror));
    history.push(Message {
        human_prompt: Some(text.into()),
        ..Message::user(text.into())
    });
    publish_live_history(id, &mirror);

    (id, history, mirror)
}

fn assert_snapshot(
    host: &PluginHost,
    session: MakiId,
    budget: usize,
    complete: bool,
    expected: &[&str],
) -> Result<(), Box<dyn std::error::Error>> {
    let expected = serde_json::to_string(expected)?;
    let source = format!(
        r#"
local history, err = maki.session.user_prompts({{session = "{session}", max_bytes = {budget}}})
assert(err == nil and history ~= nil, "named live history unavailable")
assert(history.session == "{session}", "wrong originating session")
assert(history.complete == {complete}, "unexpected history completeness")
assert(type(history.revision) == "string" and #history.revision > 0, "missing revision")
local expected = maki.json.decode([==[{expected}]==])
assert(#history.prompts == #expected, "unexpected prompt count")
for index, prompt in ipairs(expected) do
    assert(history.prompts[index] == prompt, "prompt ordering or isolation failure")
end
"#
    );
    host.load_source("plan13-history-assertion", &source)?;

    Ok(())
}

#[test]
fn published_session_snapshots_are_isolated_by_explicit_id()
-> Result<(), Box<dyn std::error::Error>> {
    let host = PluginHost::start(Arc::new(ToolRegistry::new()), Interaction::None, false)?;
    let (first, mut first_history, _first_mirror) = live_history(FIRST_PROMPT);
    let (second, _second_history, _second_mirror) = live_history(SECOND_PROMPT);
    first_history.push(Message {
        role: Role::Assistant,
        ..Message::user("Synthetic assistant instructions are not authorization.".into())
    });
    assert_snapshot(&host, first, BYTE_BUDGET, true, &[FIRST_PROMPT])?;
    assert_snapshot(&host, second, BYTE_BUDGET, true, &[SECOND_PROMPT])?;
    first_history.truncate(0);
    assert_snapshot(&host, first, BYTE_BUDGET, false, &[])?;
    assert_snapshot(&host, second, BYTE_BUDGET, true, &[SECOND_PROMPT])?;

    Ok(())
}

#[test_case(false; "replacement")]
#[test_case(true; "serialized_resume")]
fn replaced_history_fails_closed(resume: bool) -> Result<(), Box<dyn std::error::Error>> {
    let host = PluginHost::start(Arc::new(ToolRegistry::new()), Interaction::None, false)?;
    let (id, mut history, mirror) = live_history(FIRST_PROMPT);
    assert_snapshot(&host, id, BYTE_BUDGET, true, &[FIRST_PROMPT])?;
    history.replace(history.as_slice().to_vec());
    if resume {
        let serialized = serde_json::to_vec(history.as_slice())?;
        history = History::restored(serde_json::from_slice(&serialized)?)
            .with_mirror(Arc::clone(&mirror));
    }
    assert_snapshot(&host, id, BYTE_BUDGET, false, &[])?;
    assert!(
        history
            .as_slice()
            .iter()
            .all(|message| message.human_prompt.is_none())
    );

    Ok(())
}

#[test]
fn oversized_history_returns_no_partial_authorization() -> Result<(), Box<dyn std::error::Error>> {
    let host = PluginHost::start(Arc::new(ToolRegistry::new()), Interaction::None, false)?;
    let (id, _history, _mirror) = live_history(FIRST_PROMPT);
    assert_snapshot(&host, id, FIRST_PROMPT.len() - 1, false, &[])?;

    Ok(())
}

#[test]
fn unmarked_snapshot_turn_and_missing_session_fail_closed() -> Result<(), Box<dyn std::error::Error>>
{
    let host = PluginHost::start(Arc::new(ToolRegistry::new()), Interaction::None, false)?;
    let (id, mut history, _mirror) = live_history(FIRST_PROMPT);
    history.push(Message::user(SECOND_PROMPT.into()));
    assert_snapshot(&host, id, BYTE_BUDGET, false, &[FIRST_PROMPT])?;
    let missing = MakiId::generate();
    host.load_source(
        "plan13-missing-session",
        &format!(
            r#"
local value, err = maki.session.user_prompts({{session = "{missing}", max_bytes = {BYTE_BUDGET}}})
assert(value == nil and type(err) == "string", "missing session must fail closed")
local implicit, implicit_err = maki.session.user_prompts({{max_bytes = {BYTE_BUDGET}}})
assert(implicit == nil and type(implicit_err) == "string", "implicit session must be rejected")
"#
        ),
    )?;

    Ok(())
}
