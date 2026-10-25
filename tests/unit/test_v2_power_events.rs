//! State resolution v2 power-event classification.
//!
//! The spec defines a power event as `m.room.power_levels`, `m.room.join_rules`,
//! or an `m.room.member` with membership `leave` or `ban` whose `sender` is not
//! its `state_key` (a kick or ban). The definition is the same for v2 and v2.1:
//! a user's own join or profile change is not a power event, so it is ordered
//! by the mainline ordering (mainline position, `origin_server_ts`, `event_id`)
//! rather than by the reverse topological power ordering.

use crate::utils;
use crate::utils::to_event_map;

use rezzy::basespec::event_types::EventType;
use rezzy::resolve::semilattice::resolve_semilattice_fold;
use rezzy::{LeanEvent, PersistentOrdMap, StateResVersion};
use std::collections::HashMap;

const ALICE: &str = "@alice:a.com";
const BOB: &str = "@bob:b.com";

const ROOM: &str = r#"
{"event_id":"$create","type":"m.room.create","state_key":"","sender":"@alice:a.com","depth":0,"origin_server_ts":1000,"content":{"creator":"@alice:a.com","room_version":"10"},"prev_events":[],"auth_events":[]}
{"event_id":"$alice_join","type":"m.room.member","state_key":"@alice:a.com","sender":"@alice:a.com","depth":1,"origin_server_ts":1001,"content":{"membership":"join"},"prev_events":["$create"],"auth_events":["$create"]}
{"event_id":"$pl","type":"m.room.power_levels","state_key":"","sender":"@alice:a.com","depth":2,"origin_server_ts":1002,"content":{"users":{"@alice:a.com":100},"events_default":0,"state_default":50,"ban":50,"kick":50,"invite":0},"prev_events":["$alice_join"],"auth_events":["$create","$alice_join"]}
{"event_id":"$jr","type":"m.room.join_rules","state_key":"","sender":"@alice:a.com","depth":3,"origin_server_ts":1003,"content":{"join_rule":"public"},"prev_events":["$pl"],"auth_events":["$create","$alice_join","$pl"]}
{"event_id":"$bob_join","type":"m.room.member","state_key":"@bob:b.com","sender":"@bob:b.com","depth":4,"origin_server_ts":1010,"content":{"membership":"join"},"prev_events":["$jr"],"auth_events":["$create","$pl","$jr"]}
"#;

/// Bob's profile changes A -> B -> C -> D -> E, each authed by the one before.
/// B has the lexicographically largest event ID, as in the Complement run
/// where Synapse's Python resolver and gomatrixserverlib both picked B.
const CHAIN: [(&str, &str); 5] = [
    ("A", "$m_a"),
    ("B", "$m_z"),
    ("C", "$m_c"),
    ("D", "$m_d"),
    ("E", "$m_e"),
];

fn member(
    id: &str,
    sender: &str,
    state_key: &str,
    content: &str,
    ts: u64,
    auth: &[&str],
) -> LeanEvent {
    let auth = auth
        .iter()
        .map(|a| format!("\"{a}\""))
        .collect::<Vec<_>>()
        .join(",");
    let line = format!(
        r#"{{"event_id":"{id}","type":"m.room.member","state_key":"{state_key}","sender":"{sender}","depth":5,"origin_server_ts":{ts},"content":{content},"prev_events":["$jr"],"auth_events":[{auth}]}}"#
    );
    utils::parse_jsonl_events(&line).remove(0)
}

fn room_with_chain(tied: bool) -> HashMap<String, LeanEvent> {
    let mut events = utils::parse_jsonl_events(ROOM);
    let mut prev = "$bob_join";
    for ((name, id), distinct_ts) in CHAIN.iter().zip(2000_u64..) {
        let ts = if tied { 2000 } else { distinct_ts };
        let content = format!(r#"{{"membership":"join","displayname":"{name}"}}"#);
        events.push(member(
            id,
            BOB,
            BOB,
            &content,
            ts,
            &["$create", "$pl", "$jr", prev],
        ));
        prev = id;
    }
    to_event_map(&events)
}

fn bob_key() -> (EventType, String) {
    (EventType::from("m.room.member"), BOB.to_string())
}

/// Our state still has Bob's original join; theirs has E at the end of the chain.
fn fork_states() -> Vec<PersistentOrdMap<(EventType, String), String>> {
    let mut common = PersistentOrdMap::new();
    common.insert(
        (EventType::from("m.room.create"), String::new()),
        "$create".to_string(),
    );
    common.insert(
        (EventType::from("m.room.member"), ALICE.to_string()),
        "$alice_join".to_string(),
    );
    common.insert(
        (EventType::from("m.room.power_levels"), String::new()),
        "$pl".to_string(),
    );
    common.insert(
        (EventType::from("m.room.join_rules"), String::new()),
        "$jr".to_string(),
    );
    let mut ours = common.clone();
    ours.insert(bob_key(), "$bob_join".to_string());
    let mut theirs = common;
    theirs.insert(bob_key(), "$m_e".to_string());
    vec![ours, theirs]
}

fn name_of(event_id: &str) -> &str {
    CHAIN
        .iter()
        .find(|(_, id)| *id == event_id)
        .map_or(event_id, |(name, _)| name)
}

// ============================================================================
// is_power_event
// ============================================================================

fn assert_power_event_classification(version: StateResVersion) {
    let auth = ["$create", "$pl", "$jr"];
    let cases = [
        (
            "own join",
            member("$j", BOB, BOB, r#"{"membership":"join"}"#, 1, &auth),
            false,
        ),
        (
            "own profile change",
            member(
                "$p",
                BOB,
                BOB,
                r#"{"membership":"join","displayname":"Bob"}"#,
                1,
                &auth,
            ),
            false,
        ),
        (
            "own leave",
            member("$l", BOB, BOB, r#"{"membership":"leave"}"#, 1, &auth),
            false,
        ),
        (
            "invite",
            member("$i", ALICE, BOB, r#"{"membership":"invite"}"#, 1, &auth),
            false,
        ),
        (
            "kick",
            member("$k", ALICE, BOB, r#"{"membership":"leave"}"#, 1, &auth),
            true,
        ),
        (
            "ban",
            member("$b", ALICE, BOB, r#"{"membership":"ban"}"#, 1, &auth),
            true,
        ),
    ];
    for (name, ev, want) in cases {
        assert_eq!(ev.is_power_event(version), want, "{name} under {version:?}");
    }
}

#[test]
fn test_v2_membership_power_events_follow_spec() {
    assert_power_event_classification(StateResVersion::V2);
}

#[test]
fn test_v2_1_membership_power_events_follow_spec() {
    assert_power_event_classification(StateResVersion::V2_1);
}

// ============================================================================
// End-to-end: A-E profile-change chain (Complement
// TestStateIdsFallbackFetchesFullAuthChain, room version 10)
// ============================================================================

/// With distinct timestamps, E is last in mainline order under any reading.
#[test]
fn test_v2_profile_chain_distinct_timestamps_resolves_to_last() {
    let map = room_with_chain(false);
    let resolved = rezzy::resolve_state_maps(&fork_states(), &map, StateResVersion::V2);
    assert_eq!(name_of(&resolved[&bob_key()]), "E");
}

/// A-E are in the auth difference, so they join the full conflicted set. As
/// non-power events with one mainline position and one timestamp, `event_id`
/// orders them, and the largest (B) is applied last and wins. Synapse's Python
/// v2 resolver and gomatrixserverlib both return B here.
#[test]
fn test_v2_profile_chain_tied_timestamps_orders_by_event_id() {
    let map = room_with_chain(true);
    let resolved = rezzy::resolve_state_maps(&fork_states(), &map, StateResVersion::V2);
    assert_eq!(name_of(&resolved[&bob_key()]), "B");
}

/// The same fork through the lattice fold, given the full conflicted set as
/// Synapse passes it (`resolve_v2_via_lattice_fold`).
#[test]
fn test_v2_lattice_fold_profile_chain_tied_timestamps_orders_by_event_id() {
    let map = room_with_chain(true);
    let mut unconflicted = fork_states().remove(0);
    unconflicted.remove(&bob_key());
    let mut conflicted = HashMap::new();
    for id in ["$bob_join", "$m_a", "$m_z", "$m_c", "$m_d", "$m_e"] {
        conflicted.insert(id.to_string(), map[id].clone());
    }
    let resolved = resolve_semilattice_fold(&unconflicted, &conflicted, &map, StateResVersion::V2);
    assert_eq!(name_of(&resolved[&bob_key()]), "B");
}

/// v2 and v2.1 share the power-event definition and the mainline ordering, and
/// both put A-E in the full conflicted set, so they agree on this fork.
#[test]
fn test_v2_and_v2_1_agree_on_tied_profile_chain() {
    let map = room_with_chain(true);
    let v2 = rezzy::resolve_state_maps(&fork_states(), &map, StateResVersion::V2);
    let v2_1 = rezzy::resolve_state_maps(&fork_states(), &map, StateResVersion::V2_1);
    assert_eq!(name_of(&v2[&bob_key()]), name_of(&v2_1[&bob_key()]));
}
