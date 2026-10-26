//! Large-room benchmark for V2 auth-difference resolution.
//!
//! Measures the eager resolver, lazy resolver with an internally computed
//! auth difference, and lazy resolver with a precomputed auth difference.
//! The public eager API has no precomputed-diff argument, so there is no
//! eager/precomputed variant.
//!
//! Run with `cargo +1.90.0 bench --manifest-path benches/Cargo.toml --bench
//! rezzy -- auth_difference`.

use std::collections::HashMap;
use std::hint::black_box;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use rezzy::basespec::event_types::EventType;
use rezzy::basespec::rezzy_types::EventProvider;
use rezzy::{JsonValue, LeanEvent, PersistentOrdMap, StateResVersion};

type StateMap = PersistentOrdMap<(EventType, String), String>;

struct Fixture {
    events: HashMap<String, LeanEvent>,
    forks: [StateMap; 2],
    auth_diff: Vec<String>,
}

struct CountingProvider<'a> {
    events: &'a HashMap<String, LeanEvent>,
    lookups: AtomicUsize,
}

impl EventProvider<String, JsonValue> for CountingProvider<'_> {
    fn get_event(&self, id: &String) -> Option<&LeanEvent> {
        self.lookups.fetch_add(1, Ordering::Relaxed);
        self.events.get(id)
    }
}

impl CountingProvider<'_> {
    fn reset(&self) {
        self.lookups.store(0, Ordering::Relaxed);
    }

    fn lookups(&self) -> usize {
        self.lookups.load(Ordering::Relaxed)
    }
}

fn event(
    id: String,
    event_type: &str,
    state_key: &str,
    sender: &str,
    depth: u64,
    origin_server_ts: u64,
    content: JsonValue,
    auth_events: Vec<String>,
) -> LeanEvent {
    LeanEvent {
        event_id: id,
        event_type: event_type.to_string(),
        state_key: Some(state_key.to_string()),
        sender: sender.to_string(),
        content,
        auth_events,
        depth,
        origin_server_ts,
        ..LeanEvent::default()
    }
}

fn state_key(event_type: &str, state_key: &str) -> (EventType, String) {
    (EventType::from(event_type), state_key.to_string())
}

fn build_fixture(common_members: usize, auth_chain_len: usize) -> Fixture {
    let alice = "@alice:example.com";
    let bob = "@bob:example.com";
    let create = "$create".to_string();
    let alice_join = "$alice_join".to_string();
    let bob_join = "$bob_join".to_string();
    let pl = "$pl".to_string();
    let jr = "$jr".to_string();
    let base_auth = vec![create.clone(), alice_join.clone(), pl.clone(), jr.clone()];

    let mut events = HashMap::with_capacity(common_members + (2 * auth_chain_len) + 16);
    events.insert(
        create.clone(),
        event(
            create.clone(),
            "m.room.create",
            "",
            alice,
            0,
            1_000,
            rezzy::json!({"creator": alice, "room_version": "11"}),
            vec![],
        ),
    );
    events.insert(
        alice_join.clone(),
        event(
            alice_join.clone(),
            "m.room.member",
            alice,
            alice,
            1,
            1_001,
            rezzy::json!({"membership": "join"}),
            vec![create.clone()],
        ),
    );
    events.insert(
        pl.clone(),
        event(
            pl.clone(),
            "m.room.power_levels",
            "",
            alice,
            2,
            1_002,
            rezzy::json!({
                "users": { "@alice:example.com": 100 },
                "events_default": 0,
                "state_default": 0,
                "ban": 50,
                "kick": 50,
                "invite": 0
            }),
            vec![create.clone(), alice_join.clone()],
        ),
    );
    events.insert(
        jr.clone(),
        event(
            jr.clone(),
            "m.room.join_rules",
            "",
            alice,
            3,
            1_003,
            rezzy::json!({"join_rule": "public"}),
            vec![create.clone(), alice_join.clone(), pl.clone()],
        ),
    );
    events.insert(
        bob_join.clone(),
        event(
            bob_join.clone(),
            "m.room.member",
            bob,
            bob,
            4,
            1_004,
            rezzy::json!({"membership": "join"}),
            base_auth.clone(),
        ),
    );

    let mut common = StateMap::new();
    for (event_type, key, id) in [
        ("m.room.create", "", &create),
        ("m.room.member", alice, &alice_join),
        ("m.room.power_levels", "", &pl),
        ("m.room.join_rules", "", &jr),
        ("m.room.member", bob, &bob_join),
    ] {
        common.insert(state_key(event_type, key), id.clone());
    }

    // Model a large room state without making the auth difference itself
    // large. Each current member event is an unconflicted root, which is the
    // shape that stresses auth-difference setup across the room's state.
    for index in 0..common_members {
        let user = format!("@member{index}:example.com");
        let id = format!("$member{index}");
        events.insert(
            id.clone(),
            event(
                id.clone(),
                "m.room.member",
                &user,
                &user,
                5,
                2_000 + index as u64,
                rezzy::json!({"membership": "join"}),
                vec![create.clone(), pl.clone(), jr.clone()],
            ),
        );
        common.insert(state_key("m.room.member", &user), id);
    }

    let mut auth_diff = Vec::with_capacity(2 * auth_chain_len);
    let mut topic_ids = Vec::with_capacity(2);
    for branch in ['a', 'b'] {
        let mut previous = bob_join.clone();
        for index in 0..auth_chain_len {
            let id = format!("$branch_{branch}_{index}");
            let mut auth_events = base_auth.clone();
            auth_events.push(previous.clone());
            let ev = event(
                id.clone(),
                "m.room.member",
                bob,
                bob,
                5 + index as u64,
                3_000 + index as u64,
                rezzy::json!({"membership": "join", "displayname": format!("{branch}-{index}")}),
                auth_events,
            );
            events.insert(id.clone(), ev);
            auth_diff.push(id.clone());
            previous = id;
        }

        let topic_id = format!("$topic_{branch}");
        let mut topic_auth = base_auth.clone();
        topic_auth.push(previous);
        events.insert(
            topic_id.clone(),
            event(
                topic_id.clone(),
                "m.room.topic",
                "",
                alice,
                6 + auth_chain_len as u64,
                4_000 + (branch == 'b') as u64,
                rezzy::json!({"topic": format!("branch {branch}")}),
                topic_auth,
            ),
        );
        topic_ids.push(topic_id);
    }

    let topic_key = state_key("m.room.topic", "");
    let mut forks = [common.clone(), common];
    forks[0].insert(topic_key.clone(), topic_ids[0].clone());
    forks[1].insert(topic_key, topic_ids[1].clone());

    Fixture {
        events,
        forks,
        auth_diff,
    }
}

fn time_case(
    label: &str,
    iterations: usize,
    mut run: impl FnMut() -> usize,
    lookups: Option<&CountingProvider<'_>>,
) {
    run(); // warm up and verify that the path completes before timing
    if let Some(provider) = lookups {
        provider.reset();
    }
    let start = Instant::now();
    let mut result_size = 0;
    for _ in 0..iterations {
        result_size = black_box(run());
    }
    let elapsed = start.elapsed();
    let avg_ms = elapsed.as_secs_f64() * 1_000.0 / iterations as f64;
    let fetches = lookups.map_or_else(
        || "n/a".to_string(),
        |p| (p.lookups() / iterations).to_string(),
    );
    println!(
        "{label}: {avg_ms:.3} ms/op, provider lookups/op={fetches}, result entries={result_size}"
    );
}

/// Runs large-room auth-difference timings for the concrete and lazy APIs.
pub fn run() {
    for (members, chain_len, iterations) in [(1_000, 32, 5), (10_000, 64, 3)] {
        println!(
            "\n--- auth_difference: {members} common members, {chain_len} events per branch ---"
        );
        let fixture = build_fixture(members, chain_len);
        let provider = CountingProvider {
            events: &fixture.events,
            lookups: AtomicUsize::new(0),
        };

        time_case(
            "concrete/computed-diff",
            iterations,
            || {
                rezzy::resolve_state_maps(&fixture.forks, &fixture.events, StateResVersion::V2)
                    .len()
            },
            None,
        );
        time_case(
            "lazy/computed-diff",
            iterations,
            || {
                rezzy::resolve_state_maps_lazy_with_diff(
                    &fixture.forks,
                    &provider,
                    None::<Vec<String>>,
                    StateResVersion::V2,
                )
                .len()
            },
            Some(&provider),
        );
        time_case(
            "lazy/precomputed-diff",
            iterations,
            || {
                rezzy::resolve_state_maps_lazy_with_diff(
                    &fixture.forks,
                    &provider,
                    Some(fixture.auth_diff.iter().cloned()),
                    StateResVersion::V2,
                )
                .len()
            },
            Some(&provider),
        );

        // A caller-held AuthGraph: built once, outside the timing, as a server
        // would keep it per room. Only the per-resolution diff is timed.
        let build_start = Instant::now();
        let graph = rezzy::auth::roaring::AuthGraph::try_build(&fixture.events)
            .expect("fixture is auth-closed");
        let build_ms = build_start.elapsed().as_secs_f64() * 1_000.0;
        // Encoded size is a lower bound on the in-memory size, which adds
        // per-bitmap Vec and per-chunk Arc overhead plus the id index.
        let encoded: usize = graph.auth_bitmaps.iter().map(|b| b.encode().len()).sum();
        let ancestors: u64 = graph
            .auth_bitmaps
            .iter()
            .map(rezzy::bitmap::Bitmap::len)
            .sum();
        println!(
            "auth-graph build (once): {build_ms:.3} ms, {} events, {} ancestor bits, \
             encoded bitmaps {:.1} KiB ({:.0} B/event)",
            graph.auth_bitmaps.len(),
            ancestors,
            encoded as f64 / 1024.0,
            encoded as f64 / graph.auth_bitmaps.len() as f64
        );
        time_case(
            "auth-graph/diff-only",
            iterations,
            || graph.state_auth_difference(&fixture.forks).len(),
            None,
        );
        time_case(
            "lazy/auth-graph-diff",
            iterations,
            || {
                rezzy::resolve_state_maps_lazy_with_diff(
                    &fixture.forks,
                    &provider,
                    Some(graph.state_auth_difference(&fixture.forks)),
                    StateResVersion::V2,
                )
                .len()
            },
            Some(&provider),
        );

        // Hybrid: a graph missing the newest fraction of events (a topological
        // suffix, as when recent events are not inserted yet), the rest walked
        // through the provider.
        for missing_pct in [0, 1, 10, 50, 100] {
            let order = graph.index.items();
            let keep = order.len() * (100 - missing_pct) / 100;
            let mut partial =
                rezzy::auth::roaring::AuthGraph::try_build(&HashMap::<String, LeanEvent>::new())
                    .expect("empty set is auth-closed");
            let insert_start = Instant::now();
            for id in &order[..keep] {
                partial
                    .insert(&fixture.events[id])
                    .expect("topological prefix is auth-closed");
            }
            if missing_pct == 0 {
                // Graph update cost: every event inserted one at a time, as a
                // server would on accepting it.
                let us = insert_start.elapsed().as_secs_f64() * 1e6;
                println!(
                    "auth-graph insert: {us:.0} us for {keep} events ({:.2} us/event)",
                    us / keep as f64
                );
            }
            time_case(
                &format!("hybrid/{missing_pct}%-unindexed diff-only"),
                iterations,
                || {
                    partial
                        .hybrid_state_auth_difference(&fixture.forks, &provider)
                        .expect("fixture is complete")
                        .len()
                },
                Some(&provider),
            );
            time_case(
                &format!("lazy/hybrid-{missing_pct}%-unindexed"),
                iterations,
                || {
                    let diff = partial
                        .hybrid_state_auth_difference(&fixture.forks, &provider)
                        .expect("fixture is complete");
                    rezzy::resolve_state_maps_lazy_with_diff(
                        &fixture.forks,
                        &provider,
                        Some(diff),
                        StateResVersion::V2,
                    )
                    .len()
                },
                Some(&provider),
            );
        }
    }
}
