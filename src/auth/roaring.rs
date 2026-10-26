//! Fast auth chain operations using [`Bitmap`] reachability sets.
//!
//! [`AuthGraph`] pre-computes a compressed, topologically-ordered representation
//! of the auth DAG. Each event's full transitive auth chain is stored as a
//! `Bitmap`, enabling `O(1)` ancestor queries via bitwise intersection.
//!
//! This is used for fast auth-chain difference computations in state resolution.

use crate::bitmap::Bitmap;
use crate::DenseIndex;
use crate::FastMap;
use crate::HashMap;
use crate::LeanEvent;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

/// Events an [`AuthGraph`] operation needed but could not find: auth events
/// not yet inserted ([`AuthGraph::insert`]), auth events absent from the
/// event set ([`AuthGraph::try_build`]), or state events not in the graph
/// ([`AuthGraph::try_state_auth_difference`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingEvents<Id> {
    /// The missing event IDs, sorted and deduplicated.
    pub missing: Vec<Id>,
}

impl<Id: Ord> MissingEvents<Id> {
    /// `Err` naming `missing` (sorted, deduplicated), or `Ok` if it is empty.
    fn check(mut missing: Vec<Id>) -> Result<(), Self> {
        if missing.is_empty() {
            return Ok(());
        }
        missing.sort();
        missing.dedup();
        Err(Self { missing })
    }
}

impl<Id: core::fmt::Debug> core::fmt::Display for MissingEvents<Id> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "auth events not in the auth graph yet: {:?}",
            self.missing
        )
    }
}

impl<Id: core::fmt::Debug> core::error::Error for MissingEvents<Id> {}

/// A topologically-ordered auth DAG with pre-computed transitive reachability bitmaps.
///
/// Each event is assigned a dense integer index (topological order), and its
/// full auth chain is represented as a `Bitmap`. Checking whether
/// event A is in event B's auth chain is a single `bitmap.contains(idx)` call.
pub struct AuthGraph<Id = String> {
    /// Dense index over event IDs (first-seen order = topological order).
    pub index: DenseIndex<Id>,
    /// Per-event bitmaps: `auth_bitmaps[i]` contains the indices of all
    /// transitive auth ancestors of event `i`.
    pub auth_bitmaps: Vec<Bitmap>,
}

impl<Id> AuthGraph<Id>
where
    Id: crate::basespec::rezzy_types::EventId,
{
    /// Build the `AuthGraph` topological structure.
    ///
    /// # Panics
    ///
    /// Will panic if any internal graph invariants are violated during topological sorting.
    /// Will also panic if `sort_context` contains more events than a `u32` index can address.
    #[must_use]
    pub fn build<C: Clone, S: core::hash::BuildHasher>(
        sort_context: &HashMap<Id, LeanEvent<Id, C>, S>,
    ) -> Self {
        let mut in_degree: FastMap<&Id, usize> = FastMap::default();
        let mut adjacency: FastMap<&Id, Vec<&Id>> = FastMap::default();

        for (id, ev) in sort_context {
            in_degree.entry(id).or_insert(0);
            for auth_id in &ev.auth_events {
                if sort_context.contains_key(auth_id) {
                    adjacency.entry(auth_id).or_default().push(id);
                    let val = in_degree.entry(id).or_insert(0);
                    *val = val.saturating_add(1);
                }
            }
        }

        let mut queue = VecDeque::new();
        for (id, &deg) in &in_degree {
            if deg == 0 {
                queue.push_back(*id);
            }
        }

        let mut sorted = Vec::with_capacity(sort_context.len());
        while let Some(id) = queue.pop_front() {
            sorted.push(id);
            if let Some(children) = adjacency.get(id) {
                for child in children {
                    let deg = in_degree.get_mut(child).unwrap();
                    *deg = deg.saturating_sub(1);
                    if *deg == 0 {
                        queue.push_back(*child);
                    }
                }
            }
        }

        let index = DenseIndex::try_build(sorted.iter().map(|&id| id.clone()))
            .expect("auth graph event count fits in a u32 index");

        let mut auth_bitmaps = vec![Bitmap::new(); sorted.len()];
        for (idx, &id) in sorted.iter().enumerate() {
            let mut bitmap = Bitmap::new();
            if let Some(ev) = sort_context.get(id) {
                for auth_id in &ev.auth_events {
                    if let Some(p_idx) = index.index_of(auth_id) {
                        bitmap |= &auth_bitmaps[p_idx as usize];
                        bitmap.insert(p_idx);
                    }
                }
            }
            auth_bitmaps[idx] = bitmap;
        }

        Self {
            index,
            auth_bitmaps,
        }
    }

    /// [`Self::build`], but refuses an event set that is not auth-closed.
    ///
    /// `build` skips auth events missing from `sort_context`, so their
    /// descendants' bitmaps silently lack them. This returns every such auth
    /// event instead, so a caller cannot build a graph whose diffs would be
    /// incomplete.
    ///
    /// # Errors
    /// Returns [`MissingEvents`] listing auth events cited in `sort_context`
    /// but not present in it.
    ///
    /// # Panics
    /// As [`Self::build`].
    pub fn try_build<C: Clone, S: core::hash::BuildHasher>(
        sort_context: &HashMap<Id, LeanEvent<Id, C>, S>,
    ) -> Result<Self, MissingEvents<Id>> {
        MissingEvents::check(
            sort_context
                .values()
                .flat_map(|ev| &ev.auth_events)
                .filter(|id| !sort_context.contains_key(*id))
                .cloned()
                .collect(),
        )?;
        Ok(Self::build(sort_context))
    }

    /// Compute the **auth chain difference**:
    /// events in the auth chains of `conflicted_ids`
    /// that are NOT in the auth chains of
    /// `unconflicted_ids`.
    ///
    /// This is the bitmap fast path for the
    /// same computation as
    /// [`compute_auth_chain_diff`](crate::state::at::compute_auth_chain_diff),
    /// but runs in `O(|bitmap|)` time on pre-computed
    /// bitmaps instead of walking the DAG.
    ///
    /// Unknown IDs (not in the graph) are silently
    /// skipped.
    ///
    /// # Panics
    /// Panics if a resolved index is out of this graph's own index range. This
    /// cannot happen for a graph built over the event set its bitmaps address —
    /// every index in the difference originated from [`Self::index`]'s
    /// `index_of`, which never returns an out-of-range index.
    #[must_use]
    pub fn auth_difference(&self, unconflicted_ids: &[Id], conflicted_ids: &[Id]) -> Vec<Id> {
        // Union of all unconflicted auth chains
        let mut u_bitmap = Bitmap::new();
        for id in unconflicted_ids {
            if let Some(idx) = self.index.index_of(id) {
                u_bitmap |= &self.auth_bitmaps[idx as usize];
                u_bitmap.insert(idx);
            }
        }

        // Union of all conflicted auth chains
        let mut c_bitmap = Bitmap::new();
        for id in conflicted_ids {
            if let Some(idx) = self.index.index_of(id) {
                c_bitmap |= &self.auth_bitmaps[idx as usize];
                c_bitmap.insert(idx);
            }
        }

        // Difference: conflicted \ unconflicted
        let diff = core::ops::Sub::sub(c_bitmap, u_bitmap);

        diff.iter()
            .map(|idx| {
                self.index
                    .item_at(idx as usize)
                    .cloned()
                    .expect("diff index came from this graph's index")
            })
            .collect()
    }

    /// Adds one event, appending it to the topological order.
    ///
    /// Its bitmap is the union of its auth events' bitmaps plus their own
    /// indices. Every auth event must already be in the graph: a bitmap built
    /// without one would stay incomplete even after that event arrived, so a
    /// missing auth event is an error and the graph is left unchanged. Insert
    /// in the order events are accepted, or rebuild after backfilling.
    ///
    /// Returns `Ok(false)` if the event was already present.
    ///
    /// # Errors
    /// Returns [`MissingEvents`] listing the auth events not yet in the
    /// graph.
    ///
    /// # Panics
    /// Panics if the graph already holds as many events as a `u32` index can
    /// address, as [`Self::build`] does.
    pub fn insert<C>(&mut self, event: &LeanEvent<Id, C>) -> Result<bool, MissingEvents<Id>> {
        if self.index.index_of(&event.event_id).is_some() {
            return Ok(false);
        }
        MissingEvents::check(
            event
                .auth_events
                .iter()
                .filter(|id| self.index.index_of(id).is_none())
                .cloned()
                .collect(),
        )?;
        let mut bitmap = Bitmap::new();
        for auth_id in &event.auth_events {
            if let Some(p_idx) = self.index.index_of(auth_id) {
                bitmap |= &self.auth_bitmaps[p_idx as usize];
                bitmap.insert(p_idx);
            }
        }
        self.index
            .try_push(event.event_id.clone())
            .expect("auth graph event count fits in a u32 index");
        self.auth_bitmaps.push(bitmap);
        Ok(true)
    }

    /// The state resolution v2 **auth difference** of `state_maps`:
    /// `∪ Cᵢ − ∩ Cᵢ`, where `Cᵢ` is the auth chain of every event in state map
    /// `Sᵢ`, the events included.
    ///
    /// Unlike [`Self::auth_difference`], which subtracts the unconflicted
    /// chain from the conflicted one, this leaves out an ancestor that every
    /// map's chain reaches even when no unconflicted event cites it. Pass the
    /// result as the precomputed diff of
    /// [`resolve_state_maps_lazy_with_diff`](crate::resolve::multi::resolve_state_maps_lazy_with_diff).
    /// Events not in the graph are skipped; use
    /// [`Self::try_state_auth_difference`] to refuse them instead.
    ///
    /// # Panics
    /// Panics only if an index in the result is out of this graph's own range,
    /// which cannot happen: every bit came from [`Self::index`].
    #[must_use]
    pub fn state_auth_difference<K: Ord + Clone>(
        &self,
        state_maps: &[crate::state::at::SharedState<Id, K>],
    ) -> Vec<Id> {
        let mut union = Bitmap::new();
        let mut intersection: Option<Bitmap> = None;
        for state in state_maps {
            let mut chain = Bitmap::new();
            for id in state.values() {
                if let Some(idx) = self.index.index_of(id) {
                    chain |= &self.auth_bitmaps[idx as usize];
                    chain.insert(idx);
                }
            }
            union |= &chain;
            match &mut intersection {
                Some(both) => *both &= &chain,
                None => intersection = Some(chain),
            }
        }
        let diff = match intersection {
            Some(both) => core::ops::Sub::sub(union, &both),
            None => union,
        };
        diff.iter()
            .map(|idx| {
                self.index
                    .item_at(idx as usize)
                    .cloned()
                    .expect("diff index came from this graph's index")
            })
            .collect()
    }

    /// [`Self::state_auth_difference`], but refuses state events missing from
    /// the graph instead of skipping them, which would leave their chains out
    /// of the difference.
    ///
    /// # Errors
    /// Returns [`MissingEvents`] listing state event IDs not in the graph.
    pub fn try_state_auth_difference<K: Ord + Clone>(
        &self,
        state_maps: &[crate::state::at::SharedState<Id, K>],
    ) -> Result<Vec<Id>, MissingEvents<Id>> {
        MissingEvents::check(
            state_maps
                .iter()
                .flat_map(crate::state::persistent_ord_map::PersistentOrdMap::values)
                .filter(|id| self.index.index_of(id).is_none())
                .cloned()
                .collect(),
        )?;
        Ok(self.state_auth_difference(state_maps))
    }

    /// Check whether `ancestor` is in the transitive
    /// auth chain of `descendant`.
    ///
    /// Returns `false` if either ID is unknown.
    #[must_use]
    pub fn is_in_auth_chain(&self, ancestor: &Id, descendant: &Id) -> bool {
        let Some(a_idx) = self.index.index_of(ancestor) else {
            return false;
        };
        let Some(d_idx) = self.index.index_of(descendant) else {
            return false;
        };
        self.auth_bitmaps[d_idx as usize].contains(a_idx)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn test_auth_graph_build() {
        let mut sort_context: HashMap<String, LeanEvent> = HashMap::new();

        // Create events:
        // A is the creator / pl event (no auth events)
        // B auths with A
        // C auths with B
        let ev_a = LeanEvent {
            event_id: "A".to_string(),
            event_type: "m.room.create".to_string(),
            auth_events: vec![],
            ..Default::default()
        };
        let ev_b = LeanEvent {
            event_id: "B".to_string(),
            event_type: "m.room.member".to_string(),
            auth_events: vec!["A".to_string()],
            ..Default::default()
        };
        let ev_c = LeanEvent {
            event_id: "C".to_string(),
            event_type: "m.room.message".to_string(),
            auth_events: vec!["B".to_string()],
            ..Default::default()
        };

        sort_context.insert("A".to_string(), ev_a);
        sort_context.insert("B".to_string(), ev_b);
        sort_context.insert("C".to_string(), ev_c);

        let graph = AuthGraph::build(&sort_context);

        assert_eq!(graph.index.len(), 3);

        let idx_a = graph.index.index_of(&"A".to_string()).expect("A indexed");
        let idx_b = graph.index.index_of(&"B".to_string()).expect("B indexed");
        let idx_c = graph.index.index_of(&"C".to_string()).expect("C indexed");

        // Verify topological sorting holds (A is parent, so it should be processed before B, B before C)
        assert!(idx_a < idx_b);
        assert!(idx_b < idx_c);

        // Verify auth bitmaps
        let bitmap_a = &graph.auth_bitmaps[idx_a as usize];
        let bitmap_b = &graph.auth_bitmaps[idx_b as usize];
        let bitmap_c = &graph.auth_bitmaps[idx_c as usize];

        // A has no auth events
        assert!(bitmap_a.is_empty());

        // B has A as auth event
        assert!(bitmap_b.contains(idx_a));
        assert_eq!(bitmap_b.len(), 1);

        // C has B as auth event, and B transitively has A
        assert!(bitmap_c.contains(idx_b));
        assert!(bitmap_c.contains(idx_a));
        assert_eq!(bitmap_c.len(), 2);
    }

    /// Helper: build a diamond-shaped auth DAG:
    ///
    /// ```text
    ///   Create(A)
    ///    / \
    ///  PL(B) Join(C)
    ///    \ /
    ///   Topic(D)
    /// ```
    fn diamond_graph() -> (AuthGraph<String>, HashMap<String, LeanEvent>) {
        let mut ctx: HashMap<String, LeanEvent> = HashMap::new();
        ctx.insert(
            "A".into(),
            LeanEvent {
                event_id: "A".into(),
                event_type: "m.room.create".into(),
                ..Default::default()
            },
        );
        ctx.insert(
            "B".into(),
            LeanEvent {
                event_id: "B".into(),
                event_type: "m.room.power_levels".into(),
                auth_events: vec!["A".into()],
                ..Default::default()
            },
        );
        ctx.insert(
            "C".into(),
            LeanEvent {
                event_id: "C".into(),
                event_type: "m.room.member".into(),
                auth_events: vec!["A".into()],
                ..Default::default()
            },
        );
        ctx.insert(
            "D".into(),
            LeanEvent {
                event_id: "D".into(),
                event_type: "m.room.topic".into(),
                auth_events: vec!["B".into(), "C".into()],
                ..Default::default()
            },
        );
        let graph = AuthGraph::build(&ctx);
        (graph, ctx)
    }

    #[test]
    fn test_is_in_auth_chain() {
        let (graph, _) = diamond_graph();

        // Direct parents
        assert!(graph.is_in_auth_chain(&"A".into(), &"B".into()));
        assert!(graph.is_in_auth_chain(&"A".into(), &"C".into()));

        // Transitive: A is in D's auth chain (via B and C)
        assert!(graph.is_in_auth_chain(&"A".into(), &"D".into()));
        assert!(graph.is_in_auth_chain(&"B".into(), &"D".into()));
        assert!(graph.is_in_auth_chain(&"C".into(), &"D".into()));

        // Not ancestors
        assert!(!graph.is_in_auth_chain(&"D".into(), &"A".into()));
        assert!(!graph.is_in_auth_chain(&"B".into(), &"C".into()));
        assert!(!graph.is_in_auth_chain(&"C".into(), &"B".into()));

        // Self is not in own auth chain
        assert!(!graph.is_in_auth_chain(&"A".into(), &"A".into()));

        // Unknown IDs
        assert!(!graph.is_in_auth_chain(&"Z".into(), &"A".into()));
        assert!(!graph.is_in_auth_chain(&"A".into(), &"Z".into()));
    }

    #[test]
    fn test_auth_difference_basic() {
        let (graph, _) = diamond_graph();

        // Unconflicted: {A}, Conflicted: {D}
        // auth(D) = {A, B, C}, auth(A) = {}
        // Union of conflicted chains: {A, B, C} ∪ {D}
        // Union of unconflicted chains: {} ∪ {A}
        // Diff: {B, C, D}
        let diff = graph.auth_difference(&["A".into()], &["D".into()]);
        assert_eq!(diff.len(), 3);
        assert!(diff.contains(&"B".into()));
        assert!(diff.contains(&"C".into()));
        assert!(diff.contains(&"D".into()));
        assert!(!diff.contains(&"A".into()));
    }

    #[test]
    fn test_auth_difference_overlapping() {
        let (graph, _) = diamond_graph();

        // Unconflicted: {B, C}, Conflicted: {D}
        // auth(B) ∪ auth(C) ∪ {B, C} = {A, B, C}
        // auth(D) ∪ {D} = {A, B, C, D}
        // Diff = {D}
        let diff = graph.auth_difference(&["B".into(), "C".into()], &["D".into()]);
        assert_eq!(diff.len(), 1);
        assert_eq!(diff[0], "D");
    }

    #[test]
    fn test_auth_difference_empty_inputs() {
        let (graph, _) = diamond_graph();

        // Empty unconflicted — full conflicted chain returned
        let diff = graph.auth_difference(&[], &["B".into()]);
        assert!(diff.contains(&"A".into()));
        assert!(diff.contains(&"B".into()));

        // Empty conflicted — nothing returned
        let diff = graph.auth_difference(&["A".into()], &[]);
        assert_eq!(diff.len(), 0);
    }

    #[test]
    fn test_auth_difference_unknown_ids_ignored() {
        let (graph, _) = diamond_graph();

        // Unknown IDs in both lists are silently ignored
        let diff = graph.auth_difference(&["Z".into()], &["D".into()]);
        // All of D's auth chain + D itself
        assert_eq!(diff.len(), 4);
    }
}
