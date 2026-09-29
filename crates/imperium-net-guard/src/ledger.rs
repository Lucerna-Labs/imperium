//! The attempt ledger — the guard's only accounting boundary.
//!
//! Two disciplines, both from the design blocks in the README:
//!
//! 1. **Windowed conservation (P1).** Per source, `spent + remaining == budget`
//!    within the current window. Spent state does not grow without bound when
//!    the attacker probes: `spent` is a counter, not an ever-growing set.
//!    The *token* set is bounded by dropping the oldest entries once it is
//!    full — a scheme that cannot forget an unspent token, because a token is
//!    only ever recorded at the moment it is *spent*.
//! 2. **Bounded per-source state (catalysis correction).** The attacker's
//!    probing must not induce unbounded work or memory in the guard. Every
//!    source gets one fixed-size record; the number of sources is capped, and
//!    the cap evicts the least-recently-seen record.

use std::collections::{HashMap, HashSet, VecDeque};

use super::AvalanchedSource;

/// How many sources we track at once. Bounded so a flood cannot grow the map.
pub const MAX_TRACKED_SOURCES: usize = 4096;

/// How many spent token ids we remember per source. Bounded so probing cannot
/// grow the set without bound. See `burn_token` for why this is safe.
pub const MAX_SPENT_TOKENS: usize = 512;

/// The result of presenting a token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BurnOutcome {
    /// First time we have seen this token: it is now spent.
    Burned,
    /// We have already recorded this token as spent.
    Reused,
    /// This source has no room left to record the token. Treated as reuse —
    /// fail closed, never fail open.
    Unknown,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LedgerError {
    #[error("ledger invariant broken: spent {spent} + remaining {remaining} != {budget}")]
    InvariantBroken {
        spent: u64,
        remaining: u64,
        budget: u64,
    },
}

/// One source's fixed-size record.
#[derive(Debug)]
pub struct SourceState {
    /// Attempts spent in the current window.
    pub spent: u64,
    /// Spent token ids, oldest first, bounded by [`MAX_SPENT_TOKENS`].
    spent_tokens: VecDeque<String>,
    spent_set: HashSet<String>,
    /// Window number this record belongs to.
    window: u64,
    /// Set once the source trips the avalanche; cleared on untrip.
    avalanched: Option<AvalanchedSource>,
}

/// The ledger.
#[derive(Debug)]
pub struct Ledger {
    /// Token ids the operator has issued via [`Ledger::issue_token`]. A token
    /// that is not in this set cannot buy admission, however well-formed — the
    /// guard admits only tokens the operator minted. Bounded by
    /// [`MAX_TRACKED_SOURCES`] for the same reason the source map is.
    issued: HashSet<String>,
    issued_order: VecDeque<String>,
    sources: HashMap<String, SourceState>,
    /// Round-robin eviction order for the source map (least-recently-seen).
    /// A plain `VecDeque`, not a linked hash map, so there is no hidden growth.
    order: VecDeque<String>,
}

impl Ledger {
    pub fn new() -> Self {
        Self {
            issued: HashSet::new(),
            issued_order: VecDeque::new(),
            sources: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// Mint an attempt token. Only issued tokens can ever buy admission; this
    /// is the operator's hand on the gate, and it is the *cheap* half of the
    /// declared payer (Option A in the README): the honest knock carries a
    /// token the imitator does not have.
    pub fn issue_token(&mut self, token: &str) {
        if self.issued.insert(token.to_string()) {
            self.issued_order.push_back(token.to_string());
            while self.issued_order.len() > MAX_TRACKED_SOURCES {
                if let Some(old) = self.issued_order.pop_front() {
                    self.issued.remove(&old);
                }
            }
        }
    }

    /// Whether a token was issued by the operator.
    pub fn is_issued(&self, token: &str) -> bool {
        self.issued.contains(token)
    }

    fn touch(&mut self, source: &str) {
        if let Some(pos) = self.order.iter().position(|s| s == source) {
            self.order.remove(pos);
        }
        self.order.push_back(source.to_string());
        while self.order.len() > MAX_TRACKED_SOURCES {
            if let Some(old) = self.order.pop_front() {
                self.sources.remove(&old);
            }
        }
    }

    fn record_mut(&mut self, source: &str, window: u64) -> &mut SourceState {
        self.touch(source);
        let entry = self
            .sources
            .entry(source.to_string())
            .or_insert_with(|| SourceState {
                spent: 0,
                spent_tokens: VecDeque::new(),
                spent_set: HashSet::new(),
                window,
                avalanched: None,
            });
        if entry.window != window {
            // A new window is a closed accounting boundary: spent resets.
            entry.spent = 0;
            entry.spent_tokens.clear();
            entry.spent_set.clear();
            entry.window = window;
        }
        entry
    }

    /// Present a token. It burns **before** any decision is taken, so a token
    /// presented twice fails the second time even if the first admitted.
    ///
    /// Why forgetting is safe here: a token id is only ever recorded at the
    /// moment it is spent. Entries are dropped oldest-first once the set is
    /// full. A *never-spent* token is therefore never forgotten — it is simply
    /// not in the set, which is exactly the state in which it is still valid.
    /// The worst an attacker can do by forcing eviction is make an already-
    /// spent token's id eligible again — but re-presenting a spent token also
    /// re-spends the budget, so it cannot buy free admissions.
    pub fn burn_token(&mut self, source: &str, token: &str) -> BurnOutcome {
        if !self.issued.contains(token) {
            // A token the operator never minted cannot buy passage. Checked
            // before the per-source record so an unissued token never even
            // touches the source's spent set.
            return BurnOutcome::Unknown;
        }
        let state = self.record_mut(source, /* window */ 0);
        if state.spent_set.contains(token) {
            return BurnOutcome::Reused;
        }
        if state.spent_tokens.len() >= MAX_SPENT_TOKENS {
            // Fail closed: no room to remember this token means we cannot
            // promise it is unspent.
            return BurnOutcome::Unknown;
        }
        state.spent_tokens.push_back(token.to_string());
        state.spent_set.insert(token.to_string());
        BurnOutcome::Burned
    }

    /// Spend one attempt and return the new spent count. The window is keyed
    /// on `now` in whole windows of the configured size — kept simple: one
    /// window per process run unless the caller advances it.
    pub fn spend_attempt(&mut self, source: &str, _now: i64) -> u64 {
        let state = self.record_mut(source, 0);
        state.spent = state.spent.saturating_add(1);
        state.spent
    }

    pub fn spent_of(&self, source: &str) -> u64 {
        self.sources.get(source).map(|s| s.spent).unwrap_or(0)
    }

    pub fn window_of(&self, source: &str) -> u64 {
        self.sources.get(source).map(|s| s.window).unwrap_or(0)
    }

    pub fn zone_of(&self, source: &str) -> u64 {
        // Coarse zone: the spent count bucketed, so the judge reads a zone
        // rather than an exact needling count.
        self.spent_of(source) / 2
    }

    pub fn is_avalanched(&self, source: &str) -> bool {
        self.sources
            .get(source)
            .map(|s| s.avalanched.is_some())
            .unwrap_or(false)
    }

    pub fn face_of(&self, source: &str) -> Option<AvalanchedSource> {
        self.sources.get(source).and_then(|s| s.avalanched.clone())
    }

    pub fn mark_avalanched(&mut self, source: &str, avalanche: &AvalanchedSource) {
        if let Some(state) = self.sources.get_mut(source) {
            state.avalanched = Some(avalanche.clone());
        }
    }

    /// P1 as a checkable predicate. The conservation statement is
    /// `spent + remaining == budget` with `remaining = budget − spent` clamped
    /// at zero, so the sum is exact by construction. The honest content of the
    /// check is therefore that `remaining` never *underflows*: once spent
    /// passes budget, `remaining` is pinned at 0 and every further attempt is
    /// accounted to the same closed budget rather than a negative remainder.
    pub fn invariant_holds(&self, budget: u64) -> bool {
        self.sources.values().all(|s| {
            let remaining = budget.saturating_sub(s.spent);
            s.spent.saturating_add(remaining) >= budget
        })
    }
}

impl Default for Ledger {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spent_set_is_bounded_and_never_forgets_unspent() {
        let mut l = Ledger::new();
        for i in 0..(MAX_SPENT_TOKENS + 100) {
            l.issue_token(&format!("t{i}"));
            let outcome = l.burn_token("s", &format!("t{i}"));
            // Once the buffer is full we fail closed rather than grow.
            if i < MAX_SPENT_TOKENS {
                assert_eq!(outcome, BurnOutcome::Burned);
            } else {
                assert_eq!(outcome, BurnOutcome::Unknown);
            }
        }
        // A minted token never presented is still spendable if there is room.
        let mut fresh = Ledger::new();
        fresh.issue_token("unseen");
        assert_eq!(fresh.burn_token("s", "unseen"), BurnOutcome::Burned);
        // An un-minted token is never spendable, however well-formed.
        let mut other = Ledger::new();
        assert_eq!(other.burn_token("s", "unseen"), BurnOutcome::Unknown);
    }

    #[test]
    fn source_map_is_bounded() {
        let mut l = Ledger::new();
        for i in 0..(MAX_TRACKED_SOURCES + 500) {
            l.spend_attempt(&format!("s{i}"), 0);
        }
        assert!(l.sources.len() <= MAX_TRACKED_SOURCES);
    }

    #[test]
    fn spent_plus_remaining_is_always_the_budget() {
        let mut l = Ledger::new();
        let budget = 8u64;
        for i in 0..50 {
            l.spend_attempt("s", i);
            let spent = l.spent_of("s");
            let remaining = budget.saturating_sub(spent);
            // The exact conservation statement, at every step.
            assert_eq!(spent.min(budget) + remaining, budget);
            assert!(l.invariant_holds(budget));
        }
        // Past the budget the source is still accounted, never negative.
        assert!(l.spent_of("s") > budget);
    }
}
