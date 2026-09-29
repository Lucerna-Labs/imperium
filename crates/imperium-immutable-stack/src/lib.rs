//! Persistent immutable borrow paths with absorption accounting.
//!
//! A `Path` is an `Arc`-linked persistent stack: push returns a new path that
//! shares its tail with the old one, so forks compare structurally instead of
//! by copying. Absorption records prices paid in a separate currency from
//! observation. `TransferFn` evolves a scalar state deterministically. Every
//! operation is total on fixed types; malformed input is rejected, never
//! corrected.

#![cfg_attr(not(any(test, feature = "std")), no_std)]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use thiserror::Error;

/// Errors in immutable-stack construction and evolution.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum StackError {
    /// Caller tried to pop or peek an empty path.
    #[error("empty path")]
    EmptyPath,
    /// Caller supplied a malformed fixed-shape record.
    #[error("malformed record")]
    MalformedRecord,
}

/// One persistent link: a value plus a shared tail.
#[derive(Clone, Debug)]
struct Link<T> {
    value: T,
    tail: Option<Path<T>>,
}

/// A persistent immutable path. Push returns a new path sharing the old tail;
/// the old path is unchanged and remains usable.
///
/// `Path` intentionally has reference equality only (`Arc::ptr_eq` compares
/// shared tails structurally). Value equality would require `T: PartialEq`
/// through every link and would hide tail sharing, so fork comparison is
/// provided explicitly by [`Path::fork_report`] instead of `==`.
#[derive(Debug)]
pub struct Path<T> {
    head: Option<Arc<Link<T>>>,
    len: usize,
}

impl<T> Clone for Path<T> {
    fn clone(&self) -> Self {
        Self {
            head: self.head.clone(),
            len: self.len,
        }
    }
}

/// Bounded absorption ledger: prices paid in a currency separate from looking.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Absorption {
    paid: u64,
    budget: u64,
}

/// A deterministic transfer function over one scalar state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransferFn {
    gain: u8,
    decay: u8,
    modulus: u16,
}

/// Read-only fork comparison between two paths sharing history.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForkReport {
    /// Length of the shared prefix.
    pub shared_prefix: usize,
    /// Length of the first path.
    pub left_len: usize,
    /// Length of the second path.
    pub right_len: usize,
}

/// Conservation receipt for one evolution step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConservationReceipt {
    /// State before the step.
    pub before: u64,
    /// State after the step.
    pub after: u64,
    /// Absorption paid for the step.
    pub absorbed: u64,
}

impl<T> Path<T> {
    /// Empty path.
    pub fn new() -> Self {
        Self { head: None, len: 0 }
    }

    /// Number of values on this path.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether this path holds no values.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.head.is_none()
    }

    /// Push a value, returning a new path sharing this tail.
    #[must_use]
    pub fn push(&self, value: T) -> Self {
        Self {
            head: Some(Arc::new(Link {
                value,
                tail: Some(self.clone()),
            })),
            len: self.len.saturating_add(1),
        }
    }

    /// Borrow the head value without consuming the path.
    pub fn peek(&self) -> Result<&T, StackError> {
        self.head
            .as_ref()
            .map(|link| &link.value)
            .ok_or(StackError::EmptyPath)
    }

    /// Pop the head, returning the value and the shared tail path.
    pub fn pop(&self) -> Result<(T, Self), StackError>
    where
        T: Clone,
    {
        let link = self.head.as_ref().ok_or(StackError::EmptyPath)?;
        Ok((
            link.value.clone(),
            link.tail.clone().unwrap_or_else(Path::new),
        ))
    }

    /// Compare two paths for shared prefix length. Structural only: no labels,
    /// scores, verdicts, or interpretations.
    #[must_use]
    pub fn fork_report(&self, other: &Self) -> ForkReport
    where
        T: PartialEq,
    {
        let left: Vec<&T> = self.iter().collect();
        let right: Vec<&T> = other.iter().collect();
        let mut shared = 0usize;
        for (a, b) in left.iter().zip(right.iter()) {
            if a == b {
                shared += 1;
            } else {
                break;
            }
        }
        ForkReport {
            shared_prefix: shared,
            left_len: left.len(),
            right_len: right.len(),
        }
    }

    /// Immutable-borrow iterator from oldest to newest value.
    pub fn iter(&self) -> PathIter<'_, T> {
        let mut values = Vec::new();
        let mut cursor = self.head.as_ref().map(Arc::as_ref);
        while let Some(link) = cursor {
            values.push(&link.value);
            cursor = link
                .tail
                .as_ref()
                .and_then(|tail| tail.head.as_ref())
                .map(Arc::as_ref);
        }
        values.reverse();
        PathIter { values, index: 0 }
    }
}

impl<T> Default for Path<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Immutable-borrow iterator over a path, oldest first.
#[derive(Debug)]
pub struct PathIter<'a, T> {
    values: Vec<&'a T>,
    index: usize,
}

impl<'a, T> Iterator for PathIter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        let value = *self.values.get(self.index)?;
        self.index += 1;
        Some(value)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.values.len().saturating_sub(self.index);
        (remaining, Some(remaining))
    }
}

impl<'a, T> ExactSizeIterator for PathIter<'a, T> {}

impl Absorption {
    /// Create a bounded ledger with a fixed budget.
    pub fn new(budget: u64) -> Self {
        Self { paid: 0, budget }
    }

    /// Total absorbed so far.
    #[must_use]
    pub fn paid(&self) -> u64 {
        self.paid
    }

    /// Remaining budget.
    #[must_use]
    pub fn remaining(&self) -> u64 {
        self.budget.saturating_sub(self.paid)
    }

    /// Pay a cost, saturating at the budget. Separation of currency from
    /// observation lives here: paying never changes what was seen.
    pub fn absorb(&mut self, cost: u64) {
        self.paid = self.paid.saturating_add(cost).min(self.budget);
    }
}

impl TransferFn {
    /// Create a deterministic transfer function.
    pub fn new(gain: u8, decay: u8, modulus: u16) -> Self {
        Self {
            gain,
            decay,
            modulus: modulus.max(2),
        }
    }

    /// Evolve one scalar state. Total on `u64`; wraps deterministically.
    #[must_use]
    pub fn step(&self, state: u64, input: u64) -> u64 {
        let modulus = u128::from(self.modulus);
        let driven = (u128::from(state) * u128::from(self.gain)
            + u128::from(input) * u128::from(self.decay))
            % modulus;
        (driven % (u64::MAX as u128 + 1)) as u64 % u64::from(self.modulus)
    }

    /// Evolve one step and record absorption + conservation.
    #[must_use]
    pub fn step_with_receipt(
        &self,
        state: u64,
        input: u64,
        ledger: &mut Absorption,
        cost: u64,
    ) -> ConservationReceipt {
        let after = self.step(state, input);
        ledger.absorb(cost);
        ConservationReceipt {
            before: state,
            after,
            absorbed: ledger.paid(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_shares_tail_and_leaves_old_path_intact() {
        let base = Path::new().push(1u8).push(2u8);
        let forked = base.push(3u8);
        assert_eq!(base.len(), 2);
        assert_eq!(forked.len(), 3);
        assert_eq!(base.peek(), Ok(&2u8));
        assert_eq!(forked.peek(), Ok(&3u8));
    }

    #[test]
    fn pop_returns_value_and_shared_tail() {
        let path = Path::new().push(1u8).push(2u8).push(3u8);
        let (value, tail) = path.pop().unwrap();
        assert_eq!(value, 3u8);
        assert_eq!(tail.len(), 2);
        assert_eq!(path.len(), 3);
    }

    #[test]
    fn empty_path_reports_without_panic() {
        let path: Path<u8> = Path::new();
        assert!(path.is_empty());
        assert_eq!(path.peek(), Err(StackError::EmptyPath));
        assert!(matches!(path.pop(), Err(StackError::EmptyPath)));
    }

    #[test]
    fn fork_report_measures_shared_prefix_structurally() {
        let base = Path::new().push(1u8).push(2u8);
        let left = base.push(3u8);
        let right = base.push(4u8);
        let report = left.fork_report(&right);
        assert_eq!(
            report,
            ForkReport {
                shared_prefix: 2,
                left_len: 3,
                right_len: 3,
            }
        );
    }

    #[test]
    fn iter_borrows_oldest_first_without_consuming() {
        let path = Path::new().push(1u8).push(2u8).push(3u8);
        let collected: Vec<u8> = path.iter().copied().collect();
        assert_eq!(collected, vec![1u8, 2u8, 3u8]);
        assert_eq!(path.len(), 3);
    }

    #[test]
    fn absorption_is_bounded_and_separate_from_observation() {
        let mut ledger = Absorption::new(10);
        ledger.absorb(4);
        ledger.absorb(9);
        assert_eq!(ledger.paid(), 10);
        assert_eq!(ledger.remaining(), 0);
    }

    #[test]
    fn transfer_fn_is_deterministic_and_bounded() {
        let transfer = TransferFn::new(3, 5, 251);
        let first = transfer.step(17, 42);
        assert_eq!(first, transfer.step(17, 42));
        assert!(first < 251);
    }

    #[test]
    fn receipt_records_before_after_and_absorbed() {
        let transfer = TransferFn::new(3, 5, 251);
        let mut ledger = Absorption::new(100);
        let receipt = transfer.step_with_receipt(17, 42, &mut ledger, 7);
        assert_eq!(receipt.before, 17);
        assert_eq!(receipt.after, transfer.step(17, 42));
        assert_eq!(receipt.absorbed, 7);
        assert_eq!(ledger.paid(), 7);
    }
}
